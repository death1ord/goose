package facts

import (
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
	"goose/internal/loader"
)

// Build collects the entity and usage view of a loaded project.
func Build(ld *loader.Loaded) *Project {
	b := &builder{
		ld:         ld,
		objectKeys: map[types.Object]Key{},
		methodRecv: map[Key]string{},
		fieldKeys:  map[string][]Key{},
	}
	b.proj = &Project{
		Module: ModuleInfo{
			Path:       ld.Module.Path,
			Dir:        ld.Module.Dir,
			Requires:   ld.Module.Requires,
			Vendor:     ld.Module.Vendor,
			WorkFile:   ld.Module.WorkFile,
			Workspaces: ld.Module.Workspaces,
		},
		Files:              map[string]*FileFacts{},
		Entities:           map[Key]*Entity{},
		Uses:               map[Key][]UseSite{},
		EntryPkgs:          map[string]bool{},
		InterfaceMethods:   map[Key][]Key{},
		InterfaceSatisfied: map[Key]bool{},
		ReflectivePkgs:     map[string]bool{},
		SkippedFiles:       map[string]bool{},
		EntitySpans:        map[Key][]Span{},
		Fset:               ld.Fset,
	}
	for _, entry := range ld.Files {
		if !ld.IsProjectPkg(entry.Pkg) || entry.Syntax == nil {
			continue
		}
		b.collectFile(entry)
	}
	for _, entry := range ld.Files {
		if !ld.IsProjectPkg(entry.Pkg) || entry.Syntax == nil || entry.Pkg.TypesInfo == nil {
			continue
		}
		b.collectUses(entry)
	}
	ownSpans := map[Key]Span{}
	for k, sps := range b.proj.EntitySpans {
		if len(sps) > 0 {
			ownSpans[k] = sps[0]
		}
	}
	b.computeTypeSpans()
	b.resolve()
	b.populateContainingKeys(ownSpans)
	return b.proj
}

// builder holds one collection pass.
type builder struct {
	ld         *loader.Loaded
	proj       *Project
	objectKeys map[types.Object]Key
	methodRecv map[Key]string // method key -> receiver type name
	// fieldKeys indexes field keys by "pkg\x1fname" so a field object from a
	// test-binary package variant (a duplicate compilation with fresh
	// types.Objects) can still resolve to its entity when the name is unique.
	fieldKeys map[string][]Key
	// aliasChecked guards the one-time alias-entity pass.
}

// resolveObjKey maps a used object to its entity key. Identity is the fast
// path; on a miss the key is derived from the object itself and verified
// against the registered entities. The miss is the common case for test
// files: go/packages type-checks the project twice under Tests mode (the
// base package and the .test variant), and the variant's objects are
// different instances of the same symbols. Derivation keeps test-file uses
// credited everywhere (fallow's dependency reachability), and membership
// against Entities guarantees a derived key exists and resolves to the
// symbol the declarations pass registered.
func (b *builder) resolveObjKey(obj types.Object) (Key, bool) {
	if obj == nil {
		return "", false
	}
	if k, ok := b.objectKeys[obj]; ok {
		return k, true
	}
	pkgPath := ""
	if obj.Pkg() != nil {
		pkgPath = obj.Pkg().Path()
	}
	switch o := obj.(type) {
	case *types.TypeName:
		kind := KindType
		if _, isIface := o.Type().Underlying().(*types.Interface); isIface && !o.IsAlias() {
			kind = KindInterface
		}
		k := MakeKey(kind, pkgPath, "", o.Name())
		if b.proj.Entity(k) != nil {
			return k, true
		}
		return "", false
	case *types.Func:
		recv := ""
		kind := KindFunc
		if sig, ok := o.Type().(*types.Signature); ok && sig.Recv() != nil {
			kind = KindMethod
			recv = namedTypeName(sig.Recv().Type())
		}
		k := MakeKey(kind, pkgPath, recv, o.Name())
		if b.proj.Entity(k) != nil {
			return k, true
		}
		return "", false
	case *types.Var:
		if o.IsField() {
			ks := b.fieldKeys[pkgPath+"\x1f"+o.Name()]
			if len(ks) == 1 {
				return ks[0], true
			}
			if len(ks) > 1 && o.Pos().IsValid() {
				pos := b.ld.Fset.Position(o.Pos())
				for _, cand := range ks {
					if ent := b.proj.Entity(cand); ent != nil && ent.File == pos.Filename && ent.Line == pos.Line {
						return cand, true
					}
				}
			}
			return "", false // unknown or ambiguous field name
		}
		var found Key
		for _, kind := range []Kind{KindVar, KindConst} {
			if k := MakeKey(kind, pkgPath, "", o.Name()); b.proj.Entity(k) != nil {
				if found != "" {
					return "", false // const and var share the name: ambiguous
				}
				found = k
			}
		}
		return found, found != ""
	}
	return "", false
}

// collectFile collects declarations of one project file.
func (b *builder) collectFile(e *loader.FileEntry) {
	ff := &FileFacts{
		Path:    e.Path,
		Rel:     b.rel(e.Path),
		PkgPath: e.Pkg.PkgPath,
		InTest:  e.InTest,
	}
	if len(e.Src) > 0 {
		ff.Src = string(e.Src)
		ff.Loc = countLines(e.Src)
	} else if data, err := os.ReadFile(e.Path); err == nil {
		ff.Src = string(data)
		ff.Loc = countLines(data)
	}
	if e.Types != nil {
		ff.PkgName = e.Types.Name()
	} else if e.Syntax != nil && e.Syntax.Name != nil {
		ff.PkgName = e.Syntax.Name.Name
	}
	b.proj.Files[e.Path] = ff
	b.collectFileTrivia(e, ff)

	info := e.Pkg.TypesInfo
	for _, imp := range e.Syntax.Imports {
		ipath, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if ipath == "C" {
			ff.HasCgo = true
			continue
		}
		ii := ImportInfo{Path: ipath, File: e.Path}
		pos := b.ld.Fset.Position(imp.Pos())
		ii.Line, ii.Col = pos.Line, pos.Column-1
		if imp.Name != nil {
			switch imp.Name.Name {
			case "_":
				ii.Blank = true
			case ".":
				ii.Dot = true
			default:
				ii.Name = imp.Name.Name
			}
		}
		ff.Imports = append(ff.Imports, ii)
	}
	if e.Skipped {
		// Size guard: uses and imports are collected; declarations are skipped
		// so a large file can never be reported dead. This keeps its imports
		// crediting other symbols (fallow's off-graph distortion guard).
		b.proj.SkippedFiles[ff.Rel] = true
		return
	}
	if info == nil {
		for _, decl := range e.Syntax.Decls {
			b.collectDeclSyntax(e, ff, decl)
		}
		b.collectGoIssues(e, ff)
		return
	}
	for _, decl := range e.Syntax.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			b.collectFunc(e, ff, d, info)
		case *ast.GenDecl:
			b.collectGenDecl(e, ff, d, info)
		}
	}
	b.collectGoIssues(e, ff)
}

var (
	buildTagRe = regexp.MustCompile(`^//go:build\s+(.*)$`)
	suppressRe = regexp.MustCompile(`^\s*//\s*(goose|fallow)-ignore-(file|next-line|start|end)(\s|$)`)
)

// collectFileTrivia records build tags and goose-ignore markers from real Go
// AST comments (never from string or raw-string literals).
func (b *builder) collectFileTrivia(e *loader.FileEntry, ff *FileFacts) {
	if e.Syntax == nil {
		return
	}
	for _, cg := range e.Syntax.Comments {
		for _, c := range cg.List {
			trim := strings.TrimSpace(c.Text)
			if m := buildTagRe.FindStringSubmatch(trim); m != nil {
				ff.BuildTags = append(ff.BuildTags, strings.Fields(m[1])...)
			}
			if m := exportDirRe.FindStringSubmatch(trim); m != nil {
				ff.DirectiveTargets = append(ff.DirectiveTargets, m[1])
			}
			if m := linknameDirRe.FindStringSubmatch(trim); m != nil {
				ff.DirectiveTargets = append(ff.DirectiveTargets, m[1])
			}
			if m := suppressRe.FindStringSubmatch(trim); m != nil {
				toolPrefix, kind := m[1], m[2]
				full := strings.TrimSpace(strings.TrimPrefix(trim, "//"))
				body := strings.TrimSpace(strings.TrimPrefix(full, toolPrefix+"-ignore-"+kind))
				typesPart, reason := cutSupp(body)
				pos := b.ld.Fset.Position(c.Slash)
				col := pos.Column - 1
				if col < 0 {
					col = 0
				}
				s := &Suppression{
					Kind: kind, Line: pos.Line, Col: col, Raw: trim,
					Types: strings.Fields(typesPart), Reason: reason,
					HasReason: reason != "",
				}
				ff.Suppressions = append(ff.Suppressions, s)
			}
		}
	}
}

func cutSupp(s string) (string, string) {
	if i := strings.Index(s, " -- "); i >= 0 {
		return s[:i], strings.TrimSpace(s[i+4:])
	}
	return s, ""
}

// ---------------------------------------------------------------------------
// Declarations.
// ---------------------------------------------------------------------------

func (b *builder) collectFunc(e *loader.FileEntry, ff *FileFacts, d *ast.FuncDecl, info *types.Info) {
	obj := info.Defs[d.Name]
	if obj == nil || obj.Pkg() != e.Types {
		return
	}
	kind := KindFunc
	recv := ""
	if sig, ok := obj.Type().(*types.Signature); ok && sig.Recv() != nil {
		kind = KindMethod
		recv = namedTypeName(sig.Recv().Type())
	}
	key := MakeKey(kind, obj.Pkg().Path(), recv, obj.Name())
	pos := b.ld.Fset.Position(d.Pos())
	endPos := b.ld.Fset.Position(d.End())
	fi := &FuncInfo{
		Node: d, Loc: endPos.Line - pos.Line + 1,
		RecvTypeName: recv,
		IsTest:       ff.InTest && isTestName(d.Name.Name),
		IsInit:       d.Name.Name == "init",
		IsMain:       kind == KindFunc && d.Name.Name == "main" && obj.Pkg().Name() == "main",
	}
	if d.Body != nil {
		fi.Body = d.Body
		fi.BodyLoc = b.ld.Fset.Position(d.Body.End()).Line - pos.Line + 1
		cx := ComputeComplexity(b.ld.Fset, d)
		fi.Cyclomatic = cx.Cyclomatic
		fi.Cognitive = cx.Cognitive
		fi.Statements = cx.Statements
	}
	if sig, ok := obj.Type().(*types.Signature); ok {
		fi.Params = sig.Params().Len()
		fi.Results = sig.Results().Len()
	}
	b.collectUnusedParamsAndRecv(e, d, fi, info)
	doc := ""
	if d.Doc != nil {
		doc = d.Doc.Text()
	}
	b.addEntity(ff, &Entity{
		Key: key, Kind: kind,
		PkgPath: obj.Pkg().Path(), PkgName: ff.PkgName,
		Recv: recv, Name: obj.Name(),
		File: e.Path, Line: pos.Line, Col: pos.Column - 1,
		Exported: obj.Exported(), DeclNode: d,
		Doc: doc, Deprecated: strings.Contains(doc, "Deprecated:"),
		TestFile: ff.InTest, Func: fi, DocTags: parseDocTags(doc),
	})
	b.objectKeys[obj] = key
	if kind == KindMethod {
		b.methodRecv[key] = recv
	}
	b.addSpan(key, e.Path, pos.Line, endPos.Line)
}

func (b *builder) collectGenDecl(e *loader.FileEntry, ff *FileFacts, g *ast.GenDecl, info *types.Info) {
	switch g.Tok {
	case token.TYPE:
		for _, spec := range g.Specs {
			if sp, ok := spec.(*ast.TypeSpec); ok {
				b.collectTypeSpec(e, ff, g, sp, info)
			}
		}
	case token.CONST, token.VAR:
		pkgScope := e.Types.Scope()
		for _, spec := range g.Specs {
			sp, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			kind := KindVar
			if g.Tok == token.CONST {
				kind = KindConst
			}
			for _, name := range sp.Names {
				if name.Name == "_" {
					continue
				}
				obj := info.Defs[name]
				if obj == nil || obj.Pkg() != e.Types {
					continue
				}
				if obj.Parent() != nil && obj.Parent() != pkgScope {
					continue // function-local: never a reported entity
				}
				doc := valueDoc(g, sp)
				key := MakeKey(kind, obj.Pkg().Path(), "", name.Name)
				pos := b.ld.Fset.Position(name.Pos())
				b.addEntity(ff, &Entity{
					Key: key, Kind: kind,
					PkgPath: obj.Pkg().Path(), PkgName: ff.PkgName,
					Name: name.Name, File: e.Path,
					Line: pos.Line, Col: pos.Column - 1,
					Exported: obj.Exported(), DeclNode: sp,
					Doc: doc, Deprecated: strings.Contains(doc, "Deprecated:"),
					TestFile: ff.InTest, DocTags: parseDocTags(doc),
				})
				b.objectKeys[obj] = key
				b.addSpan(key, e.Path, pos.Line, pos.Line)
			}
		}
	}
}

func valueDoc(g *ast.GenDecl, sp *ast.ValueSpec) string {
	if sp.Doc != nil {
		return sp.Doc.Text()
	}
	if g.Doc != nil {
		return g.Doc.Text()
	}
	return ""
}

func (b *builder) collectTypeSpec(e *loader.FileEntry, ff *FileFacts, g *ast.GenDecl, sp *ast.TypeSpec, info *types.Info) {
	obj := info.Defs[sp.Name]
	tn, ok := obj.(*types.TypeName)
	if !ok || obj == nil || tn.Pkg() != e.Types {
		return
	}
	kind := KindType
	if _, isIface := tn.Type().Underlying().(*types.Interface); isIface {
		kind = KindInterface
	}
	key := MakeKey(kind, tn.Pkg().Path(), "", sp.Name.Name)
	doc := typeDoc(g, sp)
	pos := b.ld.Fset.Position(sp.Pos())
	endPos := b.ld.Fset.Position(sp.End())
	b.addEntity(ff, &Entity{
		Key: key, Kind: kind,
		PkgPath: tn.Pkg().Path(), PkgName: ff.PkgName,
		Name: sp.Name.Name, File: e.Path,
		Line: pos.Line, Col: pos.Column - 1,
		Exported: tn.Exported(), DeclNode: sp,
		Doc: doc, Deprecated: strings.Contains(doc, "Deprecated:"),
		TestFile: ff.InTest, DocTags: parseDocTags(doc),
	})
	b.objectKeys[obj] = key
	b.addSpan(key, e.Path, pos.Line, endPos.Line)
	if !tn.IsAlias() {
		if kind == KindInterface {
			b.collectInterfaceMethods(e, ff, tn)
		}
		if st := structOf(tn.Type()); st != nil {
			if ent := b.proj.Entity(key); ent != nil && !ff.HasCgo {
				ent.StructSize, ent.OptimalStructSize = computeStructPadding(st)
			}
			b.collectFields(e, ff, sp, tn, st)
		}
	}
}

// typeDoc returns the doc comment text of a type declaration.
func typeDoc(g *ast.GenDecl, sp *ast.TypeSpec) string {
	if sp.Doc != nil {
		return sp.Doc.Text()
	}
	if g.Doc != nil {
		return g.Doc.Text()
	}
	return ""
}

// collectInterfaceMethods registers one entity per explicit interface method.
func (b *builder) collectInterfaceMethods(e *loader.FileEntry, ff *FileFacts, obj *types.TypeName) {
	it, ok := obj.Type().Underlying().(*types.Interface)
	if !ok {
		return
	}
	ifaceKey := MakeKey(KindInterface, obj.Pkg().Path(), "", obj.Name())
	for i := 0; i < it.NumExplicitMethods(); i++ {
		m := it.ExplicitMethod(i)
		key := MakeKey(KindMethod, m.Pkg().Path(), obj.Name(), m.Name())
		mpos := b.ld.Fset.Position(m.Pos())
		if !m.Pos().IsValid() {
			mpos = b.ld.Fset.Position(obj.Pos())
		}
		b.addEntity(ff, &Entity{
			Key: key, Kind: KindMethod,
			PkgPath: m.Pkg().Path(), PkgName: obj.Pkg().Name(),
			Recv: obj.Name(), Name: m.Name(),
			File: e.Path, Line: mpos.Line,
			Exported: m.Exported(), InterfaceMethod: true,
			TestFile: ff.InTest,
		})
		b.objectKeys[m] = key
		b.proj.InterfaceMethods[ifaceKey] = append(b.proj.InterfaceMethods[ifaceKey], key)
	}
}

// collectFields registers the fields of one named struct.
func (b *builder) collectFields(e *loader.FileEntry, ff *FileFacts, sp *ast.TypeSpec, obj *types.TypeName, st *types.Struct) {
	tags := astFieldTags(sp)
	pos := b.ld.Fset.Position(obj.Pos())
	for i := 0; i < st.NumFields(); i++ {
		fld := st.Field(i)
		if fld.Pkg() != obj.Pkg() || fld.Name() == "_" {
			continue
		}
		key := MakeKey(KindField, obj.Pkg().Path(), obj.Name(), fld.Name())
		fk := obj.Pkg().Path() + "\x1f" + fld.Name()
		if !containsKey(b.fieldKeys[fk], key) {
			b.fieldKeys[fk] = append(b.fieldKeys[fk], key)
		}
		fi := &FieldInfo{Struct: obj.Name(), Embedded: fld.Embedded(), Tag: tags[fld.Name()]}
		fi.TagNames = parseTagNames(fi.Tag)
		fpos := b.ld.Fset.Position(fld.Pos())
		if !fld.Pos().IsValid() {
			fpos = pos
		}
		b.addEntity(ff, &Entity{
			Key: key, Kind: KindField,
			PkgPath: obj.Pkg().Path(), PkgName: obj.Pkg().Name(),
			Recv: obj.Name(), Name: fld.Name(),
			File: e.Path, Line: fpos.Line, Col: fpos.Column,
			Exported: fld.Exported(), TestFile: ff.InTest, Field: fi,
		})
		b.objectKeys[fld] = key
		b.addSpan(key, e.Path, fpos.Line, fpos.Line)
	}
}

func astFieldTags(sp *ast.TypeSpec) map[string]string {
	out := map[string]string{}
	st, ok := sp.Type.(*ast.StructType)
	if !ok || st.Fields == nil {
		return out
	}
	for _, f := range st.Fields.List {
		tag := ""
		if f.Tag != nil {
			if v, err := strconv.Unquote(f.Tag.Value); err == nil {
				tag = v
			}
		}
		for _, n := range f.Names {
			out[n.Name] = tag
		}
		if len(f.Names) == 0 {
			if en := embeddedFieldName(f.Type); en != "" {
				out[en] = tag
			}
		}
	}
	return out
}

func embeddedFieldName(expr ast.Expr) string {
	switch x := expr.(type) {
	case *ast.StarExpr:
		return embeddedFieldName(x.X)
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.IndexExpr:
		return embeddedFieldName(x.X)
	case *ast.IndexListExpr:
		return embeddedFieldName(x.X)
	case *ast.Ident:
		return x.Name
	}
	return ""
}

// ---------------------------------------------------------------------------
// Uses.
// ---------------------------------------------------------------------------

func (b *builder) collectUses(e *loader.FileEntry) {
	info := e.Pkg.TypesInfo
	selfPkgPath := e.Pkg.PkgPath
	writeOnly := collectWriteOnlyIdents(e.Syntax)
	for ident, obj := range info.Uses {
		key, ok := b.resolveObjKey(obj)
		if !ok || key == "" {
			continue
		}
		pos := b.ld.Fset.Position(ident.Pos())
		kind := "ident"
		switch o := obj.(type) {
		case *types.Var:
			if o.IsField() {
				kind = "field"
			}
		case *types.Func:
			if sig, ok := o.Type().(*types.Signature); ok && sig.Recv() != nil {
				kind = "method"
			}
		case *types.TypeName:
			kind = "type"
		}
		b.recordUse(UseSite{
			Key: key, File: pos.Filename, PkgPath: selfPkgPath,
			Line: pos.Line, Off: pos.Offset, Kind: kind,
			FromTest: e.InTest, SelfPackage: key.Pkg() == selfPkgPath,
			WriteOnly: writeOnly[ident],
		})
	}
	// Field promotion through embedding: the intermediate embedded field is
	// used even though it never appears as an identifier.
	for expr, sel := range info.Selections {
		base := structOf(info.Types[expr].Type)
		if base == nil {
			continue
		}
		idx := sel.Index()
		for i := 0; i+1 < len(idx); i++ {
			fld := base.Field(idx[i])
			if key, ok := b.resolveObjKey(fld); ok {
				pos := b.ld.Fset.Position(expr.Pos())
				b.recordUse(UseSite{
					Key: key, File: pos.Filename, PkgPath: selfPkgPath, Line: pos.Line,
					Kind: "embed", FromTest: e.InTest, SelfPackage: key.Pkg() == selfPkgPath,
				})
			}
		}
	}
}

func (b *builder) recordUse(u UseSite) {
	if u.Key == "" {
		return
	}
	_ = u.Containing()
	b.proj.Uses[u.Key] = append(b.proj.Uses[u.Key], u)
}

// ---------------------------------------------------------------------------
// Spans and self-use suppression.
// ---------------------------------------------------------------------------

// computeTypeSpans extends every named type's span with its own methods'
// spans, so a type whose only "uses" are its receivers reports as unused.
func (b *builder) computeTypeSpans() {
	byType := map[Key][]Key{} // type key -> method keys
	for mKey := range b.methodRecv {
		tKey := MakeKey(KindType, mKey.Pkg(), "", mKey.Container())
		byType[tKey] = append(byType[tKey], mKey)
	}
	for tKey, methods := range byType {
		for _, mKey := range methods {
			for _, sp := range b.proj.EntitySpans[mKey] {
				b.addSpan(tKey, sp.File, sp.StartLine, sp.EndLine)
			}
		}
	}
}

// addSpan records one span of an entity, merging overlaps.
func (b *builder) addSpan(key Key, file string, start, end int) {
	spans := b.proj.EntitySpans[key]
	spans = append(spans, Span{File: file, StartLine: start, EndLine: end})
	b.proj.EntitySpans[key] = spans
}

// insideOwnSpan reports whether a use lies within the declaring entity.
func insideOwnSpan(p *Project, key Key, u UseSite) bool {
	for _, sp := range p.EntitySpans[key] {
		if sp.File == u.File && u.Line >= sp.StartLine && u.Line <= sp.EndLine {
			return true
		}
	}
	return false
}

// LiveUses returns the use sites of an entity that count toward keeping it
// alive: references outside the entity's own declaration, restricted to the
// declaring package for unexported symbols.
func (p *Project) LiveUses(key Key) []UseSite {
	e := p.Entities[key]
	if e == nil {
		return nil
	}
	var out []UseSite
	for _, u := range p.Uses[key] {
		if insideOwnSpan(p, key, u) {
			continue
		}
		if !e.Exported && !u.SelfPackage {
			// Unexported symbols cannot be seen from another package.
			continue
		}
		out = append(out, u)
	}
	return out
}

// ---------------------------------------------------------------------------
// Project-level resolution.
// ---------------------------------------------------------------------------

func (b *builder) resolve() {
	b.creditDirectives()
	b.creditInactiveBuildTagFiles()
	b.creditInterfaces()
	b.creditStdlibInterfaces()
	b.creditReflection()
	b.markEntryPackages()
}

// stdInterfaces are well-known standard-library interfaces whose method sets
// a project type can satisfy without any in-repo call site: json.Marshaler,
// error, fmt.Stringer, io.Reader, sort.Interface, and friends. A live type
// that implements one keeps those methods, exactly like fallow keeps a base-
// class contract. Each entry is (package path, interface name).
var stdInterfaces = []struct{ pkg, name string }{
	{"encoding", "BinaryUnmarshaler"}, {"encoding", "BinaryMarshaler"},
	{"encoding", "TextUnmarshaler"}, {"encoding", "TextMarshaler"},
	{"encoding/json", "Marshaler"}, {"encoding/json", "Unmarshaler"},
	{"encoding/xml", "Marshaler"}, {"encoding/xml", "Unmarshaler"},
	{"encoding/gob", "GobEncoder"}, {"encoding/gob", "GobDecoder"},
	{"fmt", "Stringer"}, {"fmt", "GoStringer"}, {"fmt", "Formatter"},
	{"io", "Reader"}, {"io", "Writer"}, {"io", "Closer"}, {"io", "Seeker"},
	{"io", "ReaderFrom"}, {"io", "WriterTo"}, {"io", "ReadWriteCloser"},
	{"net/http", "Handler"}, {"net/http", "HandlerFunc"},
	{"sort", "Interface"}, {"database/sql/driver", "Valuer"},
	{"context", "Context"},
}

// creditStdlibInterfaces credits the methods a live project type uses to
// satisfy a standard-library interface such as json.Marshaler or fmt.Stringer.
// Dependency packages are not in ld.Pkgs; they hang off the ImportMap of each
// loaded package, so the lookup walks that closure.
func (b *builder) creditStdlibInterfaces() {
	want := map[string]*types.Interface{}
	for key, it := range resolveStdInterfaces(b.allTypesPackages()) {
		want[key] = it
	}
	if errObj := types.Universe.Lookup("error"); errObj != nil {
		if it, ok := errObj.Type().Underlying().(*types.Interface); ok {
			want["builtin.error"] = it
		}
	}
	if len(want) == 0 {
		return
	}
	for entry := range b.proj.Files {
		ff := b.proj.File(entry)
		pkg := b.typesPackage(ff.PkgPath)
		if pkg == nil {
			continue
		}
		scope := pkg.Scope()
		for _, name := range scope.Names() {
			obj, ok := scope.Lookup(name).(*types.TypeName)
			if !ok || obj.Pkg() != pkg {
				continue
			}
			if _, isIface := obj.Type().Underlying().(*types.Interface); isIface {
				continue
			}
			typeKey := MakeKey(KindType, obj.Pkg().Path(), "", obj.Name())
			if b.proj.Entity(typeKey) == nil {
				continue
			}
			// Only a live type can credit its contract methods.
			if len(b.proj.UsesOf(typeKey)) == 0 && !b.proj.InterfaceSatisfied[typeKey] {
				continue
			}
			for ifaceName, it := range want {
				if !satisfies(obj.Type(), it) {
					continue
				}
				for i := 0; i < it.NumMethods(); i++ {
					mName := it.Method(i).Name()
					mKey := MakeKey(KindMethod, obj.Pkg().Path(), obj.Name(), mName)
					if b.proj.Entity(mKey) != nil {
						b.recordUse(UseSite{Key: mKey, Kind: "iface", SelfPackage: true})
					}
				}
				if ifaceName == "builtin.error" {
					for _, mName := range []string{"Unwrap", "Is", "As"} {
						mKey := MakeKey(KindMethod, obj.Pkg().Path(), obj.Name(), mName)
						if b.proj.Entity(mKey) != nil {
							b.recordUse(UseSite{Key: mKey, Kind: "iface", SelfPackage: true})
						}
					}
				}
			}
		}
	}
}

// satisfies reports whether T or *T implements the interface it.
func satisfies(T types.Type, it *types.Interface) bool {
	return types.Implements(T, it) || types.Implements(types.NewPointer(T), it)
}

// resolveStdInterfaces finds each wanted well-known interface inside any of
// the given loaded packages and keys it by "pkgpath.Name".
func resolveStdInterfaces(pkgs []*packages.Package) map[string]*types.Interface {
	out := map[string]*types.Interface{}
	seen := map[string]bool{}
	var walk func(p *packages.Package)
	walk = func(p *packages.Package) {
		if p == nil || seen[p.PkgPath] {
			return
		}
		seen[p.PkgPath] = true
		if p.Types != nil {
			for _, spec := range stdInterfaces {
				if spec.pkg != p.PkgPath {
					continue
				}
				obj := p.Types.Scope().Lookup(spec.name)
				if obj == nil {
					continue
				}
				if it, ok := obj.Type().Underlying().(*types.Interface); ok {
					out[spec.pkg+"."+spec.name] = it
				}
			}
		}
		for _, dep := range p.Imports {
			walk(dep)
		}
	}
	for _, p := range pkgs {
		walk(p)
	}
	return out
}

// allTypesPackages returns the project root packages for the closure walk.
func (b *builder) allTypesPackages() []*packages.Package {
	return b.ld.Pkgs
}

// typesPackage returns the named types.Package for a project path.
func (b *builder) typesPackage(pkgPath string) *types.Package {
	for _, p := range b.ld.Pkgs {
		if p.PkgPath == pkgPath {
			return p.Types
		}
	}
	return nil
}

// creditInterfaces keeps an interface and its contract alive when the
// interface is referenced, embedded by another used interface, or implemented
// by a project type.
func (b *builder) creditInterfaces() {
	used := map[Key]bool{}
	for key, uses := range b.proj.Uses {
		if key.KindOf() != KindInterface {
			continue
		}
		for _, u := range uses {
			if u.Kind != "iface" && !insideOwnSpan(b.proj, key, u) {
				used[key] = true
				break
			}
		}
	}
	// Embedding closure over project interfaces.
	for changed := true; changed; {
		changed = false
		for key := range used {
			for _, emb := range b.embeddedInterfaces(key) {
				if _, ok := b.proj.InterfaceMethods[emb]; ok && !used[emb] {
					used[emb] = true
					changed = true
				}
			}
		}
	}
	implementors := b.interfaceImplementors(used)
	for key := range implementors {
		used[key] = true
	}
	for key := range used {
		b.proj.InterfaceSatisfied[key] = true
		for _, mKey := range b.proj.InterfaceMethods[key] {
			b.recordUse(UseSite{Key: mKey, Kind: "iface", SelfPackage: true})
		}
	}
	// Implementor methods are callable through the interface, so credit them.
	for ifaceKey, types_ := range implementors {
		sigs := b.interfaceMethodNames(ifaceKey)
		for _, typeKey := range types_ {
			for name := range sigs {
				mKey := MakeKey(KindMethod, typeKey.Pkg(), typeKey.Name(), name)
				if _, ok := b.proj.Entities[mKey]; ok {
					b.recordUse(UseSite{Key: mKey, Kind: "iface", SelfPackage: true})
				}
			}
		}
	}
}

func (b *builder) embeddedInterfaces(ifaceKey Key) []Key {
	t, ok := b.projectType(ifaceKey.Pkg(), ifaceKey.Name())
	if !ok {
		return nil
	}
	it, ok := t.Underlying().(*types.Interface)
	if !ok {
		return nil
	}
	var out []Key
	for i := 0; i < it.NumEmbeddeds(); i++ {
		if named, ok := namedOf(it.EmbeddedType(i)); ok && named.Obj().Pkg() != nil {
			out = append(out, MakeKey(KindInterface, named.Obj().Pkg().Path(), "", named.Obj().Name()))
		}
	}
	return out
}

func (b *builder) interfaceMethodNames(ifaceKey Key) map[string]bool {
	out := map[string]bool{}
	t, ok := b.projectType(ifaceKey.Pkg(), ifaceKey.Name())
	if !ok {
		return out
	}
	it, ok := t.Underlying().(*types.Interface)
	if !ok {
		return out
	}
	for i := 0; i < it.NumMethods(); i++ {
		out[it.Method(i).Name()] = true
	}
	return out
}

// interfaceImplementors returns, per candidate interface, the project named
// types that satisfy it.
func (b *builder) interfaceImplementors(used map[Key]bool) map[Key][]Key {
	out := map[Key][]Key{}
	candidates := map[Key]*types.Interface{}
	for key := range b.proj.InterfaceMethods {
		t, ok := b.projectType(key.Pkg(), key.Name())
		if !ok {
			continue
		}
		if it, ok := t.Underlying().(*types.Interface); ok {
			candidates[key] = it
		}
	}
	if len(candidates) == 0 {
		return out
	}
	for _, pkg := range b.ld.Pkgs {
		if pkg.Types == nil || !b.ld.IsProjectPkg(pkg) {
			continue
		}
		scope := pkg.Types.Scope()
		names := scope.Names()
		for _, name := range names {
			obj, ok := scope.Lookup(name).(*types.TypeName)
			if !ok || obj.Pkg() != pkg.Types {
				continue
			}
			if _, isIface := obj.Type().Underlying().(*types.Interface); isIface {
				continue
			}
			typeKey := MakeKey(KindType, obj.Pkg().Path(), "", obj.Name())
			if _, exists := b.proj.Entities[typeKey]; !exists {
				continue
			}
			// Only a type that is itself live can credit an interface.
			if len(b.proj.LiveUses(typeKey)) == 0 && !b.proj.InterfaceSatisfied[typeKey] {
				continue
			}
			for ifaceKey, it := range candidates {
				if ifaceKey.Pkg() == obj.Pkg().Path() && ifaceKey.Name() == obj.Name() {
					continue
				}
				if types.Implements(obj.Type(), it) || types.Implements(types.NewPointer(obj.Type()), it) {
					out[ifaceKey] = append(out[ifaceKey], typeKey)
				}
			}
		}
	}
	return out
}

func (b *builder) projectType(pkgPath, name string) (types.Type, bool) {
	for _, pkg := range b.ld.Pkgs {
		if pkg.PkgPath != pkgPath || pkg.Types == nil {
			continue
		}
		obj, ok := pkg.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			return nil, false
		}
		return obj.Type(), true
	}
	return nil, false
}

// reflectCodecs marshal structs by reflection, which makes their tagged
// fields reachable at runtime.
var reflectCodecs = map[string]bool{
	"encoding/json":    true,
	"encoding/xml":     true,
	"encoding/gob":     true,
	"gopkg.in/yaml.v3": true,
	"gopkg.in/yaml.v2": true,
	"reflect":          true,
}

var reflectFuncs = map[string]bool{
	"Marshal": true, "MarshalIndent": true, "Unmarshal": true,
	"NewDecoder": true, "NewEncoder": true, "Encode": true, "Decode": true,
	"TypeOf": true, "ValueOf": true, "DeepEqual": true,
}

func (b *builder) creditReflection() {
	for _, entry := range b.ld.Files {
		if !b.ld.IsProjectPkg(entry.Pkg) || entry.Syntax == nil || entry.Pkg.TypesInfo == nil {
			continue
		}
		info := entry.Pkg.TypesInfo
		ast.Inspect(entry.Syntax, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, isSel := call.Fun.(*ast.SelectorExpr)
			if !isSel {
				return true
			}
			obj := info.Uses[sel.Sel]
			if obj == nil || obj.Pkg() == nil {
				return true
			}
			if !reflectCodecs[obj.Pkg().Path()] || !reflectFuncs[sel.Sel.Name] {
				return true
			}
			b.proj.ReflectivePkgs[entry.Pkg.PkgPath] = true
			for _, arg := range call.Args {
				if t := info.TypeOf(arg); t != nil {
					b.creditFieldsOf(t, entry.Pkg.PkgPath)
				}
			}
			return true
		})
	}
	if len(b.proj.ReflectivePkgs) > 0 {
		seen := map[Key]bool{}
		for _, pkg := range b.ld.Pkgs {
			if pkg.Types == nil || !b.ld.IsProjectPkg(pkg) {
				continue
			}
			scope := pkg.Types.Scope()
			for _, name := range scope.Names() {
				obj, ok := scope.Lookup(name).(*types.TypeName)
				if !ok || obj.Pkg() != pkg.Types {
					continue
				}
				st, ok := obj.Type().Underlying().(*types.Struct)
				if !ok {
					continue
				}
				typeKey := MakeKey(KindType, obj.Pkg().Path(), "", obj.Name())
				if seen[typeKey] {
					continue
				}
				seen[typeKey] = true
				if b.proj.Entity(typeKey) == nil {
					continue
				}
				if len(b.proj.LiveUses(typeKey)) == 0 && !b.proj.InterfaceSatisfied[typeKey] {
					continue
				}
				hasTag := false
				for i := 0; i < st.NumFields(); i++ {
					fld := st.Field(i)
					fKey := MakeKey(KindField, obj.Pkg().Path(), obj.Name(), fld.Name())
					if ent := b.proj.Entity(fKey); ent != nil && ent.Field != nil && len(ent.Field.TagNames) > 0 {
						hasTag = true
						break
					}
				}
				if hasTag {
					b.creditFieldsOf(obj.Type(), obj.Pkg().Path())
				}
			}
		}
	}
}

// creditFieldsOf marks the fields of a reflect-reached type used. Reflection
// can populate a whole struct tree from one marshal or unmarshal call, so the
// credit recurses through nested named struct types. Only exported fields are
// credited, because encoding/json and yaml ignore unexported ones.
func (b *builder) creditFieldsOf(t types.Type, viaPkg string) {
	b.creditRecurse(t, viaPkg, map[*types.Named]bool{}, 0)
}

func (b *builder) creditRecurse(t types.Type, viaPkg string, seen map[*types.Named]bool, depth int) {
	if depth > 6 || t == nil {
		return
	}
	for {
		if alias, ok := t.(*types.Alias); ok {
			if key, ok := b.resolveObjKey(alias.Obj()); ok {
				b.recordUse(UseSite{Key: key, Kind: "tag", SelfPackage: true})
			}
			t = types.Unalias(alias)
			continue
		}
		switch x := t.(type) {
		case *types.Pointer:
			t = x.Elem()
			continue
		case *types.Slice:
			t = x.Elem()
			continue
		case *types.Array:
			t = x.Elem()
			continue
		case *types.Map:
			b.creditRecurse(x.Key(), viaPkg, seen, depth+1)
			t = x.Elem()
			continue
		case *types.Chan:
			t = x.Elem()
			continue
		}
		break
	}
	switch x := t.(type) {
	case *types.Named:
		if seen[x] {
			return
		}
		seen[x] = true
		if key, ok := b.resolveObjKey(x.Obj()); ok {
			b.recordUse(UseSite{Key: key, Kind: "tag", SelfPackage: true})
		}
		// An alias resolves to the referenced named type.
		obj := x.Obj()
		if obj.Type() != x {
			b.creditRecurse(obj.Type(), viaPkg, seen, depth)
			return
		}
		if st, ok := x.Underlying().(*types.Struct); ok {
			b.creditStructFields(st, viaPkg)
			for i := 0; i < st.NumFields(); i++ {
				b.creditRecurse(st.Field(i).Type(), viaPkg, seen, depth+1)
			}
		}
	case *types.Struct:
		b.creditStructFields(x, viaPkg)
		for i := 0; i < x.NumFields(); i++ {
			b.creditRecurse(x.Field(i).Type(), viaPkg, seen, depth+1)
		}
	}
}

// creditStructFields records a reflective use of every exported field.
func (b *builder) creditStructFields(st *types.Struct, viaPkg string) {
	b.proj.ReflectivePkgs[viaPkg] = true
	for i := 0; i < st.NumFields(); i++ {
		fld := st.Field(i)
		if !fld.Exported() {
			continue
		}
		if key, ok := b.resolveObjKey(fld); ok {
			b.recordUse(UseSite{Key: key, Kind: "tag", SelfPackage: true})
		}
	}
}

// markEntryPackages flags main packages as reachability roots. The Go rule is
// the package *name* main (plus a main function), not the last path element:
// module/foo/cmd can be a library named cmd, and module/cmd/bar can be main.
func (b *builder) markEntryPackages() {
	for _, entry := range b.proj.Files {
		if entry.InTest {
			continue
		}
		if entry.PkgName == "main" {
			b.proj.EntryPkgs[entry.PkgPath] = true
		}
	}
}

// addEntity registers one entity. The declaration with a body wins for
// methods declared once, and duplicates (same name across files) keep first.
func (b *builder) addEntity(ff *FileFacts, e *Entity) {
	if e == nil || e.Key == "" {
		return
	}
	if e.Exported && e.DeclNode != nil && len(e.PrivateTypeCandidates) == 0 {
		e.PrivateTypeCandidates = extractPrivateTypeCandidates(e.DeclNode)
	}
	if existing, ok := b.proj.Entities[e.Key]; ok {
		if existing.Func != nil && existing.Func.Node != nil && existing.Func.Node.Body == nil &&
			e.Func != nil && e.Func.Node != nil && e.Func.Node.Body != nil {
			b.proj.Entities[e.Key] = e
		}
		return
	}
	b.proj.Entities[e.Key] = e
	if ff != nil {
		ff.Entities = append(ff.Entities, e.Key)
	}
}

// collectDeclSyntax collects top-level entities from AST when type info is not
// loaded (e.g. fast syntax-only runs for dupes, list, and architecture).
func (b *builder) collectDeclSyntax(e *loader.FileEntry, ff *FileFacts, decl ast.Decl) {
	pkgPath := e.Pkg.PkgPath
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Name == nil {
			return
		}
		kind := KindFunc
		recv := ""
		if d.Recv != nil && len(d.Recv.List) > 0 {
			kind = KindMethod
			recv = embeddedFieldName(d.Recv.List[0].Type)
		}
		key := MakeKey(kind, pkgPath, recv, d.Name.Name)
		pos := b.ld.Fset.Position(d.Pos())
		endPos := b.ld.Fset.Position(d.End())
		fi := &FuncInfo{
			Node: d, Loc: endPos.Line - pos.Line + 1,
			RecvTypeName: recv,
			IsTest:       ff.InTest && isTestName(d.Name.Name),
			IsInit:       d.Name.Name == "init",
			IsMain:       kind == KindFunc && d.Name.Name == "main" && ff.PkgName == "main",
		}
		if d.Type != nil {
			if d.Type.Params != nil {
				fi.Params = d.Type.Params.NumFields()
			}
			if d.Type.Results != nil {
				fi.Results = d.Type.Results.NumFields()
			}
		}
		if d.Body != nil {
			fi.Body = d.Body
			fi.BodyLoc = b.ld.Fset.Position(d.Body.End()).Line - pos.Line + 1
			cx := ComputeComplexity(b.ld.Fset, d)
			fi.Cyclomatic = cx.Cyclomatic
			fi.Cognitive = cx.Cognitive
			fi.Statements = cx.Statements
		}
		doc := ""
		if d.Doc != nil {
			doc = d.Doc.Text()
		}
		b.addEntity(ff, &Entity{
			Key: key, Kind: kind,
			PkgPath: pkgPath, PkgName: ff.PkgName,
			Recv: recv, Name: d.Name.Name,
			File: e.Path, Line: pos.Line, Col: pos.Column - 1,
			Exported: ast.IsExported(d.Name.Name), DeclNode: d,
			Doc: doc, Deprecated: strings.Contains(doc, "Deprecated:"),
			TestFile: ff.InTest, Func: fi, DocTags: parseDocTags(doc),
		})
		if kind == KindMethod {
			b.methodRecv[key] = recv
		}
		b.addSpan(key, e.Path, pos.Line, endPos.Line)
	case *ast.GenDecl:
		switch d.Tok {
		case token.TYPE:
			for _, spec := range d.Specs {
				sp, ok := spec.(*ast.TypeSpec)
				if !ok || sp.Name == nil {
					continue
				}
				kind := KindType
				if _, isIface := sp.Type.(*ast.InterfaceType); isIface {
					kind = KindInterface
				}
				key := MakeKey(kind, pkgPath, "", sp.Name.Name)
				doc := typeDoc(d, sp)
				pos := b.ld.Fset.Position(sp.Pos())
				endPos := b.ld.Fset.Position(sp.End())
				b.addEntity(ff, &Entity{
					Key: key, Kind: kind,
					PkgPath: pkgPath, PkgName: ff.PkgName,
					Name: sp.Name.Name, File: e.Path,
					Line: pos.Line, Col: pos.Column - 1,
					Exported: ast.IsExported(sp.Name.Name), DeclNode: sp,
					Doc: doc, Deprecated: strings.Contains(doc, "Deprecated:"),
					TestFile: ff.InTest, DocTags: parseDocTags(doc),
				})
				b.addSpan(key, e.Path, pos.Line, endPos.Line)
			}
		case token.CONST, token.VAR:
			for _, spec := range d.Specs {
				sp, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				kind := KindVar
				if d.Tok == token.CONST {
					kind = KindConst
				}
				doc := valueDoc(d, sp)
				for _, name := range sp.Names {
					if name == nil || name.Name == "_" {
						continue
					}
					key := MakeKey(kind, pkgPath, "", name.Name)
					pos := b.ld.Fset.Position(name.Pos())
					b.addEntity(ff, &Entity{
						Key: key, Kind: kind,
						PkgPath: pkgPath, PkgName: ff.PkgName,
						Name: name.Name, File: e.Path,
						Line: pos.Line, Col: pos.Column - 1,
						Exported: ast.IsExported(name.Name), DeclNode: sp,
						Doc: doc, Deprecated: strings.Contains(doc, "Deprecated:"),
						TestFile: ff.InTest, DocTags: parseDocTags(doc),
					})
					b.addSpan(key, e.Path, pos.Line, pos.Line)
				}
			}
		}
	}
}

func extractPrivateTypeCandidates(decl ast.Node) []string {
	var exprs []ast.Expr
	switch node := decl.(type) {
	case *ast.FuncDecl:
		if node.Type != nil {
			if node.Type.Params != nil {
				for _, fld := range node.Type.Params.List {
					exprs = append(exprs, fld.Type)
				}
			}
			if node.Type.Results != nil {
				for _, fld := range node.Type.Results.List {
					exprs = append(exprs, fld.Type)
				}
			}
		}
	case *ast.TypeSpec:
		if st, ok := node.Type.(*ast.StructType); ok && st.Fields != nil {
			for _, fld := range st.Fields.List {
				isExp := len(fld.Names) == 0
				for _, name := range fld.Names {
					if name.IsExported() {
						isExp = true
						break
					}
				}
				if isExp {
					exprs = append(exprs, fld.Type)
				}
			}
		} else {
			exprs = append(exprs, node.Type)
		}
	case *ast.ValueSpec:
		if node.Type != nil {
			exprs = append(exprs, node.Type)
		}
	}
	var out []string
	for _, expr := range exprs {
		if expr == nil {
			continue
		}
		ast.Inspect(expr, func(n ast.Node) bool {
			switch t := n.(type) {
			case *ast.SelectorExpr:
				return false
			case *ast.Ident:
				if !ast.IsExported(t.Name) {
					out = append(out, t.Name)
				}
			}
			return true
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

func (b *builder) rel(abs string) string {
	if b.proj.Module.Dir != "" && strings.HasPrefix(abs, b.proj.Module.Dir+"/") {
		return strings.ReplaceAll(strings.TrimPrefix(abs, b.proj.Module.Dir+"/"), `\`, "/")
	}
	return strings.ReplaceAll(abs, `\`, "/")
}

func structOf(t types.Type) *types.Struct {
	for t != nil {
		t = types.Unalias(t)
		switch x := t.(type) {
		case *types.Pointer:
			t = x.Elem()
		case *types.Named:
			t = x.Underlying()
		case *types.Struct:
			return x
		default:
			return nil
		}
	}
	return nil
}

func namedOf(t types.Type) (*types.Named, bool) {
	for t != nil {
		t = types.Unalias(t)
		switch x := t.(type) {
		case *types.Pointer:
			t = x.Elem()
		case *types.Named:
			return x, true
		default:
			return nil, false
		}
	}
	return nil, false
}

func namedTypeName(t types.Type) string {
	if n, ok := namedOf(t); ok {
		return n.Obj().Name()
	}
	return "unknown"
}

func isTestName(name string) bool {
	for _, p := range []string{"Test", "Benchmark", "Fuzz", "Example"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func parseDocTags(doc string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(doc, "\n") {
		line = strings.TrimSpace(line)
		if len(line) > 1 && line[0] == '@' && strings.Fields(line)[0] != "@" {
			out[strings.Fields(line)[0]] = true
		}
	}
	return out
}

var structTagRe = regexp.MustCompile(`(\w+):"([^"]*)"`)

func parseTagNames(tag string) []string {
	var out []string
	for _, m := range structTagRe.FindAllStringSubmatch(tag, -1) {
		val := m[2]
		if val == "" || val == "-" {
			continue
		}
		name := strings.Split(val, ",")[0]
		if name == "" {
			// Options-only tags such as `json:",omitempty"` or `yaml:",inline"`
			// serialize under the Go field name via this codec key.
			out = append(out, m[1])
			continue
		}
		if name != "-" {
			out = append(out, name)
		}
	}
	return out
}

func countLines(data []byte) int {
	s := string(data)
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}

var _ = token.NoPos

func containsKey(list []Key, k Key) bool {
	for _, x := range list {
		if x == k {
			return true
		}
	}
	return false
}
