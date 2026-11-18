package facts

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"goose/internal/loader"
)

var (
	exportDirRe   = regexp.MustCompile(`^//export\s+([A-Za-z_][A-Za-z0-9_]*)\s*$`)
	linknameDirRe = regexp.MustCompile(`^//go:linkname\s+([A-Za-z_][A-Za-z0-9_]*)(\s+|$)`)
	pemKeyRe      = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)
	tokenPrefixRe = regexp.MustCompile(`(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})`)
)

// collectWriteOnlyIdents returns the set of *ast.Ident nodes in file that
// appear exclusively as the target of a simple assignment (=) or as the field
// name key of a struct composite literal.
func collectWriteOnlyIdents(file *ast.File) map[*ast.Ident]bool {
	out := map[*ast.Ident]bool{}
	if file == nil {
		return out
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			for _, elt := range x.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if id, ok := kv.Key.(*ast.Ident); ok {
						out[id] = true
					}
				}
			}
		case *ast.AssignStmt:
			if x.Tok != token.ASSIGN {
				return true
			}
			for _, lhs := range x.Lhs {
				switch target := lhs.(type) {
				case *ast.Ident:
					out[target] = true
				case *ast.SelectorExpr:
					if target.Sel != nil {
						out[target.Sel] = true
					}
				}
			}
		}
		return true
	})
	return out
}

// collectUnusedParamsAndRecv populates fi.UnusedParams and fi.UnusedReceiver
// using go/types object identity within d.Body.
func (b *builder) collectUnusedParamsAndRecv(e *loader.FileEntry, d *ast.FuncDecl, fi *FuncInfo, info *types.Info) {
	if d == nil || d.Body == nil || info == nil || len(d.Body.List) == 0 {
		return
	}
	if fi.IsTest || fi.IsInit || fi.IsMain {
		return
	}
	// Skip single-statement panic/stub functions.
	if len(d.Body.List) == 1 {
		if exprStmt, ok := d.Body.List[0].(*ast.ExprStmt); ok {
			if call, ok := exprStmt.X.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "panic" {
					return
				}
			}
		}
	}

	usedInBody := map[types.Object]bool{}
	ast.Inspect(d.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if obj := info.Uses[id]; obj != nil {
				usedInBody[obj] = true
			}
		}
		return true
	})

	// Check receiver.
	if d.Recv != nil && len(d.Recv.List) > 0 && len(d.Recv.List[0].Names) > 0 {
		rIdent := d.Recv.List[0].Names[0]
		if rIdent != nil && rIdent.Name != "_" && rIdent.Name != "" {
			if rObj := info.Defs[rIdent]; rObj != nil && !usedInBody[rObj] {
				pos := b.ld.Fset.Position(rIdent.Pos())
				fi.UnusedReceiver = &ParamFact{
					Name: rIdent.Name,
					Line: pos.Line,
					Col:  pos.Column - 1,
				}
			}
		}
	}

	// Check parameters.
	if d.Type != nil && d.Type.Params != nil {
		for _, fld := range d.Type.Params.List {
			for _, pIdent := range fld.Names {
				if pIdent == nil || pIdent.Name == "_" || pIdent.Name == "" {
					continue
				}
				if pObj := info.Defs[pIdent]; pObj != nil && !usedInBody[pObj] {
					pos := b.ld.Fset.Position(pIdent.Pos())
					fi.UnusedParams = append(fi.UnusedParams, ParamFact{
						Name: pIdent.Name,
						Line: pos.Line,
						Col:  pos.Column - 1,
					})
				}
			}
		}
	}
}

var stdSizes64 = &types.StdSizes{WordSize: 8, MaxAlign: 8}

// computeStructPadding calculates the actual 64-bit byte size of st and its
// optimal byte size when fields are sorted by alignment descending.
func computeStructPadding(st *types.Struct) (actual, optimal int64) {
	if st == nil || st.NumFields() < 3 {
		return 0, 0
	}
	actual = stdSizes64.Sizeof(st)
	fields := make([]*types.Var, st.NumFields())
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		// Zero-sized trailing fields or blank padding fields (`_ [4]byte`) are intentional.
		if f.Name() == "_" {
			return actual, actual
		}
		fields[i] = types.NewField(f.Pos(), f.Pkg(), f.Name(), f.Type(), f.Embedded())
	}
	sort.SliceStable(fields, func(i, j int) bool {
		ai := stdSizes64.Alignof(fields[i].Type())
		aj := stdSizes64.Alignof(fields[j].Type())
		if ai != aj {
			return ai > aj
		}
		return stdSizes64.Sizeof(fields[i].Type()) > stdSizes64.Sizeof(fields[j].Type())
	})
	optStruct := types.NewStruct(fields, nil)
	optimal = stdSizes64.Sizeof(optStruct)
	return actual, optimal
}

// populateContainingKeys assigns ContainingKey on every recorded UseSite based
// on the innermost entity declaration span in the same file.
func (b *builder) populateContainingKeys(ownSpans map[Key]Span) {
	byFile := map[string][]struct {
		key  Key
		kind Kind
		span Span
	}{}
	for k, sp := range ownSpans {
		e := b.proj.Entities[k]
		if e == nil || e.Kind == KindField || e.InterfaceMethod {
			continue
		}
		byFile[sp.File] = append(byFile[sp.File], struct {
			key  Key
			kind Kind
			span Span
		}{key: k, kind: e.Kind, span: sp})
	}
	for k, sites := range b.proj.Uses {
		for i := range sites {
			u := &sites[i]
			if u.ContainingKey != "" || u.File == "" || u.Line <= 0 {
				continue
			}
			candidates := byFile[u.File]
			bestKey := Key("")
			bestLen := int(1e9)
			bestIsFunc := false
			for _, cand := range candidates {
				if u.Line < cand.span.StartLine || u.Line > cand.span.EndLine {
					continue
				}
				spanLen := cand.span.EndLine - cand.span.StartLine
				isFunc := cand.kind == KindFunc || cand.kind == KindMethod
				if bestKey == "" || (isFunc && !bestIsFunc) || (isFunc == bestIsFunc && spanLen < bestLen) {
					bestKey = cand.key
					bestLen = spanLen
					bestIsFunc = isFunc
				}
			}
			u.ContainingKey = bestKey
		}
		b.proj.Uses[k] = sites
	}
}

// creditDirectives records synthetic uses for symbols targeted by //export or
// //go:linkname comments in their package.
func (b *builder) creditDirectives() {
	for _, ff := range b.proj.Files {
		if len(ff.DirectiveTargets) == 0 {
			continue
		}
		for _, name := range ff.DirectiveTargets {
			for _, kind := range []Kind{KindFunc, KindVar, KindConst, KindType} {
				k := MakeKey(kind, ff.PkgPath, "", name)
				if b.proj.Entity(k) != nil {
					b.recordUse(UseSite{Key: k, Kind: "directive", SelfPackage: true})
				}
			}
		}
	}
}

// creditInactiveBuildTagFiles parses .go files in project package directories
// that were skipped by the active GOOS/GOARCH/build tags so cross-platform
// helpers in shared files are not falsely reported as dead code.
func (b *builder) creditInactiveBuildTagFiles() {
	pkgByDir := map[string]string{}
	for path, ff := range b.proj.Files {
		dir := filepath.Dir(path)
		if _, ok := pkgByDir[dir]; !ok {
			pkgByDir[dir] = ff.PkgPath
		}
	}
	fset := token.NewFileSet()
	for dir, pkgPath := range pkgByDir {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, de := range entries {
			if de.IsDir() {
				continue
			}
			name := de.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				continue
			}
			full := filepath.Join(dir, name)
			if _, loaded := b.ld.Files[full]; loaded {
				continue
			}
			inTest := strings.HasSuffix(name, "_test.go")
			if inTest && !b.ld.Tests {
				continue
			}
			parsed, err := parser.ParseFile(fset, full, nil, 0)
			if err != nil || parsed == nil {
				continue
			}
			// Map imported package names to project package paths.
			importAliases := map[string]string{}
			for _, imp := range parsed.Imports {
				ipath, uerr := strconv.Unquote(imp.Path.Value)
				if uerr != nil {
					continue
				}
				alias := filepath.Base(ipath)
				if imp.Name != nil && imp.Name.Name != "_" && imp.Name.Name != "." {
					alias = imp.Name.Name
				}
				importAliases[alias] = ipath
			}
			ast.Inspect(parsed, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					if id, ok := x.X.(*ast.Ident); ok {
						if targetPkg, ok := importAliases[id.Name]; ok && x.Sel != nil {
							b.creditSymbolByName(targetPkg, x.Sel.Name, full, pkgPath, inTest)
							return false
						}
					}
					if x.Sel != nil {
						b.creditMethodOrFieldByName(pkgPath, x.Sel.Name, full, inTest)
					}
				case *ast.Ident:
					b.creditSymbolByName(pkgPath, x.Name, full, pkgPath, inTest)
				}
				return true
			})
		}
	}
}

func (b *builder) creditSymbolByName(targetPkg, name, fromFile, fromPkg string, fromTest bool) {
	for _, kind := range []Kind{KindFunc, KindType, KindInterface, KindConst, KindVar} {
		k := MakeKey(kind, targetPkg, "", name)
		if b.proj.Entity(k) != nil {
			b.recordUse(UseSite{
				Key: k, File: fromFile, PkgPath: fromPkg, Line: 1,
				Kind: "buildtag", FromTest: fromTest, SelfPackage: targetPkg == fromPkg,
			})
		}
	}
}

func (b *builder) creditMethodOrFieldByName(pkgPath, name, fromFile string, fromTest bool) {
	for k, e := range b.proj.Entities {
		if e.PkgPath == pkgPath && e.Name == name && (e.Kind == KindMethod || e.Kind == KindField) {
			b.recordUse(UseSite{
				Key: k, File: fromFile, PkgPath: pkgPath, Line: 1,
				Kind: "buildtag", FromTest: fromTest, SelfPackage: true,
			})
		}
	}
}

// collectGoIssues inspects a type-checked file for Go-specific correctness
// issues, security sinks, hardcoded secrets, and feature-flag usages.
func (b *builder) collectGoIssues(e *loader.FileEntry, ff *FileFacts) {
	if e == nil || e.Syntax == nil || ff == nil {
		return
	}
	info := e.Pkg.TypesInfo
	fset := b.ld.Fset

	// 1. Scan top-level and function-level constructs.
	ast.Inspect(e.Syntax, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			b.checkFuncGoIssues(node, ff, info, fset)
		case *ast.ValueSpec:
			b.checkValueSpecSecrets(node, ff, fset)
		case *ast.AssignStmt:
			b.checkAssignSecrets(node, ff, fset)
		case *ast.KeyValueExpr:
			b.checkKeyValueIssues(node, ff, info, fset)
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				b.checkLiteralSecrets(node, "", ff, fset)
			}
		case *ast.CallExpr:
			b.checkCallIssues(node, ff, info, fset)
		}
		return true
	})
}

func (b *builder) checkFuncGoIssues(fn *ast.FuncDecl, ff *FileFacts, info *types.Info, fset *token.FileSet) {
	if fn == nil {
		return
	}
	fnName := ""
	if fn.Name != nil {
		fnName = fn.Name.Name
	}

	// Check copylocks on receiver, params, and results.
	if info != nil && !ff.InTest {
		if fn.Recv != nil {
			for _, fld := range fn.Recv.List {
				if lockName := containsLockByValue(info.TypeOf(fld.Type)); lockName != "" {
					pos := fset.Position(fld.Pos())
					ff.GoIssues = append(ff.GoIssues, GoIssue{
						Kind: "copylocks", Rule: "copylocks", Symbol: fnName,
						Line: pos.Line, Col: pos.Column - 1,
						Message: fmt.Sprintf("Method %q passes lock (%s) by value in receiver", fnName, lockName),
						Extra:   map[string]string{"lock_type": lockName},
					})
				}
			}
		}
		if fn.Type != nil && fn.Type.Params != nil {
			for _, fld := range fn.Type.Params.List {
				if lockName := containsLockByValue(info.TypeOf(fld.Type)); lockName != "" {
					pos := fset.Position(fld.Pos())
					ff.GoIssues = append(ff.GoIssues, GoIssue{
						Kind: "copylocks", Rule: "copylocks", Symbol: fnName,
						Line: pos.Line, Col: pos.Column - 1,
						Message: fmt.Sprintf("Function %q accepts lock (%s) by value parameter", fnName, lockName),
						Extra:   map[string]string{"lock_type": lockName},
					})
				}
			}
		}
	}

	if fn.Body == nil {
		return
	}

	// Check defer-in-loop.
	walkDeferInLoop(fn.Body, 0, fnName, ff, fset)

	if info == nil {
		return
	}

	// Check context-leak, unclosed-body, and nil-error-interface.
	b.checkContextAndResourceLeaks(fn, fnName, ff, info, fset)
	b.checkNilErrorInterface(fn, fnName, ff, info, fset)
}

func walkDeferInLoop(stmt ast.Stmt, loopDepth int, fnName string, ff *FileFacts, fset *token.FileSet) {
	if stmt == nil {
		return
	}
	ast.Inspect(stmt, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.FuncLit:
			// A closure resets loop depth for its own body.
			walkDeferInLoop(x.Body, 0, fnName, ff, fset)
			return false
		case *ast.ForStmt:
			walkDeferInLoop(x.Body, loopDepth+1, fnName, ff, fset)
			return false
		case *ast.RangeStmt:
			walkDeferInLoop(x.Body, loopDepth+1, fnName, ff, fset)
			return false
		case *ast.DeferStmt:
			if loopDepth > 0 {
				pos := fset.Position(x.Defer)
				ff.GoIssues = append(ff.GoIssues, GoIssue{
					Kind: "defer-in-loop", Rule: "defer-in-loop", Symbol: fnName,
					Line: pos.Line, Col: pos.Column - 1,
					Message: "Defer statement inside loop will not execute until the enclosing function returns",
				})
			}
		}
		return true
	})
}

func (b *builder) checkContextAndResourceLeaks(fn *ast.FuncDecl, fnName string, ff *FileFacts, info *types.Info, fset *token.FileSet) {
	// Collect all objects called, returned, or escaped in fn.Body.
	calledObjs := map[types.Object]bool{}
	closedObjs := map[types.Object]bool{}
	escapedObjs := map[types.Object]bool{}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok {
				if obj := info.Uses[id]; obj != nil {
					calledObjs[obj] = true
				}
			}
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel != nil && sel.Sel.Name == "Close" {
				if rootObj := rootIdentObj(sel.X, info); rootObj != nil {
					closedObjs[rootObj] = true
				}
			}
			for _, arg := range x.Args {
				if id, ok := arg.(*ast.Ident); ok {
					if obj := info.Uses[id]; obj != nil {
						escapedObjs[obj] = true
					}
				}
				if sel, ok := arg.(*ast.SelectorExpr); ok {
					if rootObj := rootIdentObj(sel, info); rootObj != nil {
						escapedObjs[rootObj] = true
					}
				}
			}
		case *ast.ReturnStmt:
			for _, res := range x.Results {
				if id, ok := res.(*ast.Ident); ok {
					if obj := info.Uses[id]; obj != nil {
						escapedObjs[obj] = true
					}
				}
				if sel, ok := res.(*ast.SelectorExpr); ok {
					if rootObj := rootIdentObj(sel, info); rootObj != nil {
						escapedObjs[rootObj] = true
					}
				}
			}
		case *ast.AssignStmt:
			// Assigning cancel to a struct field or map escapes it.
			for i, lhs := range x.Lhs {
				if _, isIdent := lhs.(*ast.Ident); !isIdent && i < len(x.Rhs) {
					if id, ok := x.Rhs[i].(*ast.Ident); ok {
						if obj := info.Uses[id]; obj != nil {
							escapedObjs[obj] = true
						}
					}
				}
			}
		}
		return true
	})

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		calleePkg, calleeName := resolveCalleePkgAndName(call, info)

		// 1. context.WithCancel / WithTimeout / WithDeadline / WithCancelCause / WithTimeoutCause
		if calleePkg == "context" && len(as.Lhs) >= 2 &&
			(calleeName == "WithCancel" || calleeName == "WithTimeout" ||
				calleeName == "WithDeadline" || calleeName == "WithCancelCause" ||
				calleeName == "WithTimeoutCause") {
			if cancelIdent, ok := as.Lhs[1].(*ast.Ident); ok {
				pos := fset.Position(cancelIdent.Pos())
				if cancelIdent.Name == "_" {
					ff.GoIssues = append(ff.GoIssues, GoIssue{
						Kind: "context-leak", Rule: "context-leak", Symbol: fnName,
						Line: pos.Line, Col: pos.Column - 1,
						Message: fmt.Sprintf("CancelFunc returned by context.%s is discarded with '_'", calleeName),
					})
				} else {
					obj := info.Defs[cancelIdent]
					if obj == nil {
						obj = info.Uses[cancelIdent]
					}
					if obj != nil && !calledObjs[obj] && !escapedObjs[obj] {
						ff.GoIssues = append(ff.GoIssues, GoIssue{
							Kind: "context-leak", Rule: "context-leak", Symbol: fnName,
							Line: pos.Line, Col: pos.Column - 1,
							Message: fmt.Sprintf("CancelFunc %q returned by context.%s is never called", cancelIdent.Name, calleeName),
						})
					}
				}
			}
		}

		// 2. Unclosed *http.Response.Body or *sql.Rows
		if len(as.Lhs) >= 1 {
			if resIdent, ok := as.Lhs[0].(*ast.Ident); ok && resIdent.Name != "_" {
				obj := info.Defs[resIdent]
				if obj == nil {
					obj = info.Uses[resIdent]
				}
				if obj != nil && !closedObjs[obj] && !escapedObjs[obj] {
					tStr := obj.Type().String()
					if tStr == "*net/http.Response" {
						pos := fset.Position(resIdent.Pos())
						ff.GoIssues = append(ff.GoIssues, GoIssue{
							Kind: "unclosed-body", Rule: "unclosed-body", Symbol: fnName,
							Line: pos.Line, Col: pos.Column - 1,
							Message: fmt.Sprintf("HTTP response %q body is never closed (missing defer %s.Body.Close())", resIdent.Name, resIdent.Name),
						})
					} else if tStr == "*database/sql.Rows" {
						pos := fset.Position(resIdent.Pos())
						ff.GoIssues = append(ff.GoIssues, GoIssue{
							Kind: "unclosed-body", Rule: "unclosed-body", Symbol: fnName,
							Line: pos.Line, Col: pos.Column - 1,
							Message: fmt.Sprintf("SQL rows %q is never closed (missing defer %s.Close())", resIdent.Name, resIdent.Name),
						})
					}
				}
			}
		}
		return true
	})
}

func (b *builder) checkNilErrorInterface(fn *ast.FuncDecl, fnName string, ff *FileFacts, info *types.Info, fset *token.FileSet) {
	if fn.Type == nil || fn.Type.Results == nil {
		return
	}
	var resultTypes []types.Type
	for _, fld := range fn.Type.Results.List {
		t := info.TypeOf(fld.Type)
		if len(fld.Names) == 0 {
			resultTypes = append(resultTypes, t)
		} else {
			for range fld.Names {
				resultTypes = append(resultTypes, t)
			}
		}
	}
	hasIfaceResult := false
	for _, rt := range resultTypes {
		if rt != nil && types.IsInterface(rt) {
			hasIfaceResult = true
			break
		}
	}
	if !hasIfaceResult {
		return
	}

	// Find local variables of concrete pointer type (*T) that are initialized to nil
	// and never assigned a non-nil value or have their address taken.
	nilPtrVars := map[types.Object]bool{}
	nonNilVars := map[types.Object]bool{}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			for i, name := range x.Names {
				obj := info.Defs[name]
				if obj == nil {
					continue
				}
				if _, isPtr := types.Unalias(obj.Type()).(*types.Pointer); !isPtr {
					continue
				}
				if len(x.Values) == 0 {
					nilPtrVars[obj] = true
				} else if i < len(x.Values) && isNilExpr(x.Values[i], info) {
					nilPtrVars[obj] = true
				} else {
					nonNilVars[obj] = true
				}
			}
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, lhs := range x.Lhs {
					id, ok := lhs.(*ast.Ident)
					if !ok {
						continue
					}
					obj := info.Defs[id]
					if obj == nil {
						obj = info.Uses[id]
					}
					if obj == nil {
						continue
					}
					if _, isPtr := types.Unalias(obj.Type()).(*types.Pointer); !isPtr {
						continue
					}
					if isNilExpr(x.Rhs[i], info) && !nonNilVars[obj] {
						nilPtrVars[obj] = true
					} else {
						nonNilVars[obj] = true
					}
				}
			} else {
				for _, lhs := range x.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						if obj := info.Defs[id]; obj != nil {
							nonNilVars[obj] = true
						}
						if obj := info.Uses[id]; obj != nil {
							nonNilVars[obj] = true
						}
					}
				}
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				if id, ok := x.X.(*ast.Ident); ok {
					if obj := info.Uses[id]; obj != nil {
						nonNilVars[obj] = true
					}
				}
			}
		}
		return true
	})

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != len(resultTypes) {
			return true
		}
		for i, res := range ret.Results {
			if resultTypes[i] == nil || !types.IsInterface(resultTypes[i]) {
				continue
			}
			if id, ok := res.(*ast.Ident); ok {
				obj := info.Uses[id]
				if obj != nil && nilPtrVars[obj] && !nonNilVars[obj] {
					pos := fset.Position(id.Pos())
					ff.GoIssues = append(ff.GoIssues, GoIssue{
						Kind: "nil-error-interface", Rule: "nil-error-interface", Symbol: fnName,
						Line: pos.Line, Col: pos.Column - 1,
						Message: fmt.Sprintf("Returning typed nil pointer %q (%s) as interface %s creates a non-nil interface value", id.Name, obj.Type().String(), resultTypes[i].String()),
					})
				}
			}
		}
		return true
	})
}

func isNilExpr(expr ast.Expr, info *types.Info) bool {
	switch x := expr.(type) {
	case *ast.Ident:
		return x.Name == "nil"
	case *ast.CallExpr:
		if len(x.Args) == 1 && isNilExpr(x.Args[0], info) {
			return true
		}
	case *ast.ParenExpr:
		return isNilExpr(x.X, info)
	}
	return false
}

func rootIdentObj(expr ast.Expr, info *types.Info) types.Object {
	for expr != nil {
		switch x := expr.(type) {
		case *ast.Ident:
			return info.Uses[x]
		case *ast.SelectorExpr:
			expr = x.X
		case *ast.ParenExpr:
			expr = x.X
		default:
			return nil
		}
	}
	return nil
}

func resolveCalleePkgAndName(call *ast.CallExpr, info *types.Info) (string, string) {
	if call == nil || info == nil {
		return "", ""
	}
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		if fn.Sel != nil {
			if obj := info.Uses[fn.Sel]; obj != nil && obj.Pkg() != nil {
				return obj.Pkg().Path(), obj.Name()
			}
		}
	case *ast.Ident:
		if obj := info.Uses[fn]; obj != nil && obj.Pkg() != nil {
			return obj.Pkg().Path(), obj.Name()
		}
	}
	return "", ""
}

func containsLockByValue(t types.Type) string {
	return containsLockWalk(t, map[types.Type]bool{})
}

func containsLockWalk(t types.Type, seen map[types.Type]bool) string {
	if t == nil {
		return ""
	}
	t = types.Unalias(t)
	if seen[t] {
		return ""
	}
	seen[t] = true
	if named, ok := t.(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil {
		pkg := named.Obj().Pkg().Path()
		name := named.Obj().Name()
		if pkg == "sync" && (name == "Mutex" || name == "RWMutex" || name == "WaitGroup" || name == "Once" || name == "Cond" || name == "Map") {
			return pkg + "." + name
		}
		if pkg == "sync/atomic" && (name == "Value" || name == "Bool" || name == "Int32" || name == "Int64" || name == "Uint32" || name == "Uint64" || name == "Uintptr" || name == "Pointer") {
			return pkg + "." + name
		}
	}
	if st, ok := t.Underlying().(*types.Struct); ok {
		for i := 0; i < st.NumFields(); i++ {
			ft := st.Field(i).Type()
			// A pointer field does not copy the lock by value.
			if _, isPtr := types.Unalias(ft).(*types.Pointer); isPtr {
				continue
			}
			if got := containsLockWalk(ft, seen); got != "" {
				return got
			}
		}
	}
	return ""
}

func (b *builder) checkKeyValueIssues(kv *ast.KeyValueExpr, ff *FileFacts, info *types.Info, fset *token.FileSet) {
	id, ok := kv.Key.(*ast.Ident)
	if !ok || id == nil {
		return
	}
	// Check InsecureSkipVerify: true
	if id.Name == "InsecureSkipVerify" {
		if valId, ok := kv.Value.(*ast.Ident); ok && valId.Name == "true" {
			pos := fset.Position(kv.Pos())
			ff.GoIssues = append(ff.GoIssues, GoIssue{
				Kind: "security-sink", Rule: "security-sink", Symbol: "InsecureSkipVerify",
				Line: pos.Line, Col: pos.Column - 1,
				Message: "TLS configuration sets InsecureSkipVerify: true, disabling certificate verification",
				Extra:   map[string]string{"sink": "crypto/tls.InsecureSkipVerify"},
			})
		}
	}
	if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		b.checkLiteralSecrets(lit, id.Name, ff, fset)
	}
}

func (b *builder) checkValueSpecSecrets(vs *ast.ValueSpec, ff *FileFacts, fset *token.FileSet) {
	for i, name := range vs.Names {
		if name == nil || i >= len(vs.Values) {
			continue
		}
		if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			b.checkLiteralSecrets(lit, name.Name, ff, fset)
		}
	}
}

func (b *builder) checkAssignSecrets(as *ast.AssignStmt, ff *FileFacts, fset *token.FileSet) {
	for i, lhs := range as.Lhs {
		if i >= len(as.Rhs) {
			continue
		}
		lit, ok := as.Rhs[i].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		var name string
		switch x := lhs.(type) {
		case *ast.Ident:
			name = x.Name
		case *ast.SelectorExpr:
			if x.Sel != nil {
				name = x.Sel.Name
			}
		}
		if name != "" {
			b.checkLiteralSecrets(lit, name, ff, fset)
		}
	}
}

func (b *builder) checkLiteralSecrets(lit *ast.BasicLit, varName string, ff *FileFacts, fset *token.FileSet) {
	val, err := strconv.Unquote(lit.Value)
	if err != nil || len(val) < 8 {
		return
	}
	pos := fset.Position(lit.Pos())
	// Avoid duplicate secret reports on the same line.
	for _, existing := range ff.GoIssues {
		if existing.Kind == "secret-in-code" && existing.Line == pos.Line {
			return
		}
	}
	if pemKeyRe.MatchString(val) {
		ff.GoIssues = append(ff.GoIssues, GoIssue{
			Kind: "secret-in-code", Rule: "secrets-in-code", Symbol: varName,
			Line: pos.Line, Col: pos.Column - 1,
			Message: "Hardcoded PEM private key block detected in source literal",
		})
		return
	}
	if tokenPrefixRe.MatchString(val) {
		ff.GoIssues = append(ff.GoIssues, GoIssue{
			Kind: "secret-in-code", Rule: "secrets-in-code", Symbol: varName,
			Line: pos.Line, Col: pos.Column - 1,
			Message: "Hardcoded credential token prefix detected in source literal",
		})
		return
	}
	if varName != "" && isSecretIdentifier(varName) && !isBenignSecretValue(val) {
		ff.GoIssues = append(ff.GoIssues, GoIssue{
			Kind: "secret-in-code", Rule: "secrets-in-code", Symbol: varName,
			Line: pos.Line, Col: pos.Column - 1,
			Message: fmt.Sprintf("Identifier %q appears to hold a hardcoded secret or credential literal", varName),
		})
	}
}

func isSecretIdentifier(name string) bool {
	lower := strings.ToLower(name)
	// Exclude non-secret metadata names like tokenCount, secretName, passwordField, tokenKind.
	for _, suffix := range []string{"name", "path", "file", "header", "keyname", "env", "type", "kind", "count", "len", "err", "error", "msg", "message", "prefix", "suffix", "pattern", "re", "regex", "url", "uri"} {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	for _, kw := range []string{"password", "passwd", "apikey", "api_key", "privatekey", "private_key", "accesstoken", "access_token", "authtoken", "auth_token", "clientsecret", "client_secret", "secretkey", "secret_key", "bearertoken", "bearer_token"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return lower == "secret" || lower == "token"
}

func isBenignSecretValue(val string) bool {
	trim := strings.TrimSpace(val)
	if len(trim) < 8 || strings.Contains(trim, " ") {
		return true
	}
	lower := strings.ToLower(trim)
	for _, benign := range []string{"changeme", "password", "secret", "example", "test", "dummy", "redacted", "placeholder", "none", "null", "undefined", "localhost", "http://", "https://", "file://", "/"} {
		if strings.Contains(lower, benign) {
			return true
		}
	}
	// All uppercase/underscore looks like an env var name, not a secret value.
	allUpper := true
	for _, r := range trim {
		if !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			allUpper = false
			break
		}
	}
	return allUpper
}

func (b *builder) checkCallIssues(call *ast.CallExpr, ff *FileFacts, info *types.Info, fset *token.FileSet) {
	if call == nil {
		return
	}
	calleePkg, calleeName := resolveCalleePkgAndName(call, info)
	callName := exprFuncName(call.Fun)
	pos := fset.Position(call.Pos())

	// 1. Security sinks: os/exec and database/sql
	if info != nil {
		if calleePkg == "os/exec" && (calleeName == "Command" || calleeName == "CommandContext") {
			cmdIdx := 0
			if calleeName == "CommandContext" {
				cmdIdx = 1
			}
			if cmdIdx < len(call.Args) {
				tv := info.Types[call.Args[cmdIdx]]
				dynamicCmd := tv.Value == nil || tv.Value.Kind() != constant.String
				if !dynamicCmd && cmdIdx+2 < len(call.Args) {
					flagTV := info.Types[call.Args[cmdIdx+1]]
					argTV := info.Types[call.Args[cmdIdx+2]]
					if flagTV.Value != nil && flagTV.Value.Kind() == constant.String && constant.StringVal(flagTV.Value) == "-c" &&
						(argTV.Value == nil || argTV.Value.Kind() != constant.String) {
						dynamicCmd = true
					}
				}
				if dynamicCmd {
					ff.GoIssues = append(ff.GoIssues, GoIssue{
						Kind: "security-sink", Rule: "security-sink", Symbol: calleePkg + "." + calleeName,
						Line: pos.Line, Col: pos.Column - 1,
						Message: fmt.Sprintf("Call to %s.%s uses a non-constant command expression", calleePkg, calleeName),
						Extra:   map[string]string{"sink": calleePkg + "." + calleeName},
					})
				}
			}
		}
		if calleePkg == "database/sql" &&
			(calleeName == "Query" || calleeName == "QueryContext" ||
				calleeName == "QueryRow" || calleeName == "QueryRowContext" ||
				calleeName == "Exec" || calleeName == "ExecContext") {
			qIdx := 0
			if strings.HasSuffix(calleeName, "Context") {
				qIdx = 1
			}
			if qIdx < len(call.Args) {
				tv := info.Types[call.Args[qIdx]]
				if tv.Value == nil && isDynamicStringExpr(call.Args[qIdx]) {
					ff.GoIssues = append(ff.GoIssues, GoIssue{
						Kind: "security-sink", Rule: "security-sink", Symbol: "sql." + calleeName,
						Line: pos.Line, Col: pos.Column - 1,
						Message: fmt.Sprintf("SQL query passed to %s is dynamically constructed via string concatenation or formatting", calleeName),
						Extra:   map[string]string{"sink": "database/sql." + calleeName},
					})
				}
			}
		}
	}

	// 2. Feature flag calls and os.Getenv / os.LookupEnv
	var litArgs []string
	hasLit := false
	for _, arg := range call.Args {
		if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				litArgs = append(litArgs, s)
				hasLit = true
				continue
			}
		}
		litArgs = append(litArgs, "")
	}
	if !hasLit {
		return
	}
	isEnv := (calleePkg == "os" || strings.HasPrefix(callName, "os.")) &&
		(calleeName == "Getenv" || calleeName == "LookupEnv" || callName == "os.Getenv" || callName == "os.LookupEnv")
	if isEnv || callName != "" {
		ff.FlagCalls = append(ff.FlagCalls, FlagCall{
			FuncName: callName,
			Args:     litArgs,
			FlagName: firstNonEmpty(litArgs),
			Line:     pos.Line,
			Col:      pos.Column - 1,
			IsEnv:    isEnv,
		})
	}
}

func isDynamicStringExpr(expr ast.Expr) bool {
	switch x := expr.(type) {
	case *ast.BinaryExpr:
		return x.Op == token.ADD
	case *ast.CallExpr:
		name := exprFuncName(x.Fun)
		return strings.HasSuffix(name, "Sprintf") || strings.HasSuffix(name, "Sprint")
	}
	return false
}

func exprFuncName(expr ast.Expr) string {
	switch x := expr.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		if x.Sel == nil {
			return ""
		}
		prefix := exprFuncName(x.X)
		if prefix != "" {
			return prefix + "." + x.Sel.Name
		}
		return x.Sel.Name
	}
	return ""
}

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
