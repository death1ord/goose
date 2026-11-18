// Package facts builds the entity-level view of a Go project: every declared
// symbol with its type identity, every use site, and the suppression markers.
// It is the goose equivalent of fallow's repository graph, and every analysis
// (dead code, health, architecture, audit) reads its output.
package facts

import (
	"go/ast"
	"go/token"
)

// Kind classifies a declared entity.
type Kind string

// Entity kinds.
const (
	KindFunc      Kind = "func"
	KindMethod    Kind = "method"
	KindType      Kind = "type"
	KindInterface Kind = "interface"
	KindField     Kind = "field"
	KindConst     Kind = "const"
	KindVar       Kind = "var"
)

// Key is the stable identity of an entity: kind, package path, container, and
// name. Keys never carry line numbers, so a finding survives edits above it.
type Key string

// MakeKey builds an entity key from its parts.
func MakeKey(kind Kind, pkgPath, container, name string) Key {
	return Key(string(kind) + "\x1f" + pkgPath + "\x1f" + container + "\x1f" + name)
}

// split returns the four parts of a key.
func (k Key) split() [4]string {
	var out [4]string
	parts := splitKeyParts(string(k))
	for i := range parts {
		if i >= 4 {
			break
		}
		out[i] = parts[i]
	}
	return out
}

func splitKeyParts(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\x1f' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}

// KindOf returns the entity kind of a key.
func (k Key) KindOf() Kind { return Kind(k.split()[0]) }

// Pkg returns the package path of a key.
func (k Key) Pkg() string { return k.split()[1] }

// Container returns the receiver or struct name of a key.
func (k Key) Container() string { return k.split()[2] }

// Name returns the declared name of a key.
func (k Key) Name() string { return k.split()[3] }

// Entity is one declared symbol.
type Entity struct {
	Key      Key
	Kind     Kind
	PkgPath  string
	PkgName  string // the package clause name, e.g. "store"
	Recv     string // receiver type for methods, struct name for fields
	Name     string
	File     string // absolute file path
	Line     int
	Col      int // 0-based
	Exported bool
	// DeclNode is the *ast.FuncDecl, *ast.TypeSpec, or *ast.Field fragment.
	DeclNode   ast.Node
	Doc        string
	Deprecated bool
	// TestFile marks a _test.go file.
	TestFile bool
	// InterfaceMethod marks a method signature inside an interface.
	InterfaceMethod bool
	// Func carries function-level detail for funcs and methods.
	Func *FuncInfo
	// Field carries struct-field detail for fields.
	Field *FieldInfo
	// Local marks a function-body declaration, never reported on its own.
	Local bool
	// DocTags holds documentation tags such as @deprecated.
	DocTags map[string]bool
	// PrivateTypeCandidates holds unexported type identifier names referenced
	// in an exported symbol's signature/type, precomputed for cacheability.
	PrivateTypeCandidates []string
	// StructSize and OptimalStructSize hold the byte sizes of a struct under
	// 64-bit alignment in declared order vs optimal alignment order.
	StructSize        int64
	OptimalStructSize int64
}

// ParamFact records one unused parameter or method receiver.
type ParamFact struct {
	Name string
	Line int
	Col  int
}

// FuncInfo carries the analysis data of one function or method.
type FuncInfo struct {
	Node           *ast.FuncDecl
	Body           *ast.BlockStmt
	Loc            int // lines of the whole declaration
	BodyLoc        int // lines of the body, 0 without a body
	Params         int
	Results        int
	Cyclomatic     int
	Cognitive      int
	Statements     int
	IsTest         bool
	IsInit         bool
	IsMain         bool
	RecvTypeName   string
	UnusedParams   []ParamFact
	UnusedReceiver *ParamFact
}

// FieldInfo records one struct field.
type FieldInfo struct {
	Struct   string
	Tag      string
	Embedded bool
	// TagNames holds the names declared by json/yaml/db tags.
	TagNames []string
}

// UseSite records one read of an entity.
type UseSite struct {
	Key      Key
	File     string // absolute path of the using file
	PkgPath  string // package of the using file
	Line     int
	Off      int    // byte offset of the reference
	Kind     string // ident | field | method | type | iface | tag
	FromTest bool
	// SelfPackage marks a use from the declaring package, which is the only
	// kind of use that counts for unexported symbols.
	SelfPackage bool
	// WriteOnly marks a reference that only writes to a variable or initializes
	// a struct field in a composite literal or assignment LHS without reading it.
	WriteOnly bool

	// ContainingKey is the innermost declared entity whose span holds the use.
	// Build fills it so local-symbol analysis can attribute uses to functions.
	ContainingKey Key
}

// Containing returns the innermost declared entity whose span holds the use.
func (u UseSite) Containing() Key { return u.ContainingKey }

// ImportInfo records one import declaration.
type ImportInfo struct {
	Path  string // the import path
	Name  string // explicit alias, empty otherwise
	Dot   bool
	Blank bool
	File  string
	Line  int
	Col   int
}

// Suppression is one goose-ignore marker.
type Suppression struct {
	Kind      string // next-line | file | start | end
	Types     []string
	Reason    string
	HasReason bool
	Line      int
	Col       int
	Raw       string
	// Used is set by the analysis that consumes it; a false one at the end of
	// a run is a stale-suppressions finding.
	Used bool
}

// GoIssue records a Go-specific correctness, resource-leak, lock-copy,
// security-sink, or secret finding collected during AST + go/types analysis.
type GoIssue struct {
	Kind    string
	Rule    string
	Message string
	Symbol  string
	Line    int
	Col     int
	Extra   map[string]string
}

// FlagCall records a candidate feature-flag SDK call or environment lookup.
type FlagCall struct {
	FuncName string
	Args     []string // string literal args by index ("" if non-literal)
	FlagName string
	Provider string
	Line     int
	Col      int
	Stale    bool
	IsEnv    bool
}

// FileFacts holds per-file data.
type FileFacts struct {
	Path         string // absolute
	Rel          string // module-relative, forward slashes
	PkgPath      string
	PkgName      string
	InTest       bool
	Loc          int
	Entities     []Key
	Imports      []ImportInfo
	Suppressions []*Suppression
	// BuildTags holds //go:build constraint words of the file, if any.
	BuildTags []string
	// DirectiveTargets holds symbol names referenced by //export or //go:linkname.
	DirectiveTargets []string
	// GoIssues holds Go-specific static analysis findings for the file.
	GoIssues []GoIssue
	// FlagCalls holds candidate feature-flag SDK and env lookups in the file.
	FlagCalls []FlagCall
	// HasCgo marks a file with an import "C".
	HasCgo bool
	// Src is the raw file text, kept for suppression and health passes.
	Src string
}

// Span is one line range of an entity declaration in a file.
type Span struct {
	File      string
	StartLine int
	EndLine   int
}

// Project is the full entity view of one load.
type Project struct {
	Module ModuleInfo
	// Files indexes file facts by absolute path.
	Files map[string]*FileFacts
	// Entities indexes every declared symbol.
	Entities map[Key]*Entity
	// Uses lists every use site per entity key.
	Uses map[Key][]UseSite
	// EntitySpans lists the declaration ranges of each entity. Uses inside a
	// declaring entity do not keep it alive (a recursive function or a type
	// named only by its own methods stays reportable).
	EntitySpans map[Key][]Span
	// EntryPkgs lists packages that root reachability (main packages).
	EntryPkgs map[string]bool
	// InterfaceMethods maps an interface key to its method keys.
	InterfaceMethods map[Key][]Key
	// InterfaceSatisfied marks interfaces kept alive by a use or an
	// implementor, whose method set must not be reported.
	InterfaceSatisfied map[Key]bool
	// ReflectivePkgs marks packages that pass types to reflect-based codecs.
	ReflectivePkgs map[string]bool
	// SkippedFiles holds module-relative paths over the size guard: their
	// uses and imports count, their declarations are never analyzed and they
	// are dropped from NonTestFiles enumeration for dupes and health.
	SkippedFiles map[string]bool
	// Fset carries positions for consumers that need them.
	Fset *token.FileSet
}

// ModuleInfo restates loader.Module so facts has no import cycle concerns.
type ModuleInfo struct {
	Path       string
	Dir        string
	Requires   []string
	Vendor     bool
	WorkFile   string
	Workspaces []string
}

// Entity returns the named entity or nil.
func (p *Project) Entity(k Key) *Entity { return p.Entities[k] }

// File returns the facts of one file or nil.
func (p *Project) File(path string) *FileFacts { return p.Files[path] }

// NonTestFiles returns file facts excluding _test.go files.
func (p *Project) NonTestFiles() []*FileFacts {
	var out []*FileFacts
	for _, path := range p.fileOrder() {
		f := p.Files[path]
		if !f.InTest && !p.SkippedFiles[f.Rel] {
			out = append(out, f)
		}
	}
	return out
}

// fileOrder returns file paths sorted for determinism.
func (p *Project) fileOrder() []string {
	out := make([]string, 0, len(p.Files))
	for path := range p.Files {
		out = append(out, path)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// IsExportedAPI reports whether key names a symbol other packages can reach.
func (p *Project) IsExportedAPI(k Key) bool {
	e := p.Entities[k]
	return e != nil && e.Exported && !e.TestFile
}

// UsesOf returns the use sites of an entity.
func (p *Project) UsesOf(k Key) []UseSite { return p.Uses[k] }
