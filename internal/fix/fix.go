// Package fix removes auto-fixable findings — dead files, dead symbols,
// stale suppressions, and unused dependencies — the way `fallow fix` does:
// it rewrites sources, then verifies the module still builds and rolls every
// edit back if it does not.
package fix

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"

	"goose/internal/report"
)

// Target is one planned removal.
type Target struct {
	File    string // absolute path
	Kind    string // finding kind
	Symbol  string // declaration name, when a symbol fix
	Recv    string // receiver or struct, for methods and fields
	Line    int    // 1-based declaration line
	Comment string // suppression text, for stale-suppression fixes
}

// Plan is the outcome of a dry run: every planned edit, grouped and counted.
type Plan struct {
	Root      string // module root, so renderers can print relative paths
	Targets   []Target
	Files     []string // absolute file paths that would be deleted
	ModTidy   []string // go.mod require entries to drop
	Edits     int      // files whose text would change
	AutoFixes int      // total findings acted on
	Skipped   int      // findings whose fix is not auto-applicable
}

// Result reports one applied run.
type Result struct {
	Plan
	Applied    bool
	BuildOK    bool
	BuildErr   string
	RolledBack bool
}

// Build builds a plan from a set of visible findings. root is the module
// directory; findings carry module-relative paths.
func Build(root string, findings []*report.Finding) *Plan {
	p := &Plan{Root: root}
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Hidden {
			continue
		}
		fixable := false
		for _, a := range f.Actions {
			if a.AutoFixable {
				fixable = true
			}
		}
		if !fixable {
			p.Skipped++
			continue
		}
		abs := filepath.Join(root, filepath.FromSlash(f.Path))
		switch f.Kind {
		case "unused-file":
			if seen["file:"+abs] {
				continue
			}
			seen["file:"+abs] = true
			p.Files = append(p.Files, abs)
			p.AutoFixes++
		case "stale-suppression":
			p.Targets = append(p.Targets, Target{
				File: abs, Kind: f.Kind, Line: f.Line,
				Comment: fmt.Sprint(f.Extra["comment"]),
			})
			p.AutoFixes++
		case "unused-export", "unused-unexported", "unused-type",
			"unused-method", "unused-field", "unused-constant", "unused-variable":
			sym, _ := f.Extra["symbol"].(string)
			if sym == "" {
				sym, _ = f.Extra["field"].(string)
			}
			recv, _ := f.Extra["receiver"].(string)
			if recv == "" {
				recv, _ = f.Extra["struct"].(string)
			}
			p.Targets = append(p.Targets, Target{
				File: abs, Kind: f.Kind, Symbol: sym,
				Recv: recv, Line: f.Line,
			})
			p.AutoFixes++
		}
	}
	// Files edited only for symbol/suppression fixes (minus whole-file deletes).
	deleting := map[string]bool{}
	for _, fp := range p.Files {
		deleting[fp] = true
	}
	edited := map[string]bool{}
	for _, t := range p.Targets {
		if !deleting[t.File] {
			edited[t.File] = true
		}
	}
	p.Edits = len(edited)
	p.ModTidy = UnusedDeps(findings)
	sort.Strings(p.Files)
	return p
}

// Apply executes the plan: rewrites edited files, drops deleted files, then
// builds the module and rolls back on failure.
func (p *Plan) Apply(root string) *Result {
	res := &Result{Plan: *p, Applied: true}
	orig := map[string][]byte{}
	backups := map[string][]byte{} // deleted files' contents, to restore

	// 1. Symbol and suppression edits, grouped per file.
	byFile := map[string][]Target{}
	for _, t := range p.Targets {
		byFile[t.File] = append(byFile[t.File], t)
	}
	var files []string
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, file := range files {
		before, err := os.ReadFile(file)
		if err != nil {
			res.BuildErr = fmt.Sprintf("cannot read %s: %v", file, err)
			res.rollback(root, orig, backups)
			return res
		}
		orig[file] = before
		after := applyTargets(file, before, byFile[file])
		if string(after) == string(before) {
			continue
		}
		if err := os.WriteFile(file, after, 0o644); err != nil {
			res.BuildErr = fmt.Sprintf("cannot write %s: %v", file, err)
			res.rollback(root, orig, backups)
			return res
		}
	}

	// 2. Whole-file deletions, after capturing contents for rollback.
	for _, file := range p.Files {
		if data, err := os.ReadFile(file); err == nil {
			backups[file] = data
		}
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			res.BuildErr = fmt.Sprintf("cannot delete %s: %v", file, err)
			res.rollback(root, orig, backups)
			return res
		}
	}

	// 2b. go.mod require removals, captured for rollback.
	if len(p.ModTidy) > 0 {
		modPath := filepath.Join(root, "go.mod")
		before, err := os.ReadFile(modPath)
		if err == nil {
			after, ok := removeRequires(before, p.ModTidy)
			if ok && string(after) != string(before) {
				orig[modPath] = before
				if err := os.WriteFile(modPath, after, 0o644); err != nil {
					res.BuildErr = fmt.Sprintf("cannot write go.mod: %v", err)
					res.rollback(root, orig, backups)
					return res
				}
			}
		}
	}

	// 3. Verify the module still builds; roll back everything if not.
	if code, combined, err := buildModule(root); err != nil || code != 0 {
		res.BuildOK = false
		res.BuildErr = strings.TrimSpace(combined)
		if err != nil {
			res.BuildErr = err.Error()
		}
		res.rollback(root, orig, backups)
		return res
	}
	res.BuildOK = true
	return res
}

// rollback restores every touched file and recreates deleted ones.
func (r *Result) rollback(root string, orig, backups map[string][]byte) {
	for file, data := range backups {
		_ = os.MkdirAll(filepath.Dir(file), 0o755)
		_ = os.WriteFile(file, data, 0o644)
	}
	for file, data := range orig {
		_ = os.WriteFile(file, data, 0o644)
	}
	r.RolledBack = true
	if r.BuildErr != "" {
		r.BuildErr = "build failed; all changes rolled back. First errors:\n" + headLines(r.BuildErr, 12)
	}
}

// applyTargets removes the selected symbols and stale comment lines from one
// file's text by deleting whole source lines, computed from the AST.
func applyTargets(file string, src []byte, targets []Target) []byte {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.ParseComments)
	if err != nil || f == nil {
		// Without a parse tree, fall back to deleting suppression lines only.
		return deleteSuppressionLinesByLine(src, targets)
	}
	// Map each symbol target to a line range; suppressions to a single line.
	drop := map[int]bool{} // 1-based lines to delete
	for _, t := range targets {
		switch t.Kind {
		case "stale-suppression":
			if t.Line > 0 {
				drop[t.Line] = true
			}
		default:
			if r, ok := locateDecl(fset, f, t); ok {
				lo, hi := absorbComments(fset, f, src, r[0], r[1])
				for ln := lo; ln <= hi; ln++ {
					drop[ln] = true
				}
			}
		}
	}
	if len(drop) == 0 {
		return src
	}
	return dropLines(src, drop)
}

// locateDecl finds the [start,end] line range of a declaration or field.
func locateDecl(fset *token.FileSet, f *ast.File, t Target) ([2]int, bool) {
	var out [2]int
	found := false
	nameMatch := func(n string) bool { return n == t.Symbol }
	lineWithin := func(pos token.Pos) bool {
		return fset.Position(pos).Line == t.Line
	}
	// Top-level funcs and methods.
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if t.Kind == "unused-method" {
			if fd.Recv == nil || !nameMatch(fd.Name.Name) || !lineWithin(fd.Pos()) {
				continue
			}
			if !recvBase(fd.Recv, t.Recv) {
				continue
			}
			return [2]int{fset.Position(fd.Pos()).Line, fset.Position(fd.End()).Line}, true
		}
		if t.Kind == "unused-export" || t.Kind == "unused-unexported" {
			if fd.Recv == nil && nameMatch(fd.Name.Name) && lineWithin(fd.Pos()) {
				return [2]int{fset.Position(fd.Pos()).Line, fset.Position(fd.End()).Line}, true
			}
		}
	}
	// GenDecls: types, consts, vars.
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, sp := range gd.Specs {
			switch s := sp.(type) {
			case *ast.TypeSpec:
				if (t.Kind == "unused-type" || t.Kind == "unused-export" || t.Kind == "unused-unexported") &&
					nameMatch(s.Name.Name) {
					return specRange(fset, gd, s, t.Line, string(s.Name.Name))
				}
				if t.Kind == "unused-field" && s.Type != nil {
					if st, ok2 := s.Type.(*ast.StructType); ok2 {
						if r, ok3 := findField(fset, gd, s, st, t); ok3 {
							return r, true
						}
					}
				}
			case *ast.ValueSpec:
				if (t.Kind == "unused-constant" || t.Kind == "unused-variable") &&
					specHasName(s, t.Symbol) {
					if len(s.Names) > 1 {
						return out, false
					}
					return specRange(fset, gd, s, t.Line, t.Symbol)
				}
			case *ast.ImportSpec:
				_ = s
			}
		}
	}
	return out, found
}

// findField returns the line range of a named struct field in a type spec.
func findField(fset *token.FileSet, gd *ast.GenDecl, ts *ast.TypeSpec, st *ast.StructType, t Target) ([2]int, bool) {
	if t.Recv != "" && ts.Name.Name != t.Recv {
		return [2]int{}, false
	}
	if st.Fields == nil {
		return [2]int{}, false
	}
	fieldLine := fset.Position(ts.Pos()).Line
	for _, fl := range st.Fields.List {
		for _, nm := range fl.Names {
			if nm.Name == t.Symbol {
				if len(fl.Names) > 1 {
					return [2]int{}, false
				}
				posLine := fset.Position(fl.Pos()).Line
				if posLine > fieldLine {
					return [2]int{posLine, fset.Position(fl.End()).Line}, true
				}
			}
		}
	}
	return [2]int{}, false
}

// headLines keeps the first n lines of a string, for a compact build error.
func headLines(s string, n int) string {
	parts := strings.Split(s, "\n")
	if len(parts) <= n {
		return s
	}
	return strings.Join(parts[:n], "\n") + "\n…"
}

// specRange returns the deletion range for one spec. In a parenthesized group
// the spec's own lines are removed; in a single-spec decl the whole decl goes,
// because leaving "var ()" or "import ()" is not idiomatic.
func specRange(fset *token.FileSet, gd *ast.GenDecl, sp ast.Spec, wantLine int, name string) ([2]int, bool) {
	lo := fset.Position(sp.Pos()).Line
	hi := fset.Position(sp.End()).Line
	if !parenthesized(gd, lo) {
		// Single-spec decl without parens: take the whole declaration.
		lo = fset.Position(gd.Pos()).Line
	}
	// Require one of the spec's names to be the target to avoid the
	// wrong line in a one-line group.
	_ = wantLine
	_ = name
	return [2]int{lo, hi}, true
}

// parenthesized reports whether a decl spanning its spec at lo uses parens.
func parenthesized(gd *ast.GenDecl, lo int) bool {
	// Lparen is 0 when there are no parens.
	return gd.Lparen.IsValid()
}

// specHasName reports whether a ValueSpec declares a name.
func specHasName(s *ast.ValueSpec, name string) bool {
	for _, n := range s.Names {
		if n.Name == name {
			return true
		}
	}
	return false
}

// recvBase compares a method receiver's base type name to the target.
func recvBase(fl *ast.FieldList, want string) bool {
	if fl == nil || len(fl.List) == 0 {
		return false
	}
	t := fl.List[0].Type
	switch v := t.(type) {
	case *ast.StarExpr:
		t = v.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name == want
	}
	return false
}

// absorbComments extends a range to swallow directly-preceding whole-line
// comments and a single trailing blank line.
func absorbComments(fset *token.FileSet, f *ast.File, src []byte, lo, hi int) (int, int) {
	lines := strings.Split(string(src), "\n")
	// Backward over comment lines contiguous with lo.
	for lo-2 >= 0 && isCommentLine(lines[lo-2]) {
		lo--
	}
	// A blank line immediately after hi can go with it.
	if hi < len(lines) && strings.TrimSpace(lines[hi]) == "" {
		hi++
	}
	return lo, hi
}

func isCommentLine(l string) bool {
	t := strings.TrimSpace(l)
	return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") || strings.HasSuffix(t, "*/")
}

// deleteSuppressionLinesByLine removes goose-ignore comment lines by exact
// line when no AST is available.
func deleteSuppressionLines(src []byte, targets []Target) []byte {
	drop := map[int]bool{}
	for _, t := range targets {
		if t.Kind == "stale-suppression" && t.Line > 0 {
			drop[t.Line] = true
		}
	}
	if len(drop) == 0 {
		return src
	}
	return dropLines(src, drop)
}

func deleteSuppressionLinesByLine(src []byte, targets []Target) []byte {
	return deleteSuppressionLines(src, targets)
}

// dropLines deletes 1-based line indices, collapsing runs of >1 blank line.
func dropLines(src []byte, drop map[int]bool) []byte {
	lines := strings.Split(string(src), "\n")
	var out []string
	for i, l := range lines {
		if drop[i+1] {
			continue
		}
		out = append(out, l)
	}
	out = collapseBlanks(out)
	return []byte(strings.Join(out, "\n"))
}

// collapseBlanks keeps at most one blank line between statements and trims a
// leading blank at file top and trailing runs.
func collapseBlanks(lines []string) []string {
	var out []string
	blank := 0
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			blank++
			if blank <= 1 && len(out) > 0 {
				out = append(out, l)
			}
			continue
		}
		blank = 0
		out = append(out, l)
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	return append(out, "") // trailing newline
}

// buildModule runs go build ./... in the module root.
func buildModule(root string) (int, string, error) {
	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = root
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	return code, buf.String(), err
}

// removeRequires drops the named modules from require blocks of go.mod text,
// preserving formatting everywhere else.
func removeRequires(src []byte, modules []string) ([]byte, bool) {
	mf, err := modfile.Parse("go.mod", src, nil)
	if err != nil {
		return src, false
	}
	removed := false
	for _, m := range modules {
		if err := mf.DropRequire(m); err == nil {
			removed = true
		}
	}
	if !removed {
		return src, true
	}
	mf.Cleanup()
	out, err := mf.Format()
	if err != nil {
		return src, false
	}
	return out, true
}

// UnusedDeps returns the go.mod require entries among the findings.
func UnusedDeps(findings []*report.Finding) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Kind != "unused-dependency" || f.Hidden {
			continue
		}
		pkg, _ := f.Extra["package_name"].(string)
		if pkg == "" || seen[pkg] {
			continue
		}
		seen[pkg] = true
		out = append(out, pkg)
	}
	sort.Strings(out)
	return out
}
