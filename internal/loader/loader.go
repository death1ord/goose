// Package loader wraps golang.org/x/tools/go/packages so that every goose
// analysis runs on one type-checked snapshot of the project: full syntax,
// type information, and dependencies.
package loader

import (
	"context"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"golang.org/x/mod/modfile"
	"golang.org/x/tools/go/packages"
)

// Module describes the Go module the project loads from.
type Module struct {
	Path      string // module path from go.mod, empty in GOPATH mode
	Dir       string // directory holding go.mod
	GoVersion string
	// Requires lists every required module path, used by dependency analysis.
	Requires []string
	// Vendor is true when a vendor/ directory shadows the module cache.
	Vendor bool
	// WorkFile is the resolved go.work file path, if workspace mode is active.
	WorkFile string
	// Workspaces lists go.work use directories when present.
	Workspaces []string
}

// Loaded is one analysis snapshot.
type Loaded struct {
	Pkgs   []*packages.Package
	Fset   *token.FileSet
	Module Module
	// Tests reports whether _test.go files were included in this load.
	Tests bool
	// TypeErrors names type-check failures. goose analyzes syntax even when a
	// build is broken, so callers decide how strict to be.
	TypeErrors []string
	// Files indexes parsed project files by absolute path.
	Files map[string]*FileEntry
	// SkippedFiles lists files dropped by the --max-file-size guard. Their
	// uses still count (nothing is falsely dead) but their declarations are
	// not analyzed; callers surface them as workspace diagnostics.
	SkippedFiles []SkippedFile
}

// SkippedFile is one size-guard exclusion.
type SkippedFile struct {
	Path  string // absolute
	Bytes int64
}

// FileEntry is one parsed project file with its type information.
type FileEntry struct {
	Path   string // absolute path
	Pkg    *packages.Package
	Syntax *ast.File
	Types  *types.Package
	Src    []byte // optional pre-read file bytes
	// InTest marks a _test.go file.
	InTest bool
	// Skipped marks a file over the size cap: analyzed for uses and imports
	// only, never for declarations.
	Skipped bool
}

// Options control a load.
type Options struct {
	Dir       string
	Patterns  []string
	Tests     bool
	BuildTags []string
	// MaxFileSizeMB drops files larger than this from analysis (0 = no cap).
	MaxFileSizeMB float64
}

// FindModule walks up from dir looking for go.mod (and/or go.work).
func FindModule(dir string) (Module, error) {
	var m Module
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return m, err
	}
	cur := absDir
	for {
		candidate := filepath.Join(cur, "go.mod")
		data, err := os.ReadFile(candidate)
		if err != nil {
			parent := filepath.Dir(cur)
			if parent == cur {
				wf, ws := findWork(absDir)
				if wf == "" {
					return Module{}, nil
				}
				m.WorkFile = wf
				m.Workspaces = ws
				wfDir := filepath.Dir(wf)
				if absDir == wfDir || strings.HasPrefix(absDir, wfDir+string(filepath.Separator)) {
					m.Dir = wfDir
				} else {
					m.Dir = absDir
				}
				if _, statErr := os.Stat(filepath.Join(m.Dir, "vendor")); statErr == nil {
					m.Vendor = true
				}
				return m, nil
			}
			cur = parent
			continue
		}
		f, parseErr := modfile.Parse(candidate, data, nil)
		if parseErr != nil {
			return m, fmt.Errorf("invalid go.mod at %s: %w", candidate, parseErr)
		}
		m.Path = f.Module.Mod.Path
		m.Dir = cur
		if f.Go != nil {
			m.GoVersion = f.Go.Version
		}
		seen := map[string]bool{}
		for _, req := range f.Require {
			if req.Indirect {
				continue
			}
			if !seen[req.Mod.Path] {
				m.Requires = append(m.Requires, req.Mod.Path)
			}
			seen[req.Mod.Path] = true
		}
		for _, rep := range f.Replace {
			path := rep.New.Path
			if path != "" && !strings.HasPrefix(path, ".") && !seen[path] {
				m.Requires = append(m.Requires, path)
				seen[path] = true
			}
		}
		if _, statErr := os.Stat(filepath.Join(cur, "vendor")); statErr == nil {
			m.Vendor = true
		}
		m.WorkFile, m.Workspaces = findWork(absDir)
		return m, nil
	}
}

// findWork resolves the active go.work file and its use directories, honoring
// GOWORK=off or a custom GOWORK file path.
func findWork(dir string) (string, []string) {
	if gowork := os.Getenv("GOWORK"); gowork != "" {
		if gowork == "off" {
			return "", nil
		}
		if !filepath.IsAbs(gowork) {
			if abs, err := filepath.Abs(gowork); err == nil {
				gowork = abs
			}
		}
		return parseWorkFile(gowork)
	}
	cur := dir
	for {
		candidate := filepath.Join(cur, "go.work")
		if wf, ws := parseWorkFile(candidate); wf != "" {
			return wf, ws
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", nil
		}
		cur = parent
	}
}

func parseWorkFile(candidate string) (string, []string) {
	data, err := os.ReadFile(candidate)
	if err != nil {
		return "", nil
	}
	f, parseErr := modfile.ParseWork(candidate, data, nil)
	if parseErr != nil {
		return "", nil
	}
	baseDir := filepath.Dir(candidate)
	var out []string
	for _, use := range f.Use {
		p := use.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(baseDir, p)
		}
		out = append(out, filepath.Clean(p))
	}
	return candidate, out
}

// Load runs go list plus parse and type-check for the whole project.
func Load(ctx context.Context, opts Options) (*Loaded, error) {
	if opts.Dir == "" {
		opts.Dir = "."
	}
	if len(opts.Patterns) == 0 {
		opts.Patterns = []string{"./..."}
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo,
		Dir:     opts.Dir,
		Tests:   opts.Tests,
		Context: ctx,
	}
	if len(opts.BuildTags) > 0 {
		cfg.BuildFlags = []string{"-tags=" + strings.Join(opts.BuildTags, ",")}
	}
	pkgs, err := packages.Load(cfg, opts.Patterns...)
	if err != nil {
		return nil, fmt.Errorf("go/packages: %w", err)
	}
	out := &Loaded{Pkgs: pkgs, Files: map[string]*FileEntry{}, Tests: opts.Tests}
	skipSeen := map[string]bool{}
	if len(pkgs) > 0 && pkgs[0].Fset != nil {
		out.Fset = pkgs[0].Fset
	}
	if out.Fset == nil {
		out.Fset = token.NewFileSet()
	}
	for _, p := range pkgs {
		// The `.test` binary package contributes a generated test-main file
		// that lives in the build cache; goose must never analyze it.
		if strings.HasSuffix(p.PkgPath, ".test") || strings.HasSuffix(p.ID, ".test") {
			continue
		}
		for _, e := range p.Errors {
			out.TypeErrors = append(out.TypeErrors, e.Error())
		}
		for i, file := range p.Syntax {
			if file == nil {
				continue
			}
			path := ""
			if i < len(p.CompiledGoFiles) {
				path = p.CompiledGoFiles[i]
			} else if i < len(p.GoFiles) {
				path = p.GoFiles[i]
			}
			if path == "" {
				continue
			}
			if _, ok := out.Files[path]; !ok {
				entry := &FileEntry{
					Path:   path,
					Pkg:    p,
					Syntax: file,
					Types:  p.Types,
					InTest: strings.HasSuffix(path, "_test.go"),
				}
				if opts.MaxFileSizeMB > 0 {
					if st, err := os.Stat(path); err == nil && st.Size() > int64(opts.MaxFileSizeMB*1024*1024) {
						entry.Skipped = true
						if !skipSeen[path] {
							skipSeen[path] = true
							out.SkippedFiles = append(out.SkippedFiles, SkippedFile{Path: path, Bytes: st.Size()})
						}
					}
				}
				out.Files[path] = entry
			} else if opts.MaxFileSizeMB > 0 && !out.Files[path].Skipped {
				// keep first; nothing to do
			}
		}
	}
	mod, err := FindModule(opts.Dir)
	if err != nil {
		return nil, err
	}
	out.Module = mod
	if len(out.Files) == 0 {
		if len(out.TypeErrors) > 0 {
			return out, fmt.Errorf("no Go files could be parsed: %s", out.TypeErrors[0])
		}
		return out, fmt.Errorf("no Go packages found under %s", opts.Dir)
	}
	return out, nil
}

// LoadSyntax discovers and parses project .go files directly via go/build and
// go/parser without spawning a `go list` or type-checking subprocess. Use it
// for syntax- and import-only commands (dupes, list, architecture).
func LoadSyntax(_ context.Context, opts Options) (*Loaded, error) {
	if opts.Dir == "" {
		opts.Dir = "."
	}
	absDir, err := filepath.Abs(opts.Dir)
	if err != nil {
		return nil, err
	}
	mod, err := FindModule(absDir)
	if err != nil {
		return nil, err
	}
	bctx := build.Default
	if v := os.Getenv("GOOS"); v != "" {
		bctx.GOOS = v
	}
	if v := os.Getenv("GOARCH"); v != "" {
		bctx.GOARCH = v
	}
	if v := os.Getenv("CGO_ENABLED"); v != "" {
		bctx.CgoEnabled = v == "1"
	}
	if goFlagsTags := parseGoFlagsBuildTags(os.Getenv("GOFLAGS")); len(goFlagsTags) > 0 {
		bctx.BuildTags = append(append([]string{}, bctx.BuildTags...), goFlagsTags...)
	}
	if len(opts.BuildTags) > 0 {
		bctx.BuildTags = append(append([]string{}, bctx.BuildTags...), opts.BuildTags...)
	}
	out := &Loaded{
		Fset:   token.NewFileSet(),
		Module: mod,
		Files:  map[string]*FileEntry{},
		Tests:  opts.Tests,
	}
	wsMods := map[string]Module{}
	walkRoots := []string{absDir}
	seenRoot := map[string]bool{absDir: true}
	if realAbs, rerr := filepath.EvalSymlinks(absDir); rerr == nil && realAbs != "" {
		seenRoot[realAbs] = true
	}
	for _, ws := range mod.Workspaces {
		if wm, werr := FindModule(ws); werr == nil && wm.Dir != "" {
			wsMods[wm.Dir] = wm
			realDir := wm.Dir
			if r, rerr := filepath.EvalSymlinks(wm.Dir); rerr == nil && r != "" {
				realDir = r
				wsMods[realDir] = wm
			}
			underAbs := wm.Dir == absDir || strings.HasPrefix(wm.Dir, absDir+string(filepath.Separator))
			if !underAbs {
				if realAbs, rerr := filepath.EvalSymlinks(absDir); rerr == nil && realAbs != "" {
					underAbs = realDir == realAbs || strings.HasPrefix(realDir, realAbs+string(filepath.Separator))
				}
			}
			if !underAbs && !seenRoot[wm.Dir] && !seenRoot[realDir] {
				seenRoot[wm.Dir] = true
				seenRoot[realDir] = true
				walkRoots = append(walkRoots, wm.Dir)
			}
		}
	}
	pkgByDir := map[string]*packages.Package{}
	for _, walkRoot := range walkRoots {
		werr := filepath.WalkDir(walkRoot, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				if path == walkRoot {
					return nil
				}
				name := d.Name()
				if name == "vendor" || name == "testdata" || name == "node_modules" ||
					strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
					return filepath.SkipDir
				}
				// Nested go.mod that is not part of go.work is a separate module.
				if _, ok := wsMods[path]; !ok {
					if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 {
				if st, serr := os.Stat(path); serr != nil || st.IsDir() {
					return nil
				}
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return nil
			}
			inTest := strings.HasSuffix(name, "_test.go")
			if inTest && !opts.Tests {
				return nil
			}
			dir := filepath.Dir(path)
			if match, matchErr := bctx.MatchFile(dir, name); matchErr == nil && !match {
				return nil
			}
			var skipped bool
			if opts.MaxFileSizeMB > 0 {
				if info, infoErr := d.Info(); infoErr == nil && info.Size() > int64(opts.MaxFileSizeMB*1024*1024) {
					skipped = true
					out.SkippedFiles = append(out.SkippedFiles, SkippedFile{Path: path, Bytes: info.Size()})
				}
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			syntax, parseErr := parser.ParseFile(out.Fset, path, data, parser.ParseComments)
			if parseErr != nil {
				out.TypeErrors = append(out.TypeErrors, parseErr.Error())
			}
			if syntax == nil || syntax.Name == nil || syntax.Name.Name == "" {
				return nil
			}
			p, ok := pkgByDir[dir]
			if !ok {
				pkgPath := resolveSyntaxPkgPath(dir, absDir, mod, wsMods)
				p = &packages.Package{
					ID:      pkgPath,
					PkgPath: pkgPath,
					Name:    syntax.Name.Name,
					Fset:    out.Fset,
				}
				pkgByDir[dir] = p
				out.Pkgs = append(out.Pkgs, p)
			} else if !inTest && strings.HasSuffix(p.Name, "_test") {
				p.Name = syntax.Name.Name
			}
			p.GoFiles = append(p.GoFiles, path)
			p.CompiledGoFiles = append(p.CompiledGoFiles, path)
			p.Syntax = append(p.Syntax, syntax)
			out.Files[path] = &FileEntry{
				Path:    path,
				Pkg:     p,
				Syntax:  syntax,
				Src:     data,
				InTest:  inTest,
				Skipped: skipped,
			}
			return nil
		})
		if werr != nil && err == nil {
			err = werr
		}
	}
	if err != nil {
		return nil, err
	}
	if len(out.Files) == 0 {
		if len(out.TypeErrors) > 0 {
			return out, fmt.Errorf("no Go files could be parsed: %s", out.TypeErrors[0])
		}
		return out, fmt.Errorf("no Go packages found under %s", opts.Dir)
	}
	return out, nil
}

// parseGoFlagsBuildTags extracts build tags configured via GOFLAGS (-tags=... or -tags ...).
func parseGoFlagsBuildTags(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var args []string
	var cur strings.Builder
	inToken := false
	var quote rune
	for _, r := range raw {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			inToken = true
		case r == '\'' || r == '"':
			quote = r
			inToken = true
		case unicode.IsSpace(r):
			if inToken {
				args = append(args, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			cur.WriteRune(r)
			inToken = true
		}
	}
	if inToken {
		args = append(args, cur.String())
	}
	var tags []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		var val string
		switch {
		case arg == "-tags" || arg == "--tags":
			if i+1 < len(args) {
				i++
				val = args[i]
			}
		case strings.HasPrefix(arg, "-tags="):
			val = strings.TrimPrefix(arg, "-tags=")
		case strings.HasPrefix(arg, "--tags="):
			val = strings.TrimPrefix(arg, "--tags=")
		}
		if val == "" {
			continue
		}
		for _, tok := range strings.FieldsFunc(val, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
			if tok != "" {
				tags = append(tags, tok)
			}
		}
	}
	return tags
}

func resolveSyntaxPkgPath(dir, absRoot string, mod Module, wsMods map[string]Module) string {
	for wsDir, wm := range wsMods {
		if dir == wsDir {
			if wm.Path != "" {
				return wm.Path
			}
		} else if strings.HasPrefix(dir, wsDir+string(filepath.Separator)) && wm.Path != "" {
			rel, _ := filepath.Rel(wsDir, dir)
			return wm.Path + "/" + filepath.ToSlash(rel)
		}
	}
	if mod.Dir != "" && mod.Path != "" {
		if dir == mod.Dir {
			return mod.Path
		}
		if strings.HasPrefix(dir, mod.Dir+string(filepath.Separator)) {
			rel, _ := filepath.Rel(mod.Dir, dir)
			return mod.Path + "/" + filepath.ToSlash(rel)
		}
	}
	rel, err := filepath.Rel(absRoot, dir)
	if err != nil || rel == "." {
		if mod.Path != "" {
			return mod.Path
		}
		return filepath.Base(absRoot)
	}
	if mod.Path != "" {
		return mod.Path + "/" + filepath.ToSlash(rel)
	}
	return filepath.ToSlash(rel)
}

// IsProjectPkg reports whether a package belongs to the analyzed project
// rather than to the standard library or a dependency.
func (l *Loaded) IsProjectPkg(p *packages.Package) bool {
	if p == nil || p.PkgPath == "unsafe" || p.PkgPath == "builtin" {
		return false
	}
	if l.Module.Path != "" {
		if p.PkgPath == l.Module.Path || strings.HasPrefix(p.PkgPath, l.Module.Path+"/") {
			return true
		}
	}
	// GOPATH or multi-module workspace mode: judge by file location.
	for _, f := range p.GoFiles {
		if _, ok := l.Files[f]; ok {
			return true
		}
	}
	return false
}

// ProjectPackages returns the packages the module owns.
func (l *Loaded) ProjectPackages() []*packages.Package {
	var out []*packages.Package
	for _, p := range l.Pkgs {
		if l.IsProjectPkg(p) {
			out = append(out, p)
		}
	}
	return out
}

// ProjectFiles returns every analyzed project file.
func (l *Loaded) ProjectFiles() []*FileEntry {
	var out []*FileEntry
	for _, entry := range l.Files {
		if l.IsProjectPkg(entry.Pkg) {
			out = append(out, entry)
		}
	}
	return out
}
