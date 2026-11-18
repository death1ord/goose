// Package deadcode reports what nothing uses: unreachable packages, dead
// symbols, unused dependencies, and unresolved imports. It mirrors fallow's
// dead-code semantics: stable finding ids, suppression comments, baselines,
// and cascade hiding.
package deadcode

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"goose/internal/config"
	"goose/internal/facts"
	"goose/internal/glob"
	"goose/internal/graph"
	"goose/internal/report"
)

// Options carry run inputs beyond config.
type Options struct {
	// Production drops test files from analysis.
	Production bool
	// IncludeEntryExports reports unused exports in entry packages too.
	IncludeEntryExports bool
	// ShowCascade lists findings that an unused file would otherwise hide.
	ShowCascade bool
	// Std is the resolved Go standard-library package set. When nil, deadcode
	// falls back to the dot-in-first-element heuristic.
	Std map[string]bool
	// Unresolved lists import paths that go list could not resolve.
	Unresolved []UnresolvedImport
}

// UnresolvedImport names one import path that failed to resolve.
type UnresolvedImport struct {
	Specifier string
	File      string // project-relative
	Line      int
	Package   string
}

// Analysis holds the shared inputs of one run.
type Analysis struct {
	Proj  *facts.Project
	Graph *graph.Graph
	Cfg   *config.Config
	Opts  Options

	ignoreFindingsMatcher glob.Matcher
	compiled              bool
}

// Result is the finding set of one dead-code run.
type Result struct {
	Findings      []*report.Finding
	CascadeHidden int
	Diags         []report.Diag
	// UnusedPkgs lists unreachable package paths, for doctor and trace.
	UnusedPkgs []string
	// Stale lists suppression comments that matched nothing.
	Stale int
}

// Run computes every dead-code finding.
func Run(a *Analysis) *Result {
	r := &Result{}
	for _, ff := range a.Proj.Files {
		for _, s := range ff.Suppressions {
			s.Used = false
		}
	}
	reached := a.Graph.ReachablePackages(a.Cfg)
	entries := map[string]bool{}
	for _, p := range a.Graph.EntryPackages(a.Cfg) {
		entries[p] = true
	}
	a.compileMatchers()

	// 1. Unused files: files in packages nothing reaches.
	deadPkg := map[string]bool{}
	for _, pkg := range a.Graph.Packages {
		if !reached[pkg] && !entries[pkg] && !a.Graph.IsTestPkg(pkg) {
			deadPkg[pkg] = true
			r.UnusedPkgs = append(r.UnusedPkgs, pkg)
		}
	}
	sort.Strings(r.UnusedPkgs)

	// Files of an entry package are never dead, but a test-only package is
	// only dead in production mode.
	reportedFiles := map[string]bool{}
	for _, ff := range sortedFiles(a.Proj) {
		if ff.InTest {
			continue
		}
		if a.Proj.SkippedFiles[ff.Rel] {
			continue // size guard: never reported, never the judge of others
		}
		if !deadPkg[ff.PkgPath] {
			continue
		}
		if a.IgnoreFindings(ff.Rel) {
			continue
		}
		if a.suppressedAt(ff.Path, 0, "unused-file") {
			continue
		}
		sev := a.Cfg.RuleSeverity("unused-files", ff.Rel)
		if sev == config.Off {
			continue
		}
		f := &report.Finding{
			Kind: "unused-file", Rule: "unused-files", Path: ff.Rel,
			Message:  "Package is not reachable from any entry point",
			Severity: sev,
			ID:       report.Fingerprint("unused-file", ff.Rel),
			Extra:    map[string]any{"package": ff.PkgPath},
			Actions: []report.Action{{
				Type: "remove-file", Description: "Delete the file, or add its package as an entry point.",
				AutoFixable: true,
			}},
		}
		r.Findings = append(r.Findings, f)
		reportedFiles[ff.Rel] = true
	}

	// 2. Symbols.
	live := a.computeLiveEntities(entries)
	for _, e := range sortedEntities(a.Proj) {
		if e.Local || e.InterfaceMethod {
			continue
		}
		ff := a.Proj.Files[e.File]
		if ff == nil {
			continue
		}
		if e.TestFile && a.Opts.Production {
			continue
		}
		if a.IgnoreFindings(ff.Rel) {
			continue
		}
		if live[e.Key] {
			continue
		}
		// Entry packages keep their exported API: a framework or a plugin host
		// reads it through the package path with no import in the repo.
		if e.Exported && entries[e.PkgPath] && !a.Opts.IncludeEntryExports {
			continue
		}
		// A symbol inside an unused file is reported on the file, not again on
		// the symbol, unless --show-cascade asks for the full list.
		if deadPkg[e.PkgPath] && !a.Opts.ShowCascade {
			continue
		}
		kind := EntityKind(e)
		rule := report.RuleForKind(kind)
		sev := a.Cfg.RuleSeverity(rule, ff.Rel)
		if sev == config.Off {
			continue
		}
		if a.suppressedAt(e.File, e.Line, kind) {
			continue
		}
		f := &report.Finding{
			Kind: kind, Rule: rule, Path: ff.Rel, Line: e.Line, Col: e.Col,
			Message:  EntityMessage(e),
			Severity: sev,
			ID:       DeadFindingID(kind, ff.Rel, e),
			Extra:    entityExtra(e),
			Actions:  DefaultActions(kind),
		}
		// Cascade hiding: nothing in an unused file is reported separately.
		if (reportedFiles[ff.Rel] || deadPkg[e.PkgPath]) && !a.Opts.ShowCascade {
			f.Hidden = true
			r.CascadeHidden++
		}
		r.Findings = append(r.Findings, f)
	}

	// 3. Dependencies, imports, and API rules.
	r.runDependencies(a)
	r.runUnresolved(a)
	r.runDuplicateExports(a)
	r.runDeprecatedExports(a)
	r.runPrivateTypeLeaks(a)
	r.runWriteOnly(a, live)
	r.runCanBeUnexported(a, live, entries)
	r.runUnusedInterfaceMethods(a, live, entries)
	r.runUnusedParamsAndReceivers(a, live)
	r.runStructPadding(a, live)
	r.runGoIssues(a)
	r.runFeatureFlags(a)

	// 4. Suppression hygiene.
	r.runSuppressions(a)

	report.SortFindings(r.Findings)
	return r
}

// ---------------------------------------------------------------------------
// Entity helpers.
// ---------------------------------------------------------------------------

// validUses returns the use sites of e that pass production, self-declaration,
// package-visibility, and ignoreFindings filters.
func (a *Analysis) validUses(e *facts.Entity) []facts.UseSite {
	var out []facts.UseSite
	for _, u := range a.Proj.Uses[e.Key] {
		if a.Opts.Production && u.FromTest {
			continue
		}
		if insideOwnDecl(a, e, u) {
			continue
		}
		if !e.Exported && !u.SelfPackage {
			continue
		}
		if a.ignoreUseSite(u.File) {
			continue
		}
		out = append(out, u)
	}
	return out
}

// computeLiveEntities computes entity liveness, eliminating mutually recursive
// and transitive dead unexported call/reference cycles (e.g. deadA <-> deadB).
func (a *Analysis) computeLiveEntities(entries map[string]bool) map[facts.Key]bool {
	baseAlive := map[facts.Key]bool{}
	usesByKey := map[facts.Key][]facts.UseSite{}
	for k, e := range a.Proj.Entities {
		if e == nil {
			continue
		}
		if e.Func != nil && (e.Func.IsMain || e.Func.IsInit) {
			baseAlive[k] = true
			continue
		}
		if e.TestFile && isRootTestName(e.Name) {
			baseAlive[k] = true
			continue
		}
		vu := a.validUses(e)
		usesByKey[k] = vu
		if len(vu) > 0 {
			baseAlive[k] = true
		}
	}

	// Build forward edges (caller -> callee) and seed roots for reachability of
	// unexported entities. Any exported entity, intrinsic root (main/init/test),
	// or entity referenced from a non-entity context (package-level init,
	// interface satisfaction, reflection tag, compiler directive, inactive
	// build-tag file) is a root.
	reachable := map[facts.Key]bool{}
	callees := map[facts.Key][]facts.Key{}
	var queue []facts.Key
	enqueue := func(k facts.Key) {
		if !reachable[k] {
			reachable[k] = true
			queue = append(queue, k)
		}
	}

	for k, e := range a.Proj.Entities {
		if e == nil {
			continue
		}
		if (e.Func != nil && (e.Func.IsMain || e.Func.IsInit)) ||
			(e.TestFile && isRootTestName(e.Name)) ||
			(e.Exported && (e.Recv == "" || ast.IsExported(e.Recv)) && (baseAlive[k] || entries[e.PkgPath])) {
			enqueue(k)
		}
		for _, u := range usesByKey[k] {
			if u.ContainingKey == "" || a.Proj.Entities[u.ContainingKey] == nil {
				enqueue(k)
				continue
			}
			callees[u.ContainingKey] = append(callees[u.ContainingKey], k)
		}
	}

	// A reachable struct/type also reaches its methods and fields, and a
	// reachable method/field reaches its receiver type.
	for k, e := range a.Proj.Entities {
		if e == nil || e.Recv == "" {
			continue
		}
		tKey := facts.MakeKey(facts.KindType, e.PkgPath, "", e.Recv)
		if a.Proj.Entities[tKey] != nil {
			callees[k] = append(callees[k], tKey)
			if e.Kind == facts.KindField || baseAlive[k] {
				callees[tKey] = append(callees[tKey], k)
			}
		}
	}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		for _, next := range callees[curr] {
			if baseAlive[next] {
				enqueue(next)
			}
		}
	}

	live := map[facts.Key]bool{}
	for k, e := range a.Proj.Entities {
		if !baseAlive[k] {
			continue
		}
		if !e.Exported && (e.Recv == "" || !ast.IsExported(e.Recv)) && !reachable[k] {
			continue
		}
		live[k] = true
	}
	return live
}

// insideOwnDecl reports whether a use sits in the entity's own declaration.
// A method body referencing its receiver type, or a recursive call, does not
// keep the symbol alive.
func insideOwnDecl(a *Analysis, e *facts.Entity, u facts.UseSite) bool {
	for _, sp := range a.Proj.EntitySpans[e.Key] {
		if sp.File == u.File && u.Line >= sp.StartLine && u.Line <= sp.EndLine {
			return true
		}
	}
	return false
}

func isRootTestName(name string) bool {
	for _, p := range []string{"Test", "Benchmark", "Fuzz", "Example"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return name == "init" || name == "TestMain" || name == "BenchmarkMain"
}

// EntityKind maps an entity to its singular finding token.
func EntityKind(e *facts.Entity) string {
	switch e.Kind {
	case facts.KindFunc:
		if e.Exported {
			return "unused-export"
		}
		return "unused-unexported"
	case facts.KindMethod:
		return "unused-method"
	case facts.KindType, facts.KindInterface:
		return "unused-type"
	case facts.KindField:
		return "unused-field"
	case facts.KindConst:
		return "unused-constant"
	case facts.KindVar:
		return "unused-variable"
	}
	return "unused-unexported"
}

// EntityMessage renders the human description of a dead symbol.
func EntityMessage(e *facts.Entity) string {
	switch e.Kind {
	case facts.KindFunc:
		if e.Exported {
			return fmt.Sprintf("Exported function %q is never referenced by another package", e.Name)
		}
		return fmt.Sprintf("Function %q is never called in its package", e.Name)
	case facts.KindMethod:
		return fmt.Sprintf("Method %s.%s is never called and no used interface requires it", e.Recv, e.Name)
	case facts.KindType:
		return fmt.Sprintf("Type %q is never referenced", e.Name)
	case facts.KindInterface:
		return fmt.Sprintf("Interface %q is never used", e.Name)
	case facts.KindField:
		if e.Field != nil && len(e.Field.TagNames) > 0 {
			return fmt.Sprintf("Field %s.%s is never read, written, or marshalled", e.Recv, e.Name)
		}
		return fmt.Sprintf("Field %s.%s is never read or written", e.Recv, e.Name)
	case facts.KindConst:
		return fmt.Sprintf("Constant %q is never referenced", e.Name)
	case facts.KindVar:
		if strings.HasPrefix(e.Name, "err") {
			return fmt.Sprintf("Error variable %q is never referenced", e.Name)
		}
		return fmt.Sprintf("Variable %q is never referenced", e.Name)
	}
	return "unused symbol"
}

// DeadFindingID builds the stable line-free finding id of an entity.
func DeadFindingID(kind, rel string, e *facts.Entity) string {
	if e.Recv != "" {
		return report.Fingerprint(kind, rel, e.Recv, e.Name)
	}
	return report.Fingerprint(kind, rel, e.Name)
}

func entityExtra(e *facts.Entity) map[string]any {
	m := map[string]any{"symbol": e.Name}
	if e.Exported {
		m["exported"] = true
	}
	if e.Recv != "" {
		switch e.Kind {
		case facts.KindMethod:
			m["method"] = e.Name
			m["receiver"] = e.Recv
		case facts.KindField:
			m["field"] = e.Name
			m["struct"] = e.Recv
		}
	}
	if e.Kind == facts.KindInterface {
		m["interface"] = e.Name
	}
	if e.Deprecated {
		m["deprecated"] = true
	}
	return m
}

// DefaultActions returns the follow-up actions for a dead-symbol kind.
func DefaultActions(kind string) []report.Action {
	switch kind {
	case "unused-export", "unused-unexported", "unused-method", "unused-type",
		"unused-field", "unused-constant", "unused-variable":
		return []report.Action{{
			Type:        "remove-dead-code",
			Description: "Delete the declaration, then delete the helpers it enabled.",
			AutoFixable: true,
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Dependencies.
// ---------------------------------------------------------------------------

func (r *Result) runDependencies(a *Analysis) {
	imported := map[string][]string{}
	for _, ff := range sortedFiles(a.Proj) {
		if a.Opts.Production && ff.InTest {
			continue
		}
		for _, imp := range ff.Imports {
			imported[imp.Path] = append(imported[imp.Path], ff.Rel)
		}
	}
	for _, req := range a.Proj.Module.Requires {
		if a.IgnoreDependency(req) {
			continue
		}
		if len(a.Proj.Module.Path) > 0 && (req == a.Proj.Module.Path || strings.HasPrefix(req, a.Proj.Module.Path+"/")) {
			continue
		}
		used := false
		for ipath := range imported {
			if ipath == req || strings.HasPrefix(ipath, req+"/") {
				used = true
				break
			}
		}
		if used {
			continue
		}
		rule := "unused-dependencies"
		kind := "unused-dependency"
		if testOnlyImport(a, req) {
			rule = "unused-test-dependencies"
			kind = "unused-test-dependency"
		}
		sev := a.Cfg.RuleSeverity(rule, "go.mod")
		if sev == config.Off {
			continue
		}
		line, col := locateGoModLine(a.Proj.Module.Dir, req)
		msg := fmt.Sprintf("Module %s is required but never imported", req)
		if kind == "unused-test-dependency" {
			msg = fmt.Sprintf("Module %s is required in production but imported only in tests", req)
		}
		f := &report.Finding{
			Kind: kind, Rule: rule, Path: "go.mod", Line: line, Col: col,
			Message:  msg,
			Severity: sev,
			ID:       report.Fingerprint(kind, "go.mod", req),
			Extra:    map[string]any{"package_name": req, "location": "require"},
			Actions: []report.Action{{
				Type:        "remove-dependency",
				Description: "Drop the require entry, or run go mod tidy.",
				AutoFixable: true,
				Extra:       map[string]any{"package": req},
			}},
		}
		r.Findings = append(r.Findings, f)
	}
	r.reportUnlisted(a, imported)
}

// testOnlyImport reports whether a module appears only in test files.
func testOnlyImport(a *Analysis, req string) bool {
	saw := false
	for _, ff := range a.Proj.Files {
		for _, imp := range ff.Imports {
			if !(imp.Path == req || strings.HasPrefix(imp.Path, req+"/")) {
				continue
			}
			saw = true
			if !ff.InTest {
				return false
			}
		}
	}
	return saw
}

func (r *Result) reportUnlisted(a *Analysis, imported map[string][]string) {
	rule := "unlisted-dependencies"
	sev := a.Cfg.RuleSeverity(rule, "")
	if sev == config.Off {
		return
	}
	internalPkgs := make(map[string]bool, len(a.Proj.Files))
	for _, ff := range a.Proj.Files {
		if ff != nil && ff.PkgPath != "" {
			internalPkgs[ff.PkgPath] = true
		}
	}
	for ipath, files := range imported {
		if ipath == "C" || internalPkgs[ipath] ||
			(len(a.Proj.Module.Path) > 0 && (ipath == a.Proj.Module.Path || strings.HasPrefix(ipath, a.Proj.Module.Path+"/"))) ||
			IsStd(ipath, a.Opts.Std) {
			continue
		}
		if a.IgnoreDependency(ipath) || a.IgnoreSpecifier(ipath) {
			continue
		}
		covered := false
		for _, req := range a.Proj.Module.Requires {
			if ipath == req || strings.HasPrefix(ipath, req+"/") {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		for _, rel := range files {
			ff := fileByRel(a, rel)
			if ff == nil {
				continue
			}
			line, col := 1, 0
			for _, imp := range ff.Imports {
				if imp.Path == ipath {
					line, col = imp.Line, imp.Col
					break
				}
			}
			f := &report.Finding{
				Kind: "unlisted-dependency", Rule: rule, Path: ff.Rel, Line: line, Col: col,
				Message:  fmt.Sprintf("Import %s is not declared in go.mod", ipath),
				Severity: sev,
				ID:       report.Fingerprint("unlisted-dependency", ff.Rel, ipath),
				Extra:    map[string]any{"package_name": ipath, "specifier": ipath},
				Actions: []report.Action{{
					Type: "add-dependency", Description: "Run go get " + ipath + ".",
					AutoFixable: false, Extra: map[string]any{"package": ipath},
				}},
			}
			r.Findings = append(r.Findings, f)
			break // one finding per import path, like fallow
		}
	}
}

// ---------------------------------------------------------------------------
// Unresolved imports.
// ---------------------------------------------------------------------------

func (r *Result) runUnresolved(a *Analysis) {
	rule := "unresolved-imports"
	for _, u := range a.Opts.Unresolved {
		sev := a.Cfg.RuleSeverity(rule, u.File)
		if sev == config.Off || a.IgnoreFindings(u.File) || a.IgnoreSpecifier(u.Specifier) {
			continue
		}
		f := &report.Finding{
			Kind: "unresolved-import", Rule: rule, Path: u.File, Line: u.Line, Col: 0,
			Message:  fmt.Sprintf("Import %q cannot be resolved", u.Specifier),
			Severity: sev,
			ID:       report.Fingerprint("unresolved-import", u.File, u.Specifier),
			Extra:    map[string]any{"specifier": u.Specifier, "package_name": u.Package},
			Actions: []report.Action{{
				Type: "add-to-config", Description: "Ignore the specifier in ignoreUnresolvedImports.",
				AutoFixable: false,
				Extra:       map[string]any{"field": "ignoreUnresolvedImports", "specifier": u.Specifier},
			}},
		}
		r.Findings = append(r.Findings, f)
	}
}

// ---------------------------------------------------------------------------
// Duplicate exports.
// ---------------------------------------------------------------------------

func (r *Result) runDuplicateExports(a *Analysis) {
	rule := "duplicate-exports"
	if a.Cfg.RuleSeverity(rule, "") == config.Off {
		return
	}
	type exportName struct{ kind, name string }
	byName := map[exportName][]*facts.Entity{}
	for _, e := range a.Proj.Entities {
		if !e.Exported || e.Local || e.TestFile || e.Recv != "" {
			continue
		}
		if e.Kind != facts.KindFunc && e.Kind != facts.KindType && e.Kind != facts.KindConst && e.Kind != facts.KindVar {
			continue
		}
		k := exportName{string(e.Kind), e.Name}
		byName[k] = append(byName[k], e)
	}
	for k, group := range byName {
		if len(group) < 2 {
			continue
		}
		sort.Slice(group, func(i, j int) bool {
			if group[i].File != group[j].File {
				return group[i].File < group[j].File
			}
			return group[i].Line < group[j].Line
		})
		pkgs := map[string]bool{}
		for _, e := range group {
			pkgs[e.PkgPath] = true
		}
		if len(pkgs) < 2 {
			continue // the same name twice in one package is a compile error
		}
		for _, e := range group {
			var others []any
			for _, other := range group {
				if other.PkgPath != e.PkgPath {
					others = append(others, other.PkgPath)
				}
			}
			ff := a.Proj.Files[e.File]
			if ff == nil {
				continue
			}
			f := &report.Finding{
				Kind: "duplicate-export", Rule: rule, Path: ff.Rel, Line: e.Line, Col: e.Col,
				Message:  fmt.Sprintf("%s %q is exported by %d packages", labelOfKind(k.kind), k.name, len(pkgs)),
				Severity: a.Cfg.RuleSeverity(rule, ff.Rel),
				ID:       report.Fingerprint("duplicate-export", ff.Rel, k.name, e.PkgPath),
				Extra:    map[string]any{"symbol": k.name, "also_exported_by": others, "occurrences": len(group)},
			}
			if a.suppressedAt(e.File, e.Line, "duplicate-export") {
				continue
			}
			r.Findings = append(r.Findings, f)
		}
	}
}

func labelOfKind(kind string) string {
	switch facts.Kind(kind) {
	case facts.KindFunc:
		return "function"
	case facts.KindType:
		return "type"
	case facts.KindConst:
		return "constant"
	case facts.KindVar:
		return "variable"
	}
	return "symbol"
}

// ---------------------------------------------------------------------------
// Deprecated exports in use.
// ---------------------------------------------------------------------------

func (r *Result) runDeprecatedExports(a *Analysis) {
	rule := "deprecated-exports-in-use"
	if !a.Cfg.RuleEnabled(rule) {
		return
	}
	for _, e := range sortedEntities(a.Proj) {
		if !e.Deprecated || !e.Exported || e.TestFile {
			continue
		}
		ff := a.Proj.Files[e.File]
		if ff == nil || a.IgnoreFindings(ff.Rel) {
			continue
		}
		sev := a.Cfg.RuleSeverity(rule, ff.Rel)
		if sev == config.Off {
			continue
		}
		hasUse := false
		for _, u := range a.Proj.LiveUses(e.Key) {
			if a.Opts.Production && u.FromTest {
				continue
			}
			if a.ignoreUseSite(u.File) {
				continue
			}
			hasUse = true
			break
		}
		if !hasUse {
			continue
		}
		if a.suppressedAt(e.File, e.Line, "deprecated-export-in-use") {
			continue
		}
		f := &report.Finding{
			Kind: "deprecated-export-in-use", Rule: rule, Path: ff.Rel, Line: e.Line, Col: e.Col,
			Message:  fmt.Sprintf("Exported %s %q is deprecated but still in use", e.Kind, e.Name),
			Severity: sev,
			ID:       DeadFindingID("deprecated-export-in-use", ff.Rel, e),
			Extra:    entityExtra(e),
		}
		r.Findings = append(r.Findings, f)
	}
}

// ---------------------------------------------------------------------------
// Private type leaks.
// ---------------------------------------------------------------------------

func (r *Result) runPrivateTypeLeaks(a *Analysis) {
	rule := "private-type-leaks"
	if !a.Cfg.RuleEnabled(rule) {
		return
	}
	for _, e := range sortedEntities(a.Proj) {
		if !e.Exported || e.Local || e.TestFile {
			continue
		}
		if e.Recv != "" && !ast.IsExported(e.Recv) {
			continue
		}
		ff := a.Proj.Files[e.File]
		if ff == nil || a.IgnoreFindings(ff.Rel) {
			continue
		}
		sev := a.Cfg.RuleSeverity(rule, ff.Rel)
		if sev == config.Off {
			continue
		}
		var leakedTypes []string
		if e.DeclNode != nil {
			switch node := e.DeclNode.(type) {
			case *ast.FuncDecl:
				if node.Type != nil {
					if node.Type.Params != nil {
						for _, fld := range node.Type.Params.List {
							leakedTypes = append(leakedTypes, findPrivateTypes(e.PkgPath, a.Proj, fld.Type)...)
						}
					}
					if node.Type.Results != nil {
						for _, fld := range node.Type.Results.List {
							leakedTypes = append(leakedTypes, findPrivateTypes(e.PkgPath, a.Proj, fld.Type)...)
						}
					}
				}
			case *ast.TypeSpec:
				if st, ok := node.Type.(*ast.StructType); ok && st.Fields != nil {
					for _, fld := range st.Fields.List {
						isExp := len(fld.Names) == 0 // embedded
						for _, name := range fld.Names {
							if name.IsExported() {
								isExp = true
								break
							}
						}
						if isExp {
							leakedTypes = append(leakedTypes, findPrivateTypes(e.PkgPath, a.Proj, fld.Type)...)
						}
					}
				} else {
					leakedTypes = append(leakedTypes, findPrivateTypes(e.PkgPath, a.Proj, node.Type)...)
				}
			case *ast.ValueSpec:
				if node.Type != nil {
					leakedTypes = append(leakedTypes, findPrivateTypes(e.PkgPath, a.Proj, node.Type)...)
				}
			}
		} else {
			for _, name := range e.PrivateTypeCandidates {
				if isBuiltinType(name) {
					continue
				}
				tKey := facts.MakeKey(facts.KindType, e.PkgPath, "", name)
				iKey := facts.MakeKey(facts.KindInterface, e.PkgPath, "", name)
				if a.Proj.Entities[tKey] != nil || a.Proj.Entities[iKey] != nil {
					leakedTypes = append(leakedTypes, name)
				}
			}
		}

		seen := map[string]bool{}
		for _, lt := range leakedTypes {
			if seen[lt] {
				continue
			}
			seen[lt] = true
			if a.suppressedAt(e.File, e.Line, "private-type-leak") {
				continue
			}
			f := &report.Finding{
				Kind: "private-type-leak", Rule: rule, Path: ff.Rel, Line: e.Line, Col: e.Col,
				Message:  fmt.Sprintf("Exported %s %q exposes unexported type %q", e.Kind, e.Name, lt),
				Severity: sev,
				ID:       report.Fingerprint("private-type-leak", ff.Rel, e.Name, lt),
				Extra: map[string]any{
					"symbol": e.Name,
					"type":   lt,
				},
			}
			r.Findings = append(r.Findings, f)
		}
	}
}

func findPrivateTypes(pkgPath string, proj *facts.Project, expr ast.Expr) []string {
	if expr == nil {
		return nil
	}
	var out []string
	ast.Inspect(expr, func(n ast.Node) bool {
		switch t := n.(type) {
		case *ast.SelectorExpr:
			return false
		case *ast.Ident:
			if !ast.IsExported(t.Name) && !isBuiltinType(t.Name) {
				tKey := facts.MakeKey(facts.KindType, pkgPath, "", t.Name)
				iKey := facts.MakeKey(facts.KindInterface, pkgPath, "", t.Name)
				if proj.Entities[tKey] != nil || proj.Entities[iKey] != nil {
					out = append(out, t.Name)
				}
			}
		}
		return true
	})
	return out
}

func isBuiltinType(s string) bool {
	switch s {
	case "bool", "byte", "complex64", "complex128", "error", "float32", "float64",
		"int", "int8", "int16", "int32", "int64", "rune", "string",
		"uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "any", "comparable":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Go-specific symbol, type, and runtime hazard rules.
// ---------------------------------------------------------------------------

// runWriteOnly reports struct fields and package-level variables that are
// written (assigned or initialized in a composite literal) but never read.
func (r *Result) runWriteOnly(a *Analysis, live map[facts.Key]bool) {
	wantFields := a.Cfg.RuleEnabled("write-only-fields")
	wantVars := a.Cfg.RuleEnabled("write-only-variables")
	if !wantFields && !wantVars {
		return
	}
	for _, e := range sortedEntities(a.Proj) {
		if e.Local || e.InterfaceMethod || !live[e.Key] {
			continue
		}
		if e.TestFile && a.Opts.Production {
			continue
		}
		ff := a.Proj.Files[e.File]
		if ff == nil || a.IgnoreFindings(ff.Rel) {
			continue
		}
		switch e.Kind {
		case facts.KindField:
			if !wantFields {
				continue
			}
			sev := a.Cfg.RuleSeverity("write-only-fields", ff.Rel)
			if sev == config.Off {
				continue
			}
			if e.Field != nil && len(e.Field.TagNames) > 0 && a.Proj.ReflectivePkgs[e.PkgPath] {
				continue
			}
			uses := a.validUses(e)
			if len(uses) == 0 {
				continue
			}
			allWriteOnly := true
			for _, u := range uses {
				if !u.WriteOnly {
					allWriteOnly = false
					break
				}
			}
			if !allWriteOnly || a.suppressedAt(e.File, e.Line, "write-only-field") {
				continue
			}
			r.Findings = append(r.Findings, &report.Finding{
				Kind: "write-only-field", Rule: "write-only-fields",
				Path: ff.Rel, Line: e.Line, Col: e.Col,
				Message:  fmt.Sprintf("Field %s.%s is assigned or initialized but never read", e.Recv, e.Name),
				Severity: sev,
				ID:       DeadFindingID("write-only-field", ff.Rel, e),
				Extra:    entityExtra(e),
			})
		case facts.KindVar:
			if !wantVars {
				continue
			}
			sev := a.Cfg.RuleSeverity("write-only-variables", ff.Rel)
			if sev == config.Off {
				continue
			}
			uses := a.validUses(e)
			if len(uses) == 0 {
				continue
			}
			allWriteOnly := true
			for _, u := range uses {
				if !u.WriteOnly {
					allWriteOnly = false
					break
				}
			}
			if !allWriteOnly || a.suppressedAt(e.File, e.Line, "write-only-variable") {
				continue
			}
			r.Findings = append(r.Findings, &report.Finding{
				Kind: "write-only-variable", Rule: "write-only-variables",
				Path: ff.Rel, Line: e.Line, Col: e.Col,
				Message:  fmt.Sprintf("Variable %q is assigned but never read", e.Name),
				Severity: sev,
				ID:       DeadFindingID("write-only-variable", ff.Rel, e),
				Extra:    entityExtra(e),
			})
		}
	}
}

// runCanBeUnexported reports exported package-level declarations that are only
// referenced within their own declaring package.
func (r *Result) runCanBeUnexported(a *Analysis, live map[facts.Key]bool, entries map[string]bool) {
	const rule = "can-be-unexported"
	if !a.Cfg.RuleEnabled(rule) {
		return
	}
	// Precompute which types have cross-package method or field uses.
	crossPkgRecv := map[string]bool{}
	for _, e := range a.Proj.Entities {
		if e == nil || e.Recv == "" {
			continue
		}
		for _, u := range a.validUses(e) {
			if !u.SelfPackage || u.Kind == "iface" || u.Kind == "directive" {
				crossPkgRecv[e.PkgPath+"\x1f"+e.Recv] = true
				break
			}
		}
	}
	for _, e := range sortedEntities(a.Proj) {
		if !e.Exported || e.Local || e.TestFile || e.Recv != "" || e.InterfaceMethod || !live[e.Key] {
			continue
		}
		switch e.Kind {
		case facts.KindFunc, facts.KindType, facts.KindInterface, facts.KindConst, facts.KindVar:
		default:
			continue
		}
		if entries[e.PkgPath] && !a.Opts.IncludeEntryExports {
			continue
		}
		ff := a.Proj.Files[e.File]
		if ff == nil || a.IgnoreFindings(ff.Rel) || a.isPublicPackage(e.PkgPath, ff.Rel) {
			continue
		}
		sev := a.Cfg.RuleSeverity(rule, ff.Rel)
		if sev == config.Off {
			continue
		}
		if (e.Kind == facts.KindType || e.Kind == facts.KindInterface) && crossPkgRecv[e.PkgPath+"\x1f"+e.Name] {
			continue
		}
		uses := a.validUses(e)
		if len(uses) == 0 {
			continue
		}
		onlySelf := true
		for _, u := range uses {
			if !u.SelfPackage || u.Kind == "directive" || u.Kind == "iface" {
				onlySelf = false
				break
			}
		}
		if !onlySelf || a.suppressedAt(e.File, e.Line, "can-be-unexported") {
			continue
		}
		r.Findings = append(r.Findings, &report.Finding{
			Kind: "can-be-unexported", Rule: rule,
			Path: ff.Rel, Line: e.Line, Col: e.Col,
			Message:  fmt.Sprintf("Exported %s %q is only referenced within package %s and can be unexported", labelOfKind(string(e.Kind)), e.Name, e.PkgName),
			Severity: sev,
			ID:       DeadFindingID("can-be-unexported", ff.Rel, e),
			Extra:    entityExtra(e),
		})
	}
}

func (a *Analysis) isPublicPackage(pkgPath, rel string) bool {
	for _, p := range a.Cfg.PublicPackages {
		if p == pkgPath || config.MatchPath(p, pkgPath) || config.MatchPath(p, rel) {
			return true
		}
	}
	return false
}

// runUnusedInterfaceMethods reports explicit methods on live interfaces that
// have zero call sites across the project.
func (r *Result) runUnusedInterfaceMethods(a *Analysis, live map[facts.Key]bool, entries map[string]bool) {
	const rule = "unused-interface-methods"
	if !a.Cfg.RuleEnabled(rule) {
		return
	}
	for _, e := range sortedEntities(a.Proj) {
		if e.Kind != facts.KindInterface || e.Local || !live[e.Key] {
			continue
		}
		if e.TestFile && a.Opts.Production {
			continue
		}
		if e.Exported && e.PkgName != "main" && entries[e.PkgPath] && !a.Opts.IncludeEntryExports {
			continue
		}
		ff := a.Proj.Files[e.File]
		if ff == nil || a.IgnoreFindings(ff.Rel) || (e.Exported && a.isPublicPackage(e.PkgPath, ff.Rel)) {
			continue
		}
		for _, mKey := range a.Proj.InterfaceMethods[e.Key] {
			me := a.Proj.Entities[mKey]
			if me == nil {
				continue
			}
			hasCall := false
			for _, u := range a.Proj.Uses[mKey] {
				if u.Kind == "iface" {
					continue
				}
				if a.Opts.Production && u.FromTest {
					continue
				}
				if a.ignoreUseSite(u.File) {
					continue
				}
				hasCall = true
				break
			}
			if hasCall {
				continue
			}
			mff := a.Proj.Files[me.File]
			if mff == nil || a.IgnoreFindings(mff.Rel) {
				continue
			}
			sev := a.Cfg.RuleSeverity(rule, mff.Rel)
			if sev == config.Off || a.suppressedAt(me.File, me.Line, "unused-interface-method") {
				continue
			}
			r.Findings = append(r.Findings, &report.Finding{
				Kind: "unused-interface-method", Rule: rule,
				Path: mff.Rel, Line: me.Line, Col: me.Col,
				Message:  fmt.Sprintf("Interface method %s.%s is never called", e.Name, me.Name),
				Severity: sev,
				ID:       DeadFindingID("unused-interface-method", mff.Rel, me),
				Extra:    entityExtra(me),
			})
		}
	}
}

// runUnusedParamsAndReceivers reports unused function/method parameters and
// unused method receivers on live functions and methods.
func (r *Result) runUnusedParamsAndReceivers(a *Analysis, live map[facts.Key]bool) {
	wantParams := a.Cfg.RuleEnabled("unused-parameters")
	wantRecv := a.Cfg.RuleEnabled("unused-receivers")
	if !wantParams && !wantRecv {
		return
	}
	for _, e := range sortedEntities(a.Proj) {
		if (e.Kind != facts.KindFunc && e.Kind != facts.KindMethod) || e.Func == nil || e.Local || e.InterfaceMethod || !live[e.Key] {
			continue
		}
		if e.TestFile && a.Opts.Production {
			continue
		}
		ff := a.Proj.Files[e.File]
		if ff == nil || a.IgnoreFindings(ff.Rel) {
			continue
		}
		hasContractUse := false
		for _, u := range a.Proj.Uses[e.Key] {
			if u.Kind == "iface" || u.Kind == "directive" {
				hasContractUse = true
				break
			}
		}
		if wantParams && !hasContractUse && len(e.Func.UnusedParams) > 0 {
			sev := a.Cfg.RuleSeverity("unused-parameters", ff.Rel)
			if sev != config.Off {
				for _, p := range e.Func.UnusedParams {
					if a.suppressedAt(e.File, p.Line, "unused-parameter") || a.suppressedAt(e.File, e.Line, "unused-parameter") {
						continue
					}
					r.Findings = append(r.Findings, &report.Finding{
						Kind: "unused-parameter", Rule: "unused-parameters",
						Path: ff.Rel, Line: p.Line, Col: p.Col,
						Message:  fmt.Sprintf("Parameter %q of %s is never used", p.Name, qualified(e)),
						Severity: sev,
						ID:       report.Fingerprint("unused-parameter", ff.Rel, qualified(e), p.Name),
						Extra: map[string]any{
							"symbol":   p.Name,
							"function": qualified(e),
						},
					})
				}
			}
		}
		if wantRecv && e.Func.UnusedReceiver != nil {
			p := e.Func.UnusedReceiver
			sev := a.Cfg.RuleSeverity("unused-receivers", ff.Rel)
			if sev != config.Off && !a.suppressedAt(e.File, p.Line, "unused-receiver") && !a.suppressedAt(e.File, e.Line, "unused-receiver") {
				r.Findings = append(r.Findings, &report.Finding{
					Kind: "unused-receiver", Rule: "unused-receivers",
					Path: ff.Rel, Line: p.Line, Col: p.Col,
					Message:  fmt.Sprintf("Method receiver %q on %s.%s is never used", p.Name, e.Recv, e.Name),
					Severity: sev,
					ID:       report.Fingerprint("unused-receiver", ff.Rel, e.Recv, e.Name, p.Name),
					Extra: map[string]any{
						"symbol":   p.Name,
						"receiver": e.Recv,
						"method":   e.Name,
					},
				})
			}
		}
	}
}

// runStructPadding reports structs whose 64-bit memory layout can be shrunk by
// reordering fields by alignment.
func (r *Result) runStructPadding(a *Analysis, live map[facts.Key]bool) {
	const rule = "struct-padding"
	if !a.Cfg.RuleEnabled(rule) {
		return
	}
	for _, e := range sortedEntities(a.Proj) {
		if e.Kind != facts.KindType || e.Local || !live[e.Key] {
			continue
		}
		if e.TestFile && a.Opts.Production {
			continue
		}
		if e.OptimalStructSize <= 0 || e.StructSize <= e.OptimalStructSize {
			continue
		}
		ff := a.Proj.Files[e.File]
		if ff == nil || a.IgnoreFindings(ff.Rel) {
			continue
		}
		sev := a.Cfg.RuleSeverity(rule, ff.Rel)
		if sev == config.Off || a.suppressedAt(e.File, e.Line, "struct-padding") {
			continue
		}
		saved := e.StructSize - e.OptimalStructSize
		r.Findings = append(r.Findings, &report.Finding{
			Kind: "struct-padding", Rule: rule,
			Path: ff.Rel, Line: e.Line, Col: e.Col,
			Message:  fmt.Sprintf("Struct %q uses %d bytes but reordering fields saves %d bytes (%d bytes optimal)", e.Name, e.StructSize, saved, e.OptimalStructSize),
			Severity: sev,
			ID:       DeadFindingID("struct-padding", ff.Rel, e),
			Extra: map[string]any{
				"symbol":        e.Name,
				"size_bytes":    e.StructSize,
				"optimal_bytes": e.OptimalStructSize,
				"wasted_bytes":  saved,
			},
		})
	}
}

// runGoIssues emits Go runtime hazard and security findings collected per file.
func (r *Result) runGoIssues(a *Analysis) {
	for _, ff := range sortedFiles(a.Proj) {
		if ff.InTest && a.Opts.Production {
			continue
		}
		if a.Proj.SkippedFiles[ff.Rel] || a.IgnoreFindings(ff.Rel) {
			continue
		}
		for _, iss := range ff.GoIssues {
			if ff.InTest && (iss.Kind == "secret-in-code" || iss.Kind == "security-sink") {
				continue
			}
			sev := a.Cfg.RuleSeverity(iss.Rule, ff.Rel)
			if sev == config.Off || a.suppressedAt(ff.Path, iss.Line, iss.Kind) {
				continue
			}
			extra := map[string]any{}
			if iss.Symbol != "" {
				extra["symbol"] = iss.Symbol
			}
			for k, v := range iss.Extra {
				extra[k] = v
			}
			r.Findings = append(r.Findings, &report.Finding{
				Kind: iss.Kind, Rule: iss.Rule,
				Path: ff.Rel, Line: iss.Line, Col: iss.Col,
				Message:  iss.Message,
				Severity: sev,
				ID:       report.Fingerprint(iss.Kind, ff.Rel, iss.Symbol, fmt.Sprint(iss.Line)),
				Extra:    extra,
			})
		}
	}
}

// runFeatureFlags emits feature-flag findings matching configured SDK patterns
// and environment variable prefixes.
func (r *Result) runFeatureFlags(a *Analysis) {
	wantFlags := a.Cfg.RuleEnabled("feature-flags")
	wantStale := a.Cfg.RuleEnabled("stale-feature-flags")
	if !wantFlags && !wantStale {
		return
	}
	envPrefixes := a.Cfg.Flags.EnvPrefixes
	if len(envPrefixes) == 0 {
		envPrefixes = []string{"FEATURE_", "FF_", "FLAG_"}
	}
	sdkPatterns := a.Cfg.Flags.SDKPatterns
	if len(sdkPatterns) == 0 {
		sdkPatterns = []config.SDKPattern{
			{Function: "IsEnabled"},
			{Function: "FeatureEnabled"},
			{Function: "GetBoolFlag"},
			{Function: "BoolVariation"},
			{Function: "Variation"},
		}
	}
	for _, ff := range sortedFiles(a.Proj) {
		if (ff.InTest && a.Opts.Production) || a.Proj.SkippedFiles[ff.Rel] || a.IgnoreFindings(ff.Rel) {
			continue
		}
		for _, fc := range ff.FlagCalls {
			matched := false
			flagName := fc.FlagName
			callKind := "sdk"
			if fc.IsEnv {
				callKind = "env"
				for _, p := range envPrefixes {
					if strings.HasPrefix(flagName, p) || config.MatchName(p, flagName) {
						matched = true
						break
					}
				}
			} else {
				for _, p := range sdkPatterns {
					fn := p.Function
					if fn == "" {
						continue
					}
					if fc.FuncName == fn || strings.HasSuffix(fc.FuncName, "."+fn) || config.MatchName(fn, fc.FuncName) {
						if p.NameArg >= 0 && p.NameArg < len(fc.Args) && fc.Args[p.NameArg] != "" {
							flagName = fc.Args[p.NameArg]
						}
						matched = flagName != ""
						break
					}
				}
			}
			if !matched {
				continue
			}
			rule := "feature-flags"
			kind := "feature-flag"
			if fc.Stale && wantStale {
				rule = "stale-feature-flags"
				kind = "stale-feature-flag"
			} else if !wantFlags && wantStale {
				rule = "stale-feature-flags"
				kind = "stale-feature-flag"
			}
			sev := a.Cfg.RuleSeverity(rule, ff.Rel)
			if sev == config.Off || a.suppressedAt(ff.Path, fc.Line, kind) {
				continue
			}
			r.Findings = append(r.Findings, &report.Finding{
				Kind: kind, Rule: rule,
				Path: ff.Rel, Line: fc.Line, Col: fc.Col,
				Message:  fmt.Sprintf("Feature flag %q checked via %s", flagName, fc.FuncName),
				Severity: sev,
				ID:       report.Fingerprint(kind, ff.Rel, flagName, fmt.Sprint(fc.Line)),
				Extra: map[string]any{
					"symbol": flagName,
					"flag":   flagName,
					"kind":   callKind,
					"call":   fc.FuncName,
				},
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Suppression hygiene.
// ---------------------------------------------------------------------------

func (r *Result) runSuppressions(a *Analysis) {
	if a.Cfg.RuleSeverity("stale-suppressions", "") != config.Off {
		for _, ff := range sortedFiles(a.Proj) {
			if ff.InTest && a.Opts.Production {
				continue
			}
			for _, s := range ff.Suppressions {
				if s.Used || s.Kind == "end" {
					continue
				}
				r.Stale++
				r.Findings = append(r.Findings, &report.Finding{
					Kind: "stale-suppression", Rule: "stale-suppressions", Path: ff.Rel,
					Line: s.Line, Col: 0,
					Message:  "This goose-ignore comment no longer matches any issue. Remove it.",
					Severity: a.Cfg.RuleSeverity("stale-suppressions", ff.Rel),
					ID:       report.Fingerprint("stale-suppression", ff.Rel, s.Raw),
					Extra:    map[string]any{"comment": s.Raw},
					Actions: []report.Action{{
						Type: "remove-suppression", Description: "Delete the stale comment.",
						AutoFixable: true,
					}},
				})
			}
		}
	}
	if a.Cfg.RuleSeverity("require-suppression-reason", "") != config.Off {
		for _, ff := range sortedFiles(a.Proj) {
			for _, s := range ff.Suppressions {
				if s.Kind == "end" || s.HasReason {
					continue
				}
				r.Findings = append(r.Findings, &report.Finding{
					Kind: "missing-suppression-reason", Rule: "require-suppression-reason",
					Path: ff.Rel, Line: s.Line, Col: 0,
					Message:  "Every goose-ignore comment must end with \" -- reason\".",
					Severity: a.Cfg.RuleSeverity("require-suppression-reason", ff.Rel),
					ID:       report.Fingerprint("missing-suppression-reason", ff.Rel, s.Raw),
					Extra:    map[string]any{"comment": s.Raw},
				})
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Suppression and ignore plumbing on Analysis.
// ---------------------------------------------------------------------------

// compileMatchers builds the ignoreFindings matcher once per run.
func (a *Analysis) compileMatchers() {
	if a.compiled {
		return
	}
	a.compiled = true
	m, err := glob.NewMatcher(a.Cfg.IgnoreFindings, glob.Options{})
	if err == nil {
		a.ignoreFindingsMatcher = *m
	}
}

// IgnoreFindings reports whether a path hides its findings.
func (a *Analysis) IgnoreFindings(rel string) bool {
	a.compileMatchers()
	if len(a.Cfg.IgnoreFindings) == 0 {
		return false
	}
	return a.ignoreFindingsMatcher.Match(rel)
}

func (a *Analysis) ignoreUseSite(absPath string) bool {
	return a.IgnoreFindings(a.relOf(absPath))
}

func (a *Analysis) relOf(absPath string) string {
	if ff := a.Proj.Files[absPath]; ff != nil {
		return ff.Rel
	}
	return filepath.ToSlash(absPath)
}

// IgnoreDependency reports whether a module name is on the ignore list.
func (a *Analysis) IgnoreDependency(pkg string) bool {
	for _, e := range a.Cfg.IgnoreDependencies {
		if e == pkg {
			return true
		}
		if strings.ContainsAny(e, "*?[{") && config.MatchName(e, pkg) {
			return true
		}
	}
	return false
}

// IgnoreSpecifier reports whether an import path is excluded from the
// unresolved-import rule.
func (a *Analysis) IgnoreSpecifier(spec string) bool {
	trimmed := strings.TrimPrefix(spec, "./")
	for _, p := range a.Cfg.IgnoreUnresolvedImports {
		pt := strings.TrimPrefix(p, "./")
		if pt == spec || pt == trimmed {
			return true
		}
		if strings.ContainsAny(pt, "*?[{") && config.MatchName(pt, spec) {
			return true
		}
	}
	return false
}

// suppressedAt reports whether a goose-ignore marker covers a position, and
// marks the marker used.
func (a *Analysis) suppressedAt(absPath string, line int, kind string) bool {
	if absPath == "" {
		return false
	}
	ff := a.Proj.Files[absPath]
	if ff == nil {
		return false
	}
	for _, s := range ff.Suppressions {
		if coversSuppression(ff, s, line, kind) {
			s.Used = true
			return true
		}
	}
	return false
}

func coversSuppression(ff *facts.FileFacts, s *facts.Suppression, line int, kind string) bool {
	if !suppressionTypeMatches(s, kind) {
		return false
	}
	switch s.Kind {
	case "file":
		return line == 0 || line >= s.Line
	case "next-line":
		return line == s.Line+1
	case "start":
		end := startEndLine(ff, s)
		return end >= 0 && line >= s.Line && line <= end
	}
	return false
}

func suppressionTypeMatches(s *facts.Suppression, kind string) bool {
	if len(s.Types) == 0 {
		return true
	}
	rule := report.RuleForKind(kind)
	plural := report.Plural(kind)
	for _, t := range s.Types {
		c := config.CanonicalRule(t)
		if c == rule || c == plural || t == kind || c == kind {
			return true
		}
	}
	return false
}

func startEndLine(ff *facts.FileFacts, start *facts.Suppression) int {
	best := -1
	for _, s := range ff.Suppressions {
		if s.Kind == "end" && s.Line > start.Line && (best == -1 || s.Line < best) {
			best = s.Line
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// Baselines.
// ---------------------------------------------------------------------------

// Baseline is the saved dead-code baseline document.
type Baseline struct {
	Kind         string         `json:"kind"`
	Version      string         `json:"version,omitempty"`
	SavedBy      string         `json:"saved_by,omitempty"`
	Entries      map[string]int `json:"entries"`
	InstallState string         `json:"install_state,omitempty"`
}

// LoadBaseline reads a baseline file.
func LoadBaseline(p string) (*Baseline, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("invalid baseline %s: %w", p, err)
	}
	if b.Entries == nil {
		b.Entries = map[string]int{}
	}
	return &b, nil
}

// SaveBaseline writes findings as a baseline document.
func SaveBaseline(p string, findings []*report.Finding, ver string) error {
	b := Baseline{Kind: "dead-code", Version: ver, SavedBy: "dead-code", Entries: map[string]int{}}
	for _, f := range findings {
		if f.Hidden {
			continue
		}
		b.Entries[BaselineKey(f)]++
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(data, '\n'), 0o644)
}

// BaselineKey builds the line-free identity key of a finding.
func BaselineKey(f *report.Finding) string {
	key := f.Kind + "|" + f.Path
	for _, field := range []string{"symbol", "package_name", "specifier", "comment", "receiver"} {
		if v, ok := f.Extra[field]; ok {
			key += "|" + fmt.Sprint(v)
		}
	}
	return key
}

// Staleness reports how much of a loaded baseline still matches.
type Staleness struct {
	BaselineEntries    int      `json:"baseline_entries"`
	MatchedEntries     int      `json:"matched_entries"`
	CurrentFindings    int      `json:"current_findings"`
	StaleKeys          []string `json:"-"`
	UnrecognisedFormat bool     `json:"unrecognised_format,omitempty"`
}

// GateTrips is what --fail-on-stale-baseline would decide.
func (s *Staleness) GateTrips() bool { return s.MatchedEntries < s.BaselineEntries }

// ApplyBaseline hides findings the baseline covers.
// SplitBaseline keeps only the findings the baseline does not cover, counting
// matches and leftovers; audit's per-analysis baselines use it without a
// staleness report.
func SplitBaseline(findings []*report.Finding, b *Baseline) (kept []*report.Finding, matched, total int) {
	entries := map[string]int{}
	for k, n := range b.Entries {
		entries[k] = n
	}
	total = len(b.Entries)
	for _, f := range findings {
		key := BaselineKey(f)
		if entries[key] > 0 {
			entries[key]--
			matched++
			continue
		}
		kept = append(kept, f)
	}
	return kept, matched, total
}

func ApplyBaseline(findings []*report.Finding, b *Baseline) ([]*report.Finding, *Staleness) {
	st := &Staleness{BaselineEntries: len(b.Entries)}
	if st.BaselineEntries == 0 && b.Kind != "" && b.Kind != "dead-code" {
		st.UnrecognisedFormat = true
	}
	counts := map[string]int{}
	for k, n := range b.Entries {
		counts[k] = n
	}
	var kept []*report.Finding
	for _, f := range findings {
		key := BaselineKey(f)
		if counts[key] > 0 {
			counts[key]--
			st.MatchedEntries++
			continue
		}
		kept = append(kept, f)
	}
	st.CurrentFindings = len(kept)
	for k, n := range counts {
		if n > 0 {
			st.StaleKeys = append(st.StaleKeys, k)
		}
	}
	sort.Strings(st.StaleKeys)
	return kept, st
}

// ---------------------------------------------------------------------------
// Trace.
// ---------------------------------------------------------------------------

// Trace explains why a symbol is used or unused, like fallow dead-code --trace.
// target is "path/to/file.go:Name" or "pkg/path:Name".
func Trace(a *Analysis, target string) string {
	prefix, name, ok := strings.Cut(target, ":")
	if !ok {
		return "usage: goose dead-code --trace <file.go:Symbol>"
	}
	var b strings.Builder
	matched := false
	for _, e := range sortedEntities(a.Proj) {
		if e.Name != name {
			continue
		}
		rel := a.relOf(e.File)
		if !strings.HasSuffix(rel, prefix) && e.PkgPath != prefix && !strings.HasSuffix(e.PkgPath, prefix) {
			continue
		}
		matched = true
		fmt.Fprintf(&b, "%s %s (%s:%d)\n", e.Kind, qualified(e), a.relOf(e.File), e.Line)
		uses := a.Proj.Uses[e.Key]
		if len(uses) == 0 {
			b.WriteString("  no recorded use — the symbol is dead\n")
			continue
		}
		for _, u := range uses {
			fmt.Fprintf(&b, "  used by %s:%d (kind=%s", a.relOf(u.File), u.Line, u.Kind)
			if u.SelfPackage {
				b.WriteString(", same package")
			} else {
				b.WriteString(", package " + u.PkgPath)
			}
			if u.FromTest {
				b.WriteString(", test file")
			}
			if insideOwnDecl(a, e, u) {
				b.WriteString(" — inside the declaration itself, does not count")
			}
			b.WriteString(")\n")
		}
		if iface := interfaceCreditOf(a, e); iface != "" {
			fmt.Fprintf(&b, "  kept alive as an implementation of %s\n", iface)
		}
	}
	if !matched {
		return "goose: no symbol " + name + " matched " + prefix
	}
	return b.String()
}

func qualified(e *facts.Entity) string {
	if e.Recv != "" {
		return e.Recv + "." + e.Name
	}
	return e.Name
}

// interfaceCreditOf names the used interface that kept a method alive.
func interfaceCreditOf(a *Analysis, e *facts.Entity) string {
	if e.Kind != facts.KindMethod {
		return ""
	}
	for _, u := range a.Proj.Uses[e.Key] {
		if u.Kind == "iface" {
			// The container name is the implementing type; the interface is
			// found by scanning satisfaction. Cheap enough for a trace.
			for ifaceKey, methods := range a.Proj.InterfaceMethods {
				for _, mk := range methods {
					if mk != e.Key {
						continue
					}
					if a.Proj.InterfaceSatisfied[ifaceKey] {
						return ifaceKey.Name()
					}
				}
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

// IsStd reports whether an import path is in the Go standard library.
func IsStd(importPath string, std map[string]bool) bool {
	if len(std) > 0 {
		return std[importPath]
	}
	return IsGorootStd(importPath)
}

var (
	gorootMu        sync.RWMutex
	gorootCachedFor string
	gorootCachedOk  bool
	gorootCachedSrc string
)

func resolveGorootSrc() string {
	envGR := os.Getenv("GOROOT")
	gorootMu.RLock()
	if gorootCachedOk && gorootCachedFor == envGR {
		src := gorootCachedSrc
		gorootMu.RUnlock()
		return src
	}
	gorootMu.RUnlock()

	gr := envGR
	if gr == "" {
		gr = runtime.GOROOT()
	}
	if gr == "" {
		gr = build.Default.GOROOT
	}
	var src string
	if gr != "" {
		cand := filepath.Join(gr, "src")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			src = cand
		}
	}

	gorootMu.Lock()
	gorootCachedFor = envGR
	gorootCachedSrc = src
	gorootCachedOk = true
	gorootMu.Unlock()
	return src
}

// IsGorootStd checks whether importPath is a Go standard-library package
// using GOROOT/src without spawning a `go list std` subprocess.
func IsGorootStd(importPath string) bool {
	if importPath == "unsafe" || importPath == "builtin" || importPath == "C" {
		return true
	}
	head := importPath
	if i := strings.Index(importPath, "/"); i > 0 {
		head = importPath[:i]
	}
	if strings.Contains(head, ".") {
		return false
	}
	src := resolveGorootSrc()
	if src == "" {
		return true
	}
	rel := filepath.FromSlash(importPath)
	if st, err := os.Stat(filepath.Join(src, rel)); err == nil && st.IsDir() {
		return true
	}
	if st, err := os.Stat(filepath.Join(src, "vendor", rel)); err == nil && st.IsDir() {
		return true
	}
	return false
}

// sortedFiles returns file facts in deterministic order.
func sortedFiles(p *facts.Project) []*facts.FileFacts {
	out := make([]*facts.FileFacts, 0, len(p.Files))
	for _, ff := range p.Files {
		out = append(out, ff)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out
}

func sortedEntities(p *facts.Project) []*facts.Entity {
	out := make([]*facts.Entity, 0, len(p.Entities))
	for _, e := range p.Entities {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func fileByRel(a *Analysis, rel string) *facts.FileFacts {
	for _, ff := range a.Proj.Files {
		if ff.Rel == rel {
			return ff
		}
	}
	return nil
}

func locateGoModLine(dir, modulePath string) (int, int) {
	if dir == "" {
		return 1, 0
	}
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return 1, 0
	}
	for i, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, modulePath) {
			return i + 1, strings.Index(line, modulePath)
		}
	}
	return 1, 0
}
