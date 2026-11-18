// Package architecture implements the goose architecture analysis: import
// cycles, boundary violations (zone rules and coverage), and rule-pack
// policy violations, mirroring `fallow architecture`.
package architecture

import (
	"fmt"
	"go/ast"
	"strings"

	"goose/internal/config"
	"goose/internal/facts"
	"goose/internal/graph"
	"goose/internal/report"
)

// Options select which architecture groups run, matching the --cycles,
// --boundaries, and --policy flags. All false means run everything.
type Options struct {
	Cycles     bool
	Boundaries bool
	Policy     bool
	Production bool
	// SelectorsSet is true when any selector flag was passed.
	SelectorsSet bool
}

func (o Options) all() bool        { return !o.SelectorsSet }
func (o Options) wantCycles() bool { return o.all() || o.Cycles }
func (o Options) wantBoundaries() bool {
	return o.all() || o.Boundaries
}
func (o Options) wantPolicy() bool { return o.all() || o.Policy }

// Analysis runs the architecture checks over one loaded project.
type Analysis struct {
	Proj  *facts.Project
	Graph *graph.Graph
	Cfg   *config.Config
	// Syntax maps absolute file paths to their parsed trees, for call-level
	// policy rules.
	Syntax map[string]*ast.File
}

// Result is the outcome of one architecture run.
type Result struct {
	Findings []*report.Finding
	// Zones lists resolved zone names with their file counts, for list output.
	Zones []ZoneSummary
	// Diags carries config diagnostics (unknown preset, unreadable packs).
	Diags []report.Diag
}

// ZoneSummary is one boundary zone and the files classified into it.
type ZoneSummary struct {
	Name     string   `json:"name"`
	Patterns []string `json:"patterns"`
	Files    int      `json:"files"`
}

// BoundarySummary is the list view of the configured architecture zones.
type BoundarySummary struct {
	Configured bool               `json:"configured"`
	Preset     string             `json:"preset,omitempty"`
	Zones      []ZoneSummary      `json:"zones"`
	Rules      []BoundaryRuleView `json:"rules,omitempty"`
}

// BoundaryRuleView is one from→allow/deny rule for list output.
type BoundaryRuleView struct {
	From  string   `json:"from"`
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// SummarizeBoundaries resolves the zones and reports file counts per zone
// without running any violation check. Configured is false when neither a
// preset nor any zone is defined.
func (a *Analysis) SummarizeBoundaries() (*BoundarySummary, error) {
	out := &BoundarySummary{Preset: a.Cfg.Boundaries.Preset}
	if a.Cfg.Boundaries.Preset == "" && len(a.Cfg.Boundaries.Zones) == 0 {
		return out, nil
	}
	out.Configured = true
	zones, err := a.resolveZones()
	if err != nil {
		return nil, err
	}
	zc := map[string]int{}
	for _, ff := range a.sortedFiles() {
		if z := classify(zones, ff.Rel); z != "" {
			zc[z]++
		}
	}
	for _, z := range zones {
		out.Zones = append(out.Zones, ZoneSummary{Name: z.name, Patterns: z.patterns, Files: zc[z.name]})
	}
	for _, r := range a.effectiveRules(zones) {
		out.Rules = append(out.Rules, BoundaryRuleView{From: r.From, Allow: r.Allow, Deny: r.Deny})
	}
	return out, nil
}

// Run performs the requested groups and returns findings in report order.
func (a *Analysis) Run(o Options) (*Result, error) {
	res := &Result{}
	var zones []zone
	if a.Cfg.Boundaries.Preset != "" || len(a.Cfg.Boundaries.Zones) > 0 {
		var err error
		zones, err = a.resolveZones()
		if err != nil {
			return nil, err
		}
	}
	classified := map[string]string{} // rel path -> zone name
	if len(zones) > 0 {
		zc := map[string]int{}
		for _, ff := range a.sortedFiles() {
			if ff.InTest && o.Production {
				continue
			}
			if z := classify(zones, ff.Rel); z != "" {
				classified[ff.Rel] = z
				zc[z]++
			}
		}
		for _, z := range zones {
			res.Zones = append(res.Zones, ZoneSummary{Name: z.name, Patterns: z.patterns, Files: zc[z.name]})
		}
	}

	if o.wantCycles() {
		res.Findings = append(res.Findings, a.cycles()...)
	}
	if o.wantBoundaries() {
		res.Findings = append(res.Findings, a.boundaryViolations(classified)...)
		if a.Cfg.Boundaries.Coverage.RequireAllFiles {
			res.Findings = append(res.Findings, a.boundaryCoverage(classified, o.Production)...)
		}
		res.Findings = append(res.Findings, a.deepImports(o.Production)...)
	}
	if o.wantPolicy() {
		fs, diags, err := a.policyViolations(classified, o.Production)
		if err != nil {
			return nil, err
		}
		res.Findings = append(res.Findings, fs...)
		res.Diags = append(res.Diags, diags...)
	}
	// Suppressions remove covered findings and mark the markers used.
	var kept []*report.Finding
	for _, f := range res.Findings {
		if a.suppressedAt(a.absOf(f.Path), f.Line, f.Kind) {
			continue
		}
		kept = append(kept, f)
	}
	res.Findings = kept
	report.SortFindings(res.Findings)
	return res, nil
}

// ---------------------------------------------------------------------------
// Cycles.
// ---------------------------------------------------------------------------

// cycles reports one circular-dependency finding per import cycle, anchored
// at the import line of the first hop that closes it.
func (a *Analysis) cycles() []*report.Finding {
	sev := a.Cfg.RuleSeverity("circular-dependencies", "")
	if sev == config.Off {
		return nil
	}
	var out []*report.Finding
	for _, cyc := range a.Graph.Cycles() {
		if len(cyc) < 2 {
			continue
		}
		var hops []hop
		var files []string
		for i, pkg := range cyc {
			next := cyc[(i+1)%len(cyc)]
			hops = append(hops, a.exampleImport(pkg, next))
			if ff := a.pkgFile(pkg); ff != "" {
				files = append(files, ff)
			}
		}
		pk := hop{}
		for _, h := range hops {
			if h.File != "" {
				pk = h
				break
			}
		}
		id := report.Fingerprint("circular-dependency", strings.Join(cyc, ","))
		f := &report.Finding{
			Kind: "circular-dependency", Rule: "circular-dependencies",
			Path: pk.File, Line: pk.Line,
			Message:  fmt.Sprintf("Import cycle across %d packages: %s", len(cyc), strings.Join(cyc, " → ")),
			Severity: sev,
			ID:       id,
			Extra: map[string]any{
				"packages": cyc, "files": files, "length": len(cyc),
			},
			Actions: []report.Action{{
				Type: "break-cycle", AutoFixable: false,
				Description: "Move the shared code into a package both sides import.",
			}},
		}
		out = append(out, f)
	}
	return out
}

// hop is one edge of a cycle: where in the source it happens.
type hop struct {
	File string
	Line int
}

// exampleImport finds one import declaration in pkg that pulls in dep.
func (a *Analysis) exampleImport(pkg, dep string) hop {
	for _, ff := range a.sortedFiles() {
		if ff.PkgPath != pkg || ff.InTest {
			continue
		}
		for _, imp := range ff.Imports {
			if imp.Path == dep {
				return hop{File: ff.Rel, Line: imp.Line}
			}
		}
	}
	return hop{}
}

// suppressedAt reports whether a goose-ignore marker covers a position, and
// marks the marker used. Same semantics as the dead-code pass.
func (a *Analysis) suppressedAt(absPath string, line int, kind string) bool {
	if absPath == "" {
		return false
	}
	ff := a.Proj.Files[absPath]
	if ff == nil {
		return false
	}
	rule := report.RuleForKind(kind)
	for _, s := range ff.Suppressions {
		covers := false
		switch s.Kind {
		case "file":
			covers = line == 0 || line >= s.Line
		case "next-line":
			covers = line == s.Line+1
		case "start":
			end := -1
			for _, e := range ff.Suppressions {
				if e.Kind == "end" && e.Line > s.Line && (end == -1 || e.Line < end) {
					end = e.Line
				}
			}
			covers = end >= 0 && line >= s.Line && line <= end
		}
		if !covers {
			continue
		}
		if !kindMatches(s, kind, rule) {
			continue
		}
		s.Used = true
		return true
	}
	return false
}

func kindMatches(s *facts.Suppression, kind, rule string) bool {
	if len(s.Types) == 0 {
		return true
	}
	plural := report.Plural(kind)
	for _, t := range s.Types {
		c := config.CanonicalRule(t)
		if c == rule || c == plural || t == kind || c == kind {
			return true
		}
	}
	return false
}

// pkgFile returns the first production file of a package, module-relative.
func (a *Analysis) pkgFile(pkg string) string {
	for _, ff := range a.sortedFiles() {
		if ff.PkgPath == pkg && !ff.InTest {
			return ff.Rel
		}
	}
	return ""
}
