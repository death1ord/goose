package report

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"goose/internal/config"
	"goose/internal/health"
	"goose/internal/version"
)

// HealthView carries what the health renderers need beyond the analysis.
type HealthView struct {
	Res      *health.Result
	Cfg      *config.Config
	Sections HealthSections
	Top      int
	// Gaps carries the --coverage-gaps scan result when it ran.
	Gaps        *health.CoverageGaps
	Sort        string // cyclomatic | cognitive | lines | severity
	Colors      bool
	FailOnIssue bool
	Explain     bool
	MinSeverity string // critical | high | moderate | ""
	MinScore    float64
	MinSet      bool // true when an explicit --min-score gate is active
	// Trend carries the --trend comparison against a saved snapshot.
	Trend *health.Trend
	// Lean opts into the --format json --lean profile: empty arrays drop
	// out and the health tables cap at TableCap rows (--full-tables, or a
	// --top N below the default, keeps more).
	Lean       bool
	TableCap   int
	FullTables bool
	// TrendBaseline is the raw baseline when a trend was requested; the
	// grouped renderers use it for per-group trend_status.
	TrendBaseline *health.TrendBaseline
}

// HealthSections records which sections the run produced.
type HealthSections struct {
	Complexity   bool
	LargeFuncs   bool
	FileScores   bool
	Hotspots     bool
	Targets      bool
	Score        bool
	CoverageGaps bool
}

// dimensionRules maps an exceeded dimension to its canonical rule name.
var dimensionRules = map[string]string{
	"cyclomatic": "complexity-cyclomatic",
	"cognitive":  "complexity-cognitive",
	"crap":       "complexity-crap",
	"file_lines": "complexity-file-lines",
}

// HealthFindingSeverity resolves the effective rule severity of a finding:
// the most severe rule among the dimensions it breached.
func HealthFindingSeverity(cfg *config.Config, f health.Finding) config.Severity {
	sev := config.Off
	rank := map[config.Severity]int{"off": 0, "warn": 1, "error": 2}
	for _, dim := range f.Exceeded {
		rule, ok := dimensionRules[dim]
		if !ok {
			continue
		}
		s := cfg.RuleSeverity(rule, f.Path)
		if rank[s] > rank[sev] {
			sev = s
		}
	}
	if len(f.Exceeded) == 0 {
		sev = cfg.RuleSeverity("complexity-cyclomatic", f.Path)
	}
	return sev
}

// HealthDoc converts the analysis into a Doc for the shared machine formats
// (sarif, codeclimate, markdown, annotations). Sections the run skipped are
// absent.
func HealthDoc(v HealthView) *Doc {
	d := NewDoc("health")
	d.Envelope["schema_version"] = version.HealthSchemaVersion
	d.Envelope["kind"] = "health"
	d.ElapsedMS = v.Res.ElapsedMS
	for _, f := range sortedHealthFindings(v) {
		sev := HealthFindingSeverity(v.Cfg, f)
		if v.FailOnIssue && sev == config.Warn {
			sev = config.Error
		}
		if sev == config.Off {
			continue
		}
		msg := healthFindingMessage(f)
		kind := "complexity-finding"
		if f.Name == "<file>" {
			kind = "large-file"
		}
		d.Findings = append(d.Findings, &Finding{
			Kind: kind, Rule: "complexity-cyclomatic",
			Path: f.Path, Line: f.Line, Col: f.Col,
			Message:  msg,
			Severity: sev,
			ID:       Fingerprint(kind, f.Path, f.Name),
			Extra: map[string]any{
				"name": f.Name, "cyclomatic": f.Cyclomatic, "cognitive": f.Cognitive,
				"lines": f.Lines, "exceeded": f.Exceeded, "band": f.Band,
			},
		})
	}
	if v.Gaps != nil {
		for _, uf := range v.Gaps.Files {
			sev := v.Cfg.RuleSeverity("coverage-gaps", uf.Path)
			if sev == config.Off {
				continue
			}
			d.Findings = append(d.Findings, &Finding{
				Kind: "coverage-gap", Rule: "coverage-gaps",
				Path:     uf.Path,
				Message:  fmt.Sprintf("File is runtime-reachable but has no test dependency path (%d value exports)", uf.ValueExportCount),
				Severity: sev,
				ID:       Fingerprint("coverage-gap", uf.Path),
				Extra:    map[string]any{"value_export_count": uf.ValueExportCount},
			})
		}
		for _, ue := range v.Gaps.Exports {
			sev := v.Cfg.RuleSeverity("coverage-gaps", ue.Path)
			if sev == config.Off {
				continue
			}
			d.Findings = append(d.Findings, &Finding{
				Kind: "coverage-gap-export", Rule: "coverage-gaps",
				Path: ue.Path, Line: ue.Line, Col: ue.Col,
				Message:  fmt.Sprintf("Export %s is runtime-reachable but no test references it", ue.ExportName),
				Severity: sev,
				ID:       Fingerprint("coverage-gap-export", ue.Path, ue.ExportName),
				Extra:    map[string]any{"export_name": ue.ExportName},
			})
		}
	}
	return d
}

func healthFindingMessage(f health.Finding) string {
	if f.Name == "<file>" {
		return fmt.Sprintf("File has %d lines, above the ceiling", f.Lines)
	}
	var parts []string
	for _, dim := range f.Exceeded {
		switch dim {
		case "cyclomatic":
			parts = append(parts, fmt.Sprintf("cyclomatic complexity %d", f.Cyclomatic))
		case "cognitive":
			parts = append(parts, fmt.Sprintf("cognitive complexity %d", f.Cognitive))
		case "crap":
			parts = append(parts, fmt.Sprintf("CRAP score %.1f", f.Crap))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "complexity above threshold")
	}
	return fmt.Sprintf("Function '%s' has %s", f.Name, strings.Join(parts, " and "))
}

// sortedHealthFindings applies --sort and --top for presentation.
func sortedHealthFindings(v HealthView) []health.Finding {
	fs := append([]health.Finding(nil), v.Res.Findings...)
	bandRank := map[string]float64{"critical": 3, "high": 2, "moderate": 1}
	key := func(f health.Finding) float64 {
		switch v.Sort {
		case "cognitive":
			return float64(f.Cognitive)
		case "lines":
			return float64(f.Lines)
		case "severity":
			return bandRank[f.Band]
		}
		return float64(f.Cyclomatic)
	}
	sort.SliceStable(fs, func(i, j int) bool {
		ki, kj := key(fs[i]), key(fs[j])
		if ki != kj {
			return ki > kj
		}
		if fs[i].Path != fs[j].Path {
			return fs[i].Path < fs[j].Path
		}
		return fs[i].Line < fs[j].Line
	})
	if v.Top > 0 && len(fs) > v.Top {
		fs = fs[:v.Top]
	}
	return fs
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

// HealthJSON renders the health JSON envelope: summary, findings,
// large_functions, file_scores, hotspots, targets, health_score, vital_signs.
// Only sections the run produced are present.
func HealthJSON(v HealthView) string {
	res := v.Res
	root := map[string]any{
		"kind":           "health",
		"schema_version": version.HealthSchemaVersion,
		"version":        version.Version,
	}
	if res.ElapsedMS > 0 {
		root["elapsed_ms"] = res.ElapsedMS
	}
	root["summary"] = healthProjectSummary(v, res)
	if v.Lean {
		root["profile"] = "lean"
	}
	leanCap := 0
	if v.Lean && !v.FullTables {
		leanCap = v.TableCap
		if leanCap <= 0 {
			leanCap = 10
		}
	}

	if v.Sections.Complexity {
		fs := make([]any, 0, len(res.Findings))
		for _, f := range sortedHealthFindings(v) {
			if f.Name == "<file>" {
				continue
			}
			m := map[string]any{
				"path": f.Path, "name": f.Name, "line": f.Line, "col": f.Col,
				"cyclomatic": f.Cyclomatic, "cognitive": f.Cognitive,
				"line_count": f.Lines, "exceeded": f.Exceeded,
				"severity": f.Band,
			}
			if f.Crap > 0 {
				m["crap"] = f.Crap
			}
			fs = append(fs, m)
		}
		root["findings"] = fs
	}
	if v.Sections.LargeFuncs && len(res.LargeFuncs) > 0 {
		lf := make([]any, 0, len(res.LargeFuncs))
		for _, f := range res.LargeFuncs {
			lf = append(lf, map[string]any{
				"path": f.Path, "name": f.Name, "line": f.Line, "cognitive": f.Cognitive,
				"cyclomatic": f.Cyclomatic, "line_count": f.Lines,
			})
		}
		root["large_functions"] = lf
	}
	if v.Sections.FileScores && len(res.FileScores) > 0 {
		scores := make([]any, 0, len(res.FileScores))
		for _, fs := range res.FileScores {
			scores = append(scores, map[string]any{
				"path": fs.Path, "fan_in": fs.FanIn, "fan_out": fs.FanOut,
				"dead_code_ratio":       fs.DeadCodeRatio,
				"complexity_density":    fs.ComplexityDensity,
				"maintainability_index": fs.Maintainability,
				"total_cyclomatic":      fs.TotalCyclomatic,
				"total_cognitive":       fs.TotalCognitive,
				"function_count":        fs.FuncCount,
				"lines":                 fs.LOC,
				"crap_max":              fs.CrapMax,
				"crap_above_threshold":  fs.CrapAbove,
			})
		}
		root["file_scores"] = scores
		root["vital_signs"] = vitalSignsJSON(res)
	}
	if v.Sections.Hotspots && len(res.Hotspots) > 0 {
		hs := make([]any, 0, len(res.Hotspots))
		for _, h := range res.Hotspots {
			m := map[string]any{
				"path": h.Path, "score": h.Score, "commits": h.Commits,
				"weighted_commits": h.WeightedCommits,
				"lines_added":      h.LinesAdded, "lines_deleted": h.LinesDeleted,
				"complexity_density": h.Density, "fan_in": h.FanIn, "trend": h.Trend,
			}
			if h.IsTestPath {
				m["is_test_path"] = true
			}
			hs = append(hs, m)
		}
		root["hotspots"] = hs
		root["hotspot_summary"] = map[string]any{
			"since":          res.ChurnSince,
			"min_commits":    res.ChurnMinCommits,
			"files_analyzed": len(res.Hotspots),
			"shallow_clone":  res.ChurnShallow,
		}
	}
	if v.Sections.Targets && len(res.Targets) > 0 {
		tg := make([]any, 0, len(res.Targets))
		for _, t := range res.Targets {
			factors := make([]any, 0, len(t.Factors))
			for _, f := range t.Factors {
				factors = append(factors, map[string]any{
					"metric": f.Metric, "value": f.Value,
					"threshold": f.Threshold, "detail": f.Detail,
				})
			}
			tg = append(tg, map[string]any{
				"path": t.Path, "priority": t.Priority, "efficiency": t.Efficiency,
				"recommendation": t.Recommendation, "category": t.Category,
				"effort": t.Effort, "confidence": t.Confidence, "factors": factors,
			})
		}
		root["targets"] = tg
	}
	if v.Sections.Score {
		scoreObj := map[string]any{
			"formula_version": res.Score.FormulaVersion,
			"score":           res.Score.Score,
			"grade":           res.Score.Grade,
			"penalties":       res.Score.Penalties,
		}
		root["health_score"] = scoreObj
	}
	if v.Gaps != nil {
		root["coverage_gaps"] = v.Gaps
	}
	if v.Trend != nil {
		root["health_trend"] = v.Trend
	}
	if v.Lean {
		applyHealthLeanProfile(root, leanCap)
	}
	s, err := JSONString(root)
	if err != nil {
		return "{}"
	}
	return s
}

// applyHealthLeanProfile rewrites the full envelope to fallow's lean shape:
// empty arrays drop out, the capped tables report how many rows they omit,
// and the health file/hotspot/target tables keep their headline rows.
func applyHealthLeanProfile(root map[string]any, cap int) {
	for key, mv := range map[string][2]string{
		"findings":        {"findings_omitted", "findings"},
		"large_functions": {"large_functions_omitted", "large_functions"},
		"file_scores":     {"file_scores_omitted", "file_scores"},
		"hotspots":        {"hotspots_omitted", "hotspots"},
		"targets":         {"targets_omitted", "targets"},
	} {
		arr, ok := root[key].([]any)
		if !ok {
			continue
		}
		if len(arr) == 0 {
			delete(root, key)
			continue
		}
		if cap > 0 && len(arr) > cap {
			root[mv[0]] = len(arr) - cap
			root[key] = arr[:cap]
		}
	}
}

// healthProjectSummary builds the project-level health summary block.
func healthProjectSummary(v HealthView, res *health.Result) map[string]any {
	summary := map[string]any{
		"files_analyzed":            res.FilesAnalyzed,
		"functions_analyzed":        res.FuncsAnalyzed,
		"functions_above_threshold": res.AboveCeiling,
		"max_cyclomatic_threshold":  v.Cfg.MaxCyclomatic(),
		"max_cognitive_threshold":   v.Cfg.MaxCognitive(),
	}
	if v.Sections.FileScores && res.FilesScored > 0 {
		summary["files_scored"] = res.FilesScored
		summary["average_maintainability"] = res.Vital.MaintainabilityAvg
		summary["coverage_model"] = res.Model
	}
	return summary
}

// patternsOut echoes the selector patterns the user gave.
func (gf *GroupFilter) patternsOut() []string {
	if gf == nil {
		return nil
	}
	return gf.patterns
}

func vitalSignsJSON(res *health.Result) map[string]any {
	v := res.Vital
	m := map[string]any{
		"avg_cyclomatic":          v.AvgCyclomatic,
		"critical_complexity_pct": v.CriticalComplexityPct,
		"maintainability_avg":     v.MaintainabilityAvg,
		"dead_file_pct":           v.DeadFilePercent,
		"dead_export_pct":         v.DeadExportPercent,
		"hotspot_count":           v.HotspotCount,
	}
	return m
}

// ---------------------------------------------------------------------------
// Human
// ---------------------------------------------------------------------------

// HealthHuman renders the terminal report with all requested sections.
func HealthHuman(v HealthView) string {
	var b strings.Builder
	dim := ""
	if v.Colors {
		dim = "\x1b[2m"
	}
	res := v.Res
	if v.Sections.Complexity {
		shown := sortedHealthFindings(v)
		var fn []health.Finding
		var fileLines []health.Finding
		for _, f := range shown {
			if f.Name == "<file>" {
				fileLines = append(fileLines, f)
			} else {
				fn = append(fn, f)
			}
		}
		if v.Top > 0 && len(fn) < len(res.Findings) {
			fmt.Fprintf(&b, "\n● High complexity functions (%d shown, %d total)\n", len(fn), res.AboveCeiling)
		} else {
			fmt.Fprintf(&b, "\n● High complexity functions (%d)\n", len(fn))
		}
		if res.Model == "static_estimated" {
			fmt.Fprintf(&b, "  %sCRAP scores are estimated from usage; pass --coverage <profile> for exact scores.%s\n", dim, reset(v.Colors))
		}
		mark := func(f health.Finding, dim string) string {
			for _, e := range f.Exceeded {
				if e == dim {
					return "!"
				}
			}
			return " "
		}
		cur := ""
		for _, f := range fn {
			if f.Path != cur {
				cur = f.Path
				fmt.Fprintf(&b, "  %s\n", f.Path)
			}
			fmt.Fprintf(&b, "    :%d %s\n", f.Line, f.Name)
			fmt.Fprintf(&b, "        %s%-3d cyclomatic  %s%-3d cognitive  %4d lines\n",
				mark(f, "cyclomatic"), f.Cyclomatic, mark(f, "cognitive"), f.Cognitive, f.Lines)
			if f.Crap > 0 {
				fmt.Fprintf(&b, "        %s%.1f CRAP\n", mark(f, "crap"), f.Crap)
			}
		}
		if len(fn) == 0 {
			fmt.Fprintf(&b, "  No functions above the ceilings\n")
		}
		if len(fn) > 0 && v.Explain {
			b.WriteString("  Functions exceeding cyclomatic, cognitive, or CRAP thresholds; ! marks the dimension that breached\n")
		}
		if len(fn) > 0 {
			b.WriteString("  " + healthDocLink("complexity-metrics") + "\n")
		}
		if len(fileLines) > 0 {
			fmt.Fprintf(&b, "\n● Large files (%d)\n", len(fileLines))
			for _, f := range fileLines {
				fmt.Fprintf(&b, "  %s  %d lines\n", f.Path, f.Lines)
			}
		}
	}
	if v.Sections.LargeFuncs && len(res.LargeFuncs) > 0 {
		fmt.Fprintf(&b, "\n● Large functions (%d)\n", len(res.LargeFuncs))
		for _, f := range res.LargeFuncs {
			fmt.Fprintf(&b, "  %s:%d  %s  %d lines\n", f.Path, f.Line, f.Name, f.Lines)
		}
	}
	if v.Sections.FileScores && len(res.FileScores) > 0 {
		fmt.Fprintf(&b, "\n● File health scores (%d files) · sorted by triage concern\n\n", len(res.FileScores))
		for _, fs := range res.FileScores {
			fmt.Fprintf(&b, "  %5.1f    %s  %s\n", fs.Maintainability, fs.Path, fs.Concern)
			fmt.Fprintf(&b, "          %4d LOC  %3d fan-in  %3d fan-out  %4.0f%% dead  %.2f density  %.1f\n",
				fs.LOC, fs.FanIn, fs.FanOut, fs.DeadCodeRatio*100, fs.ComplexityDensity, fs.CrapMax)
		}

	}
	if v.Sections.Hotspots {
		fmt.Fprintf(&b, "\n● Hotspots (%d files%s)\n", len(res.Hotspots), sinceSuffix(res))
		if len(res.Hotspots) == 0 && !res.ChurnAvailable {
			fmt.Fprintf(&b, "  %s hotspots skipped%s: no git repository found\n", dim, reset(v.Colors))
		}
		for _, h := range res.Hotspots {
			glyph := hotspotGlyph(h.Trend)
			testTag := ""
			if h.IsTestPath {
				testTag = " [test]"
			}
			fmt.Fprintf(&b, "  %5.1f %s %s%s\n", h.Score, glyph, h.Path, testTag)
			fmt.Fprintf(&b, "          %4d commits  %5d churn  %.2f density  %3d fan-in  %s %s\n",
				h.Commits, h.LinesAdded+h.LinesDeleted, h.Density, h.FanIn, glyph, strings.ToLower(h.Trend))
		}
	}
	if v.Sections.Targets && len(res.Targets) > 0 {
		fmt.Fprintf(&b, "\n● Refactoring targets (%d)\n\n", len(res.Targets))
		for _, t := range res.Targets {
			fmt.Fprintf(&b, "  %5.1f  %s  (%s · %s effort · %s confidence)\n", t.Priority, t.Path, t.Category, t.Effort, t.Confidence)
			fmt.Fprintf(&b, "          %s\n", t.Recommendation)
		}
	}
	if v.Sections.CoverageGaps && v.Gaps != nil {
		g := v.Gaps
		fmt.Fprintf(&b, "\n● Coverage gaps (%d untested files, %d untested exports, %.1f%% file coverage)\n", g.Summary.UntestedFiles, g.Summary.UntestedExports, g.Summary.FileCoveragePct)
		for _, uf := range g.Files {
			suffix := "s"
			if uf.ValueExportCount == 1 {
				suffix = ""
			}
			fmt.Fprintf(&b, "  %s (%d value export%s)\n", uf.Path, uf.ValueExportCount, suffix)
		}
		for _, ue := range g.Exports {
			fmt.Fprintf(&b, "  %s:%d  %s\n", ue.Path, ue.Line, ue.ExportName)
		}
		if len(g.Files) == 0 && len(g.Exports) == 0 {
			fmt.Fprintf(&b, "  %s No coverage gaps found in scope%s\n", dim, reset(v.Colors))
		}
		b.WriteString("  " + healthDocLink("coverage-gaps") + "\n")
	}
	if v.Sections.Score {
		s := res.Score
		fmt.Fprintf(&b, "\n● Health score: %s%.1f/100 (%s)%s\n", bold(v.Colors), s.Score, s.Grade, reset(v.Colors))
		keys := make([]string, 0, len(s.Penalties))
		for k := range s.Penalties {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  -%.1f  %s\n", s.Penalties[k], strings.ReplaceAll(k, "_", " "))
		}
	}
	if v.Trend != nil {
		b.WriteString(renderHealthTrend(v.Trend, v.Colors, v.Sections.Score, res.Score.FormulaVersion))
	}
	// Verdict line.
	mark := "✓"
	if HealthFailing(v) {
		mark = "✗"
	}
	secs := []string{}
	if v.Sections.Complexity {
		secs = append(secs, fmt.Sprintf("%d above threshold", res.AboveCeiling))
	}
	if v.Sections.Hotspots {
		secs = append(secs, fmt.Sprintf("%d hotspots", len(res.Hotspots)))
	}
	if v.Sections.Score {
		secs = append(secs, fmt.Sprintf("score %.1f", res.Score.Score))
	}
	fmt.Fprintf(&b, "\n%s %s · %d analyzed (%.2fs)\n", mark, strings.Join(secs, " · "),
		res.FilesAnalyzed, float64(res.ElapsedMS)/1000)
	return b.String()
}

func sinceSuffix(res *health.Result) string {
	if res.ChurnSince == "" || !res.ChurnAvailable {
		return ""
	}
	return ", since " + res.ChurnSince
}

func hotspotGlyph(trend string) string {
	switch trend {
	case "Accelerating":
		return "▲"
	case "Cooling":
		return "▼"
	}
	return "─"
}

// renderHealthTrend renders the fallow trend block: a header naming the
// snapshot with its overall arrow, then one row per metric with a signed
// delta and a direction word. Arrows: improving up, declining down, stable
// right.
func renderHealthTrend(t *health.Trend, colors bool, haveScore bool, curFormula int) string {
	var b strings.Builder
	label := trendWord(t.OverallDirection)
	colored := label
	switch t.OverallDirection {
	case "improving":
		colored = green(colors) + label + reset(colors)
	case "declining":
		colored = red(colors) + label + reset(colors)
	}
	arrow := trendArrow(t.OverallDirection)
	date := t.ComparedTo.Timestamp
	if len(date) >= 10 {
		date = date[:10]
	}
	sha := ""
	if t.ComparedTo.GitSHA != "" {
		sha = " · " + t.ComparedTo.GitSHA
	}
	fmt.Fprintf(&b, "\n● Trend: %s %s vs %s%s\n", arrow, colored, date, sha)
	if note := healthScoreComparisonNote(t, haveScore, curFormula); note != "" {
		fmt.Fprintf(&b, "  %s\n", note)
	}
	for _, m := range t.Metrics {
		fmt.Fprintf(&b, "  %-18s %8s  %-8s  %-9s %s %s\n",
			m.Label, fmtTrendVal(m.Previous, m.Unit), fmtTrendVal(m.Current, m.Unit),
			fmtTrendDelta(m.Delta, m.Unit), trendArrow(m.Direction), trendWord(m.Direction))
	}
	return b.String()
}

// healthScoreComparisonNote explains a dropped score delta, mirroring
// fallow: the stored and current formulas must both be known and equal.
func healthScoreComparisonNote(t *health.Trend, haveScore bool, curFormula int) string {
	hasScore := false
	for _, m := range t.Metrics {
		if m.Name == "score" {
			hasScore = true
		}
	}
	if hasScore || t.ComparedTo.Score == nil {
		return ""
	}
	if !haveScore || curFormula == 0 {
		return "score delta omitted: this run did not compute a health score"
	}
	if t.ComparedTo.ScoreFormulaVersion == 0 {
		return fmt.Sprintf("score delta omitted: the snapshot score predates formula tracking (this run uses formula %d)", curFormula)
	}
	return fmt.Sprintf("score delta omitted: snapshot formula %d, this run uses formula %d", t.ComparedTo.ScoreFormulaVersion, curFormula)
}

func fmtTrendVal(v float64, unit string) string {
	if unit == "%" {
		return fmt.Sprintf("%.1f%%", v)
	}
	if math.Abs(v-math.Round(v)) < 0.05 {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%.1f", v)
}

func fmtTrendDelta(v float64, unit string) string {
	if unit == "%" {
		return fmt.Sprintf("%+.1f%%", v)
	}
	if math.Abs(v-math.Round(v)) < 0.05 {
		return fmt.Sprintf("%+.0f", v)
	}
	return fmt.Sprintf("%+.1f", v)
}

func trendArrow(direction string) string {
	switch direction {
	case "improving":
		return "\u2191"
	case "declining":
		return "\u2193"
	}
	return "\u2192"
}

func trendWord(direction string) string {
	if direction == "" {
		return "stable"
	}
	return direction
}

// HealthFailing applies the fallow health exit rules: any error-severity
// finding fails; with --min-score only the score gates; --report-only never
// fails (the caller handles report-only).
func HealthFailing(v HealthView) bool {
	if v.MinSet {
		return v.Res.Score.Score < v.MinScore
	}
	for _, f := range v.Res.Findings {
		sev := HealthFindingSeverity(v.Cfg, f)
		if v.FailOnIssue && sev == config.Warn {
			sev = config.Error
		}
		if sev == config.Error && bandAtLeast(f.Band, v.MinSeverityRank()) {
			return true
		}
	}
	if v.Gaps != nil {
		for _, uf := range v.Gaps.Files {
			if v.Cfg.RuleSeverity("coverage-gaps", uf.Path) == config.Error {
				return true
			}
		}
		for _, ue := range v.Gaps.Exports {
			if v.Cfg.RuleSeverity("coverage-gaps", ue.Path) == config.Error {
				return true
			}
		}
	}
	return false
}

// MinSeverityRank converts --min-severity into a band rank; empty means all.
func (v HealthView) MinSeverityRank() int {
	switch v.MinSeverity {
	case "critical":
		return 3
	case "high":
		return 2
	}
	return 1
}

func bandAtLeast(band string, rank int) bool {
	switch band {
	case "critical":
		return rank <= 3
	case "high":
		return rank <= 2
	}
	return rank <= 1
}

// ---------------------------------------------------------------------------
// Compact + markdown reuse
// ---------------------------------------------------------------------------

// HealthCompact renders one line per complexity finding.
func HealthCompact(v HealthView) string {
	var b strings.Builder
	for _, f := range sortedHealthFindings(v) {
		if len(f.Exceeded) == 0 {
			continue
		}
		dims := strings.Join(f.Exceeded, " ")
		fmt.Fprintf(&b, "complexity:%s:%d:%s cyc=%d cog=%d lines=%d exceeded=%s\n",
			f.Path, f.Line, f.Name, f.Cyclomatic, f.Cognitive, f.Lines, dims)
	}
	if v.Gaps != nil {
		g := v.Gaps
		fmt.Fprintf(&b, "coverage-gap-summary:runtime_files=%d,covered_files=%d,file_coverage_pct=%.1f,untested_files=%d,untested_exports=%d\n",
			g.Summary.RuntimeFiles, g.Summary.CoveredFiles, g.Summary.FileCoveragePct, g.Summary.UntestedFiles, g.Summary.UntestedExports)
		for _, uf := range g.Files {
			fmt.Fprintf(&b, "untested-file:%s:value_exports=%d\n", uf.Path, uf.ValueExportCount)
		}
		for _, ue := range g.Exports {
			fmt.Fprintf(&b, "untested-export:%s:%d:%s\n", ue.Path, ue.Line, ue.ExportName)
		}
	}
	return b.String()
}

// HealthMarkdown renders the PR-friendly health summary.
func HealthMarkdown(v HealthView) string {
	res := v.Res
	var b strings.Builder
	if res.AboveCeiling == 0 {
		b.WriteString("## Goose Health: no functions above threshold\n")
	} else {
		fmt.Fprintf(&b, "## Goose Health: %d functions above threshold\n", res.AboveCeiling)
	}
	if v.Sections.Complexity && len(res.Findings) > 0 {
		fmt.Fprintf(&b, "\n### High complexity functions\n\n")
		b.WriteString("| File | Function | Line | Cyclomatic | Cognitive | Lines |\n")
		b.WriteString("|:-----|:---------|-----:|-----------:|----------:|------:|\n")
		for _, f := range sortedHealthFindings(v) {
			if f.Name == "<file>" {
				continue
			}
			fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d |\n",
				f.Path, f.Name, f.Line, f.Cyclomatic, f.Cognitive, f.Lines)
		}
	}
	if v.Sections.Score {
		fmt.Fprintf(&b, "\n**Health score: %.1f/100 (%s)**\n", res.Score.Score, res.Score.Grade)
	}
	if v.Gaps != nil {
		g := v.Gaps
		fmt.Fprintf(&b, "\n### Coverage Gaps\n\n*%d untested files · %d untested exports · %.1f%% file coverage*\n\n", g.Summary.UntestedFiles, g.Summary.UntestedExports, g.Summary.FileCoveragePct)
		if len(g.Files) == 0 && len(g.Exports) == 0 {
			b.WriteString("_No coverage gaps found in scope._\n")
		}
		for _, uf := range g.Files {
			fmt.Fprintf(&b, "- untested file: `%s` (%d value exports)\n", uf.Path, uf.ValueExportCount)
		}
		for _, ue := range g.Exports {
			fmt.Fprintf(&b, "- untested export: `%s` in `%s` (line %d)\n", ue.ExportName, ue.Path, ue.Line)
		}
	}
	return b.String()
}

func healthDocLink(sec string) string {
	return "https://github.com/rf/goose/blob/main/docs/explanations/health.md#" + sec
}

func green(on bool) string {
	if on {
		return "\x1b[32m"
	}
	return ""
}

func red(on bool) string {
	if on {
		return "\x1b[31m"
	}
	return ""
}

func bold(on bool) string {
	if on {
		return "\x1b[1m"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Grouped health (--group-by)
// ---------------------------------------------------------------------------

// HealthGroupedJSON renders the fallow grouped health envelope: the project
// body without the per-file arrays, plus grouped_by, total_issues (functions
// above threshold across groups), and groups[] where each bucket carries its
// own recomputed vital_signs and health_score. filter, when set, keeps only
// matching group keys; it reports the unmatched positive patterns.
func HealthGroupedJSON(v HealthView, project *health.Result, bodies map[string]*health.Result, ownership *Ownership, order []string, sectionOwners map[string][]string, filter *GroupFilter) (string, int, []string) {
	baseline := v.TrendBaseline
	total := 0
	kept := order
	var unmatched []string
	if filter != nil {
		var kept2 []string
		for _, k := range order {
			if filter.Keep(k) {
				kept2 = append(kept2, k)
			}
		}
		kept = kept2
		unmatched = filter.Unmatched(order)
	}
	for _, k := range kept {
		if r := bodies[k]; r != nil {
			total += r.AboveCeiling
		}
	}
	groups := make([]map[string]any, 0, len(kept))
	for _, k := range kept {
		r := bodies[k]
		if r == nil {
			continue
		}
		g := map[string]any{"key": k, "files_analyzed": r.FilesAnalyzed}
		if ownership.Mode == "section" {
			owners := sectionOwners[k]
			if owners == nil {
				owners = []string{}
			}
			g["owners"] = owners
		}
		if len(r.Findings) > 0 {
			g["functions_above_threshold"] = r.AboveCeiling
		}
		if v.Sections.Complexity {
			fs := make([]any, 0, len(r.Findings))
			for _, f := range r.Findings {
				if f.Name == "<file>" {
					continue
				}
				m := map[string]any{"path": f.Path, "name": f.Name, "line": f.Line, "col": f.Col,
					"cyclomatic": f.Cyclomatic, "cognitive": f.Cognitive, "line_count": f.Lines,
					"exceeded": f.Exceeded, "severity": f.Band}
				if f.Crap > 0 {
					m["crap"] = f.Crap
				}
				fs = append(fs, m)
			}
			g["findings"] = fs
			lf := make([]any, 0, len(r.LargeFuncs))
			for _, f := range r.LargeFuncs {
				lf = append(lf, map[string]any{"path": f.Path, "name": f.Name, "line": f.Line,
					"cognitive": f.Cognitive, "cyclomatic": f.Cyclomatic, "line_count": f.Lines})
			}
			if len(lf) > 0 {
				g["large_functions"] = lf
			}
		}
		if v.Sections.FileScores && len(r.FileScores) > 0 {
			scores := make([]any, 0, len(r.FileScores))
			for _, fs := range r.FileScores {
				scores = append(scores, map[string]any{"path": fs.Path, "fan_in": fs.FanIn, "fan_out": fs.FanOut,
					"dead_code_ratio": fs.DeadCodeRatio, "complexity_density": fs.ComplexityDensity,
					"maintainability_index": fs.Maintainability, "total_cyclomatic": fs.TotalCyclomatic,
					"total_cognitive": fs.TotalCognitive, "function_count": fs.FuncCount,
					"lines": fs.LOC, "crap_max": fs.CrapMax, "crap_above_threshold": fs.CrapAbove})
			}
			g["file_scores"] = scores
		}
		vital := map[string]any{}
		if v.Sections.Score {
			g["health_score"] = map[string]any{"formula_version": r.Score.FormulaVersion, "score": r.Score.Score,
				"grade": r.Score.Grade, "penalties": r.Score.Penalties}
			vital = vitalSignsJSON(r)
		}
		if v.Sections.Hotspots && len(r.Hotspots) > 0 {
			hs := make([]any, 0, len(r.Hotspots))
			for _, h := range r.Hotspots {
				m := map[string]any{"path": h.Path, "score": h.Score, "commits": h.Commits,
					"weighted_commits": h.WeightedCommits, "lines_added": h.LinesAdded,
					"lines_deleted": h.LinesDeleted, "complexity_density": h.Density,
					"fan_in": h.FanIn, "trend": h.Trend}
				if h.IsTestPath {
					m["is_test_path"] = true
				}
				hs = append(hs, m)
			}
			g["hotspots"] = hs
		}
		if v.Sections.Targets && len(r.Targets) > 0 {
			tg := make([]any, 0, len(r.Targets))
			for _, t := range r.Targets {
				factors := make([]any, 0, len(t.Factors))
				for _, fc := range t.Factors {
					factors = append(factors, map[string]any{"metric": fc.Metric, "value": fc.Value,
						"threshold": fc.Threshold, "detail": fc.Detail})
				}
				tg = append(tg, map[string]any{"path": t.Path, "priority": t.Priority,
					"efficiency": t.Efficiency, "recommendation": t.Recommendation,
					"category": t.Category, "effort": t.Effort, "confidence": t.Confidence, "factors": factors})
			}
			g["targets"] = tg
		}
		if len(vital) > 0 {
			g["vital_signs"] = vital
		}
		if baseline != nil && baseline.Snapshot != nil && baseline.Snapshot.Groups != nil && baseline.Snapshot.Groups.GroupedBy == ownership.Mode {
			gt := health.BuildGroupTrend(baseline.Snapshot, baseline.SnapshotsLoaded, k, r)
			if gt != nil {
				g["trend_status"] = "compared"
				g["trend"] = gt
			} else {
				g["trend_status"] = "new_group"
			}
		} else if baseline != nil && baseline.Snapshot != nil {
			g["trend_status"] = "no_group_baseline"
		} else {
			g["trend_status"] = "new_group"
		}
		groups = append(groups, g)
	}
	envelope := map[string]any{
		"kind":           "health",
		"schema_version": version.HealthSchemaVersion,
		"version":        version.Version,
	}
	if project.ElapsedMS > 0 {
		envelope["elapsed_ms"] = project.ElapsedMS
	}
	envelope["summary"] = healthProjectSummary(v, project)
	if v.Trend != nil {
		envelope["health_trend"] = v.Trend
	}
	if filter != nil {
		envelope["group_filter"] = filter.patternsOut()
	}
	root := GroupedRoot("health-grouped", version.HealthSchemaVersion, ownership, envelope, groups, total)
	s, err := JSONString(root)
	if err != nil {
		return "{}", total, unmatched
	}
	return s, total, unmatched
}

// HealthGroupedHuman renders the fallow health grouping matrix: one row per
// bucket with its score, grade, and counts, unowned pinned last.
func HealthGroupedHuman(v HealthView, bodies map[string]*health.Result, ownership *Ownership, order []string, sectionOwners map[string][]string, filter *GroupFilter, colors bool) string {
	var b strings.Builder
	b.WriteString(bold(colors) + "Grouped health (" + ownership.Mode + ")" + reset(colors) + "\n")
	for _, k := range order {
		if filter != nil && !filter.Keep(k) {
			continue
		}
		r := bodies[k]
		if r == nil {
			continue
		}
		scoreLine := "score -"
		if v.Sections.Score {
			scoreLine = fmt.Sprintf("score %.1f/100 (%s)", r.Score.Score, r.Score.Grade)
		}
		fmt.Fprintf(&b, "\n\u25c6 %s \u00b7 %d files \u00b7 %d above threshold \u00b7 %d hotspots \u00b7 %s\n", k, r.FilesAnalyzed, r.AboveCeiling, len(r.Hotspots), scoreLine)
		if ownership.Mode == "section" && len(sectionOwners[k]) > 0 {
			fmt.Fprintf(&b, "  owners: %s\n", strings.Join(sectionOwners[k], ", "))
		}
		inner := v
		inner.Res = r
		body := HealthHuman(inner)
		// Drop the per-group verdict line; the matrix keeps one total.
		body = trimHealthVerdict(body)
		b.WriteString(body)
	}
	total := 0
	for _, k := range order {
		if filter != nil && !filter.Keep(k) {
			continue
		}
		if r := bodies[k]; r != nil {
			total += r.AboveCeiling
		}
	}
	mark := "\u2713"
	if v.Res != nil && HealthFailing(v) {
		mark = "\u2717"
	}
	fmt.Fprintf(&b, "\n%s %d functions above threshold across %d groups \u00b7 %d analyzed (%.2fs)\n",
		mark, total, len(order), v.Res.FilesAnalyzed, float64(v.Res.ElapsedMS)/1000)
	return b.String()
}

// trimHealthVerdict removes the final "✓/✗/⚠ ..." summary line that
// HealthHuman appends, so grouped blocks flow without repeated verdicts.
func trimHealthVerdict(body string) string {
	best := -1
	for _, m := range []string{"\n\u2713 ", "\n\u2717 ", "\n\u26a0 "} {
		if i := strings.LastIndex(body, m); i > best {
			best = i
		}
	}
	if best >= 0 {
		return body[:best+1]
	}
	return body
}
