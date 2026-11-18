package health

import (
	"math"
	"sort"
	"strconv"
	"strings"

	"goose/internal/facts"
)

// ---------------------------------------------------------------------------
// File scores.
// ---------------------------------------------------------------------------

func (r *Result) computeFileScores(in Input) {
	if !(in.Opts.FileScores || in.Opts.Hotspots || in.Opts.Targets ||
		in.Opts.Score || in.Opts.MinScore > 0 || in.Opts.ReportOnly) {
		return
	}
	maxCR := in.Cfg.MaxCrapF()
	fanIn := map[string]map[string]bool{}
	for _, ff := range in.Facts.NonTestFiles() {
		for _, key := range ff.Entities {
			for _, u := range in.Facts.Uses[key] {
				if u.PkgPath != ff.PkgPath && u.File != ff.Path && u.File != "" {
					if fanIn[ff.Rel] == nil {
						fanIn[ff.Rel] = map[string]bool{}
					}
					fanIn[ff.Rel][u.File] = true
				}
			}
		}
	}
	exportN, deadN := map[string]int{}, map[string]int{}
	var out []FileScore
	for _, ff := range sortedFiles(in) {
		fs := FileScore{Path: ff.Rel, LOC: ff.Loc, FanOut: len(ff.Imports)}
		if n := len(fanIn[ff.Rel]); n > 0 {
			fs.FanIn = n
		}
		var volumeSum, nToken float64
		for _, key := range ff.Entities {
			e := in.Facts.Entities[key]
			if e == nil {
				continue
			}
			if e.Exported && !e.Local && !e.InterfaceMethod &&
				(e.Kind == facts.KindFunc || e.Kind == facts.KindType) {
				exportN[ff.Rel]++
				if len(in.Facts.LiveUses(key)) == 0 {
					deadN[ff.Rel]++
				}
			}
			if e.Func == nil || e.Local || e.InterfaceMethod || ff.InTest {
				continue
			}
			fs.FuncCount++
			fs.TotalCyclomatic += e.Func.Cyclomatic
			fs.TotalCognitive += e.Func.Cognitive
			cov := r.coverageOf(in, ff.Rel, e)
			crp := Crap(e.Func.Cyclomatic, cov)
			fs.CrapMax = math.Max(fs.CrapMax, crp)
			if maxCR > 0 && crp >= maxCR {
				fs.CrapAbove++
			}
		}
		vocab, tk := halsteadLite(ff.Src, &fs)
		if tk > 0 {
			volumeSum = tk * math.Log2(math.Max(vocab, 2))
			nToken = volumeSum / math.Max(vocab/2, 1)
		}
		fs.Maintainability = round1(maintainability(nToken, fs))
		if fs.LOC > 0 {
			fs.ComplexityDensity = round2(float64(fs.TotalCyclomatic) / float64(fs.LOC))
		}
		if exportN[ff.Rel] > 0 {
			fs.DeadCodeRatio = round2(float64(deadN[ff.Rel]) / float64(exportN[ff.Rel]))
		}
		risk := clamp01(fs.CrapMax/60) * 100
		st := clamp01(1-fs.Maintainability/100) * 100
		if risk >= st {
			fs.Concern = "risk"
		} else {
			fs.Concern = "structure"
		}
		out = append(out, fs)
	}
	sort.Slice(out, func(i, j int) bool {
		ci, cj := concernOf(out[i]), concernOf(out[j])
		if ci != cj {
			return ci > cj
		}
		return out[i].Path < out[j].Path
	})
	r.FileScores = out
	r.FilesScored = len(out)
}

func concernOf(fs FileScore) float64 {
	risk := clamp01(fs.CrapMax/60) * 100
	st := clamp01(1-fs.Maintainability/100) * 100
	return math.Max(risk, st)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// maintainability is the Halstead-Schostak MI mapped to 0..100: an effort
// volume term, an average-cyclomatic term, and a size term.
func maintainability(effort float64, fs FileScore) float64 {
	loc := math.Max(float64(fs.LOC), 1)
	cyclo := float64(fs.TotalCyclomatic)
	if fs.FuncCount > 0 {
		cyclo = float64(fs.TotalCyclomatic) / float64(fs.FuncCount)
	}
	if effort <= 0 {
		effort = loc
	}
	mi := 171 - 5.2*math.Log(effort+1) - 0.23*cyclo - 16.2*math.Log(loc)
	return clampPct(mi * 100 / 171)
}

func clampPct(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// halsteadLite counts identifiers and operators outside strings and comments
// and fills the file's token volume used for MI.
func halsteadLite(src string, fs *FileScore) (vocab, tokens float64) {
	seen := map[string]bool{}
	line, block, str := false, false, byte(0)
	flush := func(w string) {
		if w != "" {
			seen[w] = true
			tokens++
		}
	}
	var word []rune
	r := []rune(src)
	for i := 0; i < len(r); i++ {
		c := r[i]
		switch {
		case block:
			if c == '*' && i+1 < len(r) && r[i+1] == '/' {
				block = false
				i++
			}
		case line:
			if c == '\n' {
				line = false
			}
		case str != 0:
			if c == '\\' {
				i++
			} else if byte(c) == str {
				str = 0
			}
		case c == '/' && i+1 < len(r) && r[i+1] == '/':
			flush(string(word))
			word = word[:0]
			line = true
			i++
		case c == '/' && i+1 < len(r) && r[i+1] == '*':
			flush(string(word))
			word = word[:0]
			block = true
			i++
		case c == '"' || c == '\'' || c == '`':
			flush(string(word))
			word = word[:0]
			str = byte(c)
		case isWord(c):
			word = append(word, c)
		default:
			flush(string(word))
			word = word[:0]
			if !strings.ContainsRune(" \t\n\r", c) {
				seen[string(c)] = true
				tokens++
			}
		}
	}
	flush(string(word))
	return float64(len(seen)), tokens
}

func isWord(c rune) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// ---------------------------------------------------------------------------
// Vital signs.
// ---------------------------------------------------------------------------

func (r *Result) computeVitals(in Input, out *Result) {
	proj := in.Facts
	var files, deadFiles, exported, deadEx, funcs, ccSum, crit int
	criticalCC := 2 * in.Cfg.MaxCyclomatic()
	for _, ff := range sortedFiles(in) {
		files++
		if len(ff.Entities) > 0 {
			alive := ff.PkgName == "main" || (proj.EntryPkgs != nil && proj.EntryPkgs[ff.PkgPath])
			if !alive {
				for _, key := range ff.Entities {
					e := proj.Entities[key]
					if e != nil && e.Func != nil && (e.Func.IsInit || e.Func.IsMain) {
						alive = true
						break
					}
					if len(proj.LiveUses(key)) > 0 {
						alive = true
						break
					}
				}
			}
			if !alive {
				deadFiles++
			}
		}
		for _, key := range ff.Entities {
			e := proj.Entities[key]
			if e == nil {
				continue
			}
			if e.Exported && !e.Local && !e.InterfaceMethod {
				exported++
				if len(proj.LiveUses(key)) == 0 {
					deadEx++
				}
			}
			if e.Func == nil || e.Local || e.InterfaceMethod || ff.InTest {
				continue
			}
			funcs++
			ccSum += e.Func.Cyclomatic
			if e.Func.Cyclomatic >= criticalCC {
				crit++
			}
		}
	}
	v := &out.Vital
	if files > 0 {
		v.DeadFilePercent = round1(float64(deadFiles) / float64(files) * 100)
	}
	if exported > 0 {
		v.DeadExportPercent = round1(float64(deadEx) / float64(exported) * 100)
	}
	if funcs > 0 {
		v.AvgCyclomatic = round1(float64(ccSum) / float64(funcs))
		v.CriticalComplexityPct = round1(float64(crit) / float64(funcs) * 100)
	}
	if len(r.FileScores) > 0 {
		sum := 0.0
		for _, fs := range r.FileScores {
			sum += fs.Maintainability
		}
		v.MaintainabilityAvg = round1(sum / float64(len(r.FileScores)))
	}
}

// ---------------------------------------------------------------------------
// Hotspots (churn x complexity).
// ---------------------------------------------------------------------------

func (r *Result) computeHotspots(in Input) {
	if !in.Opts.Hotspots && !in.Opts.Targets {
		return
	}
	if !in.Churn.Available || len(in.Churn.FilesByPath) == 0 {
		return
	}
	minCommits := in.Churn.MinCommits
	if minCommits <= 0 {
		minCommits = 3
	}
	maxWeighted := 0.0
	for _, cf := range in.Churn.FilesByPath {
		if cf.Weighted > maxWeighted {
			maxWeighted = cf.Weighted
		}
	}
	if maxWeighted <= 0 {
		maxWeighted = 1
	}
	densityBy := map[string]float64{}
	fanBy := map[string]int{}
	maxD := 0.0
	for _, fs := range r.FileScores {
		densityBy[fs.Path] = fs.ComplexityDensity
		fanBy[fs.Path] = fs.FanIn
		if fs.ComplexityDensity > maxD {
			maxD = fs.ComplexityDensity
		}
	}
	if maxD <= 0 {
		maxD = 1
	}
	for path, cf := range in.Churn.FilesByPath {
		if !inSubset(in, path) {
			continue
		}
		if cf.Commits < minCommits {
			continue
		}
		churn := math.Log1p(cf.Weighted) / math.Log1p(maxWeighted)
		density := densityBy[path] / maxD
		blast := 0.0
		if avg := avgFanIn(r.FileScores); avg > 0 {
			blast = clamp01(float64(fanBy[path]) / avg)
		}
		score := (churn*0.45 + density*0.4 + blast*0.15) * 100
		r.Hotspots = append(r.Hotspots, Hotspot{
			Path: path, Score: round1(score), Commits: cf.Commits,
			WeightedCommits: round1(cf.Weighted), LinesAdded: cf.Added,
			LinesDeleted: cf.Deleted, Density: round2(densityBy[path]),
			FanIn: fanBy[path], Trend: cf.Trend, IsTestPath: isTestPath(path),
		})
	}
	sort.Slice(r.Hotspots, func(i, j int) bool {
		if r.Hotspots[i].Score != r.Hotspots[j].Score {
			return r.Hotspots[i].Score > r.Hotspots[j].Score
		}
		return r.Hotspots[i].Path < r.Hotspots[j].Path
	})
	n := 0
	for _, h := range r.Hotspots {
		if h.Score >= 50 {
			n++
		}
	}
	r.Vital.HotspotCount = n
}

func avgFanIn(scores []FileScore) float64 {
	if len(scores) == 0 {
		return 0
	}
	s := 0
	for _, f := range scores {
		s += f.FanIn
	}
	return math.Max(1, float64(s)/float64(len(scores)))
}

// ---------------------------------------------------------------------------
// Health score.
// ---------------------------------------------------------------------------

func (r *Result) computeScore(in Input) {
	v := r.Vital
	pen := map[string]float64{}
	add := func(k string, p float64) {
		if p > 0 {
			pen[k] = round1(p)
		}
	}
	add("dead_files", minF(v.DeadFilePercent, 60)/100*15)
	add("dead_exports", minF(v.DeadExportPercent, 60)/100*15)
	add("complexity", v.CriticalComplexityPct/100*25)
	if cc := in.Cfg.MaxCyclomatic(); v.AvgCyclomatic > float64(cc) && cc > 0 {
		add("p90_complexity", minF((v.AvgCyclomatic-float64(cc))/float64(cc)*5, 5))
	}
	if v.MaintainabilityAvg > 0 && v.MaintainabilityAvg < 100 {
		add("maintainability", (100-v.MaintainabilityAvg)/100*20)
	}
	add("hotspots", minF(float64(v.HotspotCount)*0.5, 10))
	if in.UnusedDeps != nil {
		add("unused_deps", minF(float64(*in.UnusedDeps)*2, 10))
	}
	if in.Cycles != nil {
		add("circular_deps", minF(float64(*in.Cycles)*2, 15))
	}
	if in.Duplication != nil {
		add("duplication", minF(*in.Duplication, 40)/100*12)
	}
	total := 0.0
	for _, p := range pen {
		total += p
	}
	score := round1(clampPct(100 - total))
	r.Score = Score{FormulaVersion: ScoreFormulaVersion, Score: score, Grade: gradeOf(score), Penalties: pen}
}

func gradeOf(s float64) string {
	switch {
	case s >= 90:
		return "A"
	case s >= 80:
		return "B"
	case s >= 70:
		return "C"
	case s >= 60:
		return "D"
	}
	return "F"
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Refactoring targets.
// ---------------------------------------------------------------------------

func (r *Result) computeTargets(in Input) {
	cycles := map[string]bool{}
	for _, f := range r.cycleFiles(in) {
		cycles[f] = true
	}
	deadBy := map[string][]string{}
	exportBy := map[string]int{}
	for _, ff := range in.Facts.Files {
		if ff.InTest {
			continue
		}
		for _, key := range ff.Entities {
			e := in.Facts.Entities[key]
			if e == nil || !e.Exported || e.Local || e.InterfaceMethod ||
				(e.Kind != facts.KindFunc && e.Kind != facts.KindType) {
				continue
			}
			exportBy[ff.Rel]++
			if len(in.Facts.LiveUses(key)) == 0 {
				deadBy[ff.Rel] = append(deadBy[ff.Rel], funcQual(e))
			}
		}
	}
	fsBy := map[string]FileScore{}
	for _, fs := range r.FileScores {
		fsBy[fs.Path] = fs
	}
	byPath := map[string]*facts.FileFacts{}
	for _, ff := range in.Facts.Files {
		if ff.Rel != "" {
			byPath[ff.Rel] = ff
		}
	}
	var ts []Target
	for rel, ff := range byPath {
		if ff.InTest {
			continue
		}
		fs := fsBy[rel]
		var cf *ChurnFile
		if in.Churn.FilesByPath != nil {
			cf = in.Churn.FilesByPath[rel]
		}
		above := 0
		for _, f := range r.Findings {
			if f.Path == rel && f.Name != "<file>" {
				above++
			}
		}
		dead := deadBy[rel]
		pctUnused := pctf(float64(len(dead)), float64(maxI(exportBy[rel], 1)))

		add := func(cat, effort, conf, rec string, prio, eff float64, factors ...Factor) {
			if prio <= 0 {
				return
			}
			ts = append(ts, Target{
				Path: rel, Priority: round1(prio), Efficiency: round1(eff),
				Category: cat, Effort: effort, Confidence: conf,
				Recommendation: rec, Factors: factors,
			})
		}

		// churn + complexity.
		if cf != nil && fs.ComplexityDensity >= 0.3 && cf.Weighted >= 3 {
			prio := clampScore(math.Log1p(cf.Weighted)*12 + fs.ComplexityDensity*35)
			add("urgent_churn_complexity", "high", "low", "Actively-changing file with growing complexity; stabilize before adding features.",
				prio, prio/3,
				Factor{"complexity_density", round2(fs.ComplexityDensity), 0.3, "density exceeds the risk bar"},
				Factor{"weighted_commits", round1(cf.Weighted), 3, "active churn in the window"})
		}
		// circular dependency.
		if cycles[rel] {
			add("break_circular_dependency", "medium", "high", "This file sits in an import cycle; break it with a shared interface.",
				70, 35, Factor{"in_cycle", 1, 1, "inside a package cycle"})
		}
		// high impact.
		if fs.FanIn >= 12 && fs.ComplexityDensity >= 0.3 {
			prio := clampScore(float64(fs.FanIn)*4 + fs.ComplexityDensity*40)
			add("split_high_impact", "high", "low", "High fan-in and high complexity: a change ripples widely; split the risky helpers.",
				prio, prio/3,
				Factor{"fan_in", float64(fs.FanIn), 12, "many importers"},
				Factor{"complexity_density", round2(fs.ComplexityDensity), 0.3, "dense decisions"})
		}
		// dead code.
		if len(dead) > 0 && pctUnused >= 20 {
			prio := clampScore(pctUnused*0.6 + float64(len(dead))*2)
			add("remove_dead_code", "low", "high", "Remove "+itoa(len(dead))+" unused exports to shrink the surface ("+fmtPct(pctUnused)+" dead).",
				prio, prio,
				Factor{"dead_export_pct", round2(pctUnused), 50, "share of exports unused"},
				Factor{"dead_exports", float64(len(dead)), 0, "unused exported count"})
		}
		// extracted complexity.
		if above > 0 {
			prio := clampScore(float64(above)*10 + float64(fs.TotalCognitive)*0.15)
			add("extract_complex_functions", "medium", "high", "Extract the "+itoa(above)+" over-threshold functions into named helpers.",
				prio, prio/2.5,
				Factor{"complexity_findings", float64(above), 1, "functions above the ceilings"})
		}
		// coupling.
		if fs.FanOut >= 12 {
			prio := clampScore(float64(fs.FanOut) * 3)
			add("extract_dependencies", "low", "high", "Reduce the import fan-out of "+itoa(fs.FanOut)+" behind a facade.",
				prio, prio, Factor{"fan_out", float64(fs.FanOut), 12, "too many imports"})
		}
		// untested risk.
		if fs.CrapAbove >= 2 && fs.ComplexityDensity >= 0.3 {
			prio := clampScore(float64(fs.CrapAbove)*8 + fs.ComplexityDensity*40)
			add("add_test_coverage", "medium", "medium", "Add tests: complex functions in this file have low coverage.",
				prio, prio/2,
				Factor{"crap_above", float64(fs.CrapAbove), 2, "functions above the CRAP ceiling"},
				Factor{"complexity_density", round2(fs.ComplexityDensity), 0.3, "decisions per line"})
		}
	}
	// One target per file: highest efficiency wins.
	sort.Slice(ts, func(i, j int) bool { return ts[i].Efficiency > ts[j].Efficiency })
	seen := map[string]bool{}
	for i := range ts {
		if seen[ts[i].Path] {
			continue
		}
		seen[ts[i].Path] = true
		r.Targets = append(r.Targets, ts[i])
	}
}

func (r *Result) cycleFiles(in Input) []string {
	if in.Graph == nil {
		return nil
	}
	set := map[string]bool{}
	for _, cyc := range in.Graph.Cycles() {
		for _, pkg := range cyc {
			for _, ff := range in.Facts.Files {
				if ff.PkgPath == pkg {
					set[ff.Rel] = true
				}
			}
		}
	}
	return sortedKeys(set)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func pctf(part, whole float64) float64 {
	if whole == 0 {
		return 0
	}
	return part / whole * 100
}

func clampScore(v float64) float64 { return clampPct(v) }

func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var _ = strings.Contains

// isTestPath is fallow's test-path gate used on hotspot entries.
func isTestPath(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		switch seg {
		case "test", "tests", "__tests__", "__test__", "spec", "specs",
			"__mocks__", "__fixtures__", "fixtures", "__snapshots__", "e2e":
			return true
		}
	}
	lower := strings.ToLower(rel)
	for _, sub := range []string{".test.", ".spec.", ".e2e.", ".cy.", ".fixture."} {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

func itoa(v int) string { return strconv.Itoa(v) }

func fmtPct(v float64) string {
	return strconv.FormatFloat(math.Round(v), 'f', 0, 64) + "%"
}

// applyTop caps each table section after the rank order Run chose.
func (r *Result) applyTop(top int) {
	if top <= 0 {
		return
	}
	r.Findings = headTo(r.Findings, top)
	r.LargeFuncs = headTo(r.LargeFuncs, top)
	r.Hotspots = headTo(r.Hotspots, top)
	r.FileScores = headTo(r.FileScores, top)
	r.Targets = headTo(r.Targets, top)
}

func headTo[T any](s []T, n int) []T {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
