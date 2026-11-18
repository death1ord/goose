// Package health measures where a Go codebase is hard to change: function
// and file complexity, CRAP risk (exact from Go coverage profiles, estimated
// otherwise), churn hotspots, ranked refactoring targets, and the 0-100
// project health score. It mirrors the fallow health contract for Go sources.
package health

import (
	"math"
	"sort"
	"time"

	"goose/internal/config"
	"goose/internal/facts"
	"goose/internal/graph"
)

// ChurnData is the git history view one run reads. Available=false when the
// project has no repository, and the churn sections skip without an error.
// Events feeds FilesByPath through AggregateChurn; a caller may also set
// FilesByPath directly.
type ChurnData struct {
	Available   bool
	Shallow     bool
	Since       string
	MinCommits  int
	Events      []ChurnEvent
	FilesByPath map[string]*ChurnFile
}

// ChurnEvent is one (commit, file) pair, the goose record of a git numstat
// row. Timestamp is unix seconds.
type ChurnEvent struct {
	Path      string
	Timestamp int64
	Author    string
	Added     int
	Deleted   int
}

// ChurnFile aggregates churn events for one project-relative path.
type ChurnFile struct {
	Commits   int
	Weighted  float64 // recency-weighted commits
	Recent    int     // commits in the newest third of the window
	Added     int
	Deleted   int
	Trend     string // Accelerating | Stable | Cooling
	BusFactor int
	TopAuthor string
	AuthorNum int
}

// AggregateChurn folds events into per-file churn with recency weighting and
// a trend, then fills FilesByPath. now is the current unix time.
func AggregateChurn(c *ChurnData, now int64) {
	if c.Events == nil {
		return
	}
	c.FilesByPath = map[string]*ChurnFile{}
	type rev struct {
		ts      int64
		author  string
		added   int
		deleted int
	}
	byFile := map[string][]rev{}
	allTS := []int64{}
	for _, e := range c.Events {
		byFile[e.Path] = append(byFile[e.Path], rev{e.Timestamp, e.Author, e.Added, e.Deleted})
		allTS = append(allTS, e.Timestamp)
	}
	// Window bounds split history into thirds for the trend.
	sort.Slice(allTS, func(i, j int) bool { return allTS[i] > allTS[j] })
	var recentCut, olderCut int64
	if len(allTS) > 2 {
		recentCut = allTS[len(allTS)/3]
		olderCut = allTS[2*len(allTS)/3]
	}
	// Half-life recency weighting, 90 days.
	const halfLifeSecs = 90 * 24 * 3600
	decay := func(ts int64) float64 {
		if ts <= 0 {
			return 1
		}
		return math.Exp(-float64(now-ts) * 0.693 / halfLifeSecs)
	}
	for path, revs := range byFile {
		cf := &ChurnFile{}
		perAuthor := map[string]float64{}
		totalW := 0.0
		for _, rf := range revs {
			w := decay(rf.ts)
			cf.Weighted += w
			cf.Recent += boolInt(rf.ts >= recentCut)
			perAuthor[rf.author] += w
			totalW += w
			cf.Commits++
			cf.Added += rf.added
			cf.Deleted += rf.deleted
		}
		cf.AuthorNum = len(perAuthor)
		// bus factor: smallest set of authors covering >= 50% of weighted.
		shares := make([]float64, 0, len(perAuthor))
		for _, v := range perAuthor {
			shares = append(shares, v)
		}
		sort.Sort(sort.Reverse(sort.Float64Slice(shares)))
		acc, bus := 0.0, 0
		for _, s := range shares {
			if totalW > 0 {
				acc += s / totalW
			}
			bus++
			if acc >= 0.5 {
				break
			}
		}
		cf.BusFactor = bus
		for a, v := range perAuthor {
			if v >= maxPer(perAuthor) {
				cf.TopAuthor = a
			}
		}
		_ = olderCut
		switch {
		case cf.Commits >= 5 && float64(cf.Recent) >= 0.6*float64(cf.Commits):
			cf.Trend = "Accelerating"
		case cf.Commits >= 5 && float64(cf.Recent) <= 0.25*float64(cf.Commits):
			cf.Trend = "Cooling"
		default:
			cf.Trend = "Stable"
		}
		c.FilesByPath[path] = cf
	}
}

func maxPer(m map[string]float64) float64 {
	best := 0.0
	for _, v := range m {
		if v > best {
			best = v
		}
	}
	return best
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Input carries everything one health run reads. The caller assembles it so
// this package stays free of loader and output imports.
type Input struct {
	Facts      *facts.Project
	Graph      *graph.Graph
	Cfg        *config.Config
	Cov        *Coverage
	Churn      ChurnData
	Opts       Options
	ModulePath string

	// External inputs for the score, set when those sections ran.
	UnusedDeps  *int
	Cycles      *int
	Duplication *float64

	// Subset limits counts, vital signs, and scores to one set of
	// project-relative paths — the --group-by bucket filter. nil means the
	// whole project. Graph edges stay project-wide, so fan-in from outside
	// the subset still counts.
	Subset map[string]bool
}

// Options select the sections Run computes.
type Options struct {
	Complexity   bool
	FileScores   bool
	Hotspots     bool
	Targets      bool
	Score        bool
	MinScore     float64
	MinSeverity  string
	ReportOnly   bool
	Production   bool
	Top          int
	CoverageGaps bool
}

// Result holds the assembled sections.
type Result struct {
	FilesAnalyzed int
	FuncsAnalyzed int
	AboveCeiling  int
	FilesScored   int
	Model         string // "istanbul" | "static_estimated"
	ElapsedMS     int64

	Findings   []Finding
	LargeFuncs []Finding
	FileScores []FileScore
	Hotspots   []Hotspot
	Targets    []Target
	Score      Score
	Vital      VitalSigns
	Gaps       *CoverageGaps

	// Churn metadata for the hotspot header.
	ChurnSince      string
	ChurnMinCommits int
	ChurnShallow    bool
	ChurnAvailable  bool
}

// Finding is one complexity finding; Exceeded names the breached ceilings.
type Finding struct {
	Path       string   `json:"path"`
	Name       string   `json:"name"`
	Line       int      `json:"line"`
	Col        int      `json:"col"`
	Cyclomatic int      `json:"cyclomatic"`
	Cognitive  int      `json:"cognitive"`
	Lines      int      `json:"line_count"`
	Crap       float64  `json:"crap,omitempty"`
	Exceeded   []string `json:"exceeded"`
	Band       string   `json:"band"`
}

// FileScore is one file's metric block.
type FileScore struct {
	Path              string  `json:"path"`
	Maintainability   float64 `json:"maintainability_index"`
	LOC               int     `json:"lines"`
	FanIn             int     `json:"fan_in"`
	FanOut            int     `json:"fan_out"`
	FuncCount         int     `json:"function_count"`
	TotalCyclomatic   int     `json:"total_cyclomatic"`
	TotalCognitive    int     `json:"total_cognitive"`
	CrapMax           float64 `json:"crap_max"`
	CrapAbove         int     `json:"crap_above_threshold"`
	ComplexityDensity float64 `json:"complexity_density"`
	DeadCodeRatio     float64 `json:"dead_code_ratio"`
	Concern           string  `json:"concern_kind"` // risk | structure
}

// Hotspot is one churn x complexity row.
type Hotspot struct {
	Path            string  `json:"path"`
	Score           float64 `json:"score"`
	Commits         int     `json:"commits"`
	WeightedCommits float64 `json:"weighted_commits"`
	LinesAdded      int     `json:"lines_added"`
	LinesDeleted    int     `json:"lines_deleted"`
	Density         float64 `json:"complexity_density"`
	FanIn           int     `json:"fan_in"`
	Trend           string  `json:"trend"`
	IsTestPath      bool    `json:"is_test_path,omitempty"`
}

// Target is one ranked refactoring recommendation.
type Target struct {
	Path           string   `json:"path"`
	Priority       float64  `json:"priority"`
	Efficiency     float64  `json:"efficiency"`
	Category       string   `json:"category"`
	Effort         string   `json:"effort"` // low | medium | high
	Confidence     string   `json:"confidence"`
	Recommendation string   `json:"recommendation"`
	Factors        []Factor `json:"factors"`
}

// Factor is one raw evidence row behind a target.
type Factor struct {
	Metric    string  `json:"metric"`
	Value     float64 `json:"value"`
	Threshold float64 `json:"threshold"`
	Detail    string  `json:"detail"`
}

// Score is the project score with grade and penalties. 100 - sum(penalties)
// reproduces the score.
type Score struct {
	FormulaVersion int                `json:"formula_version"`
	Score          float64            `json:"score"`
	Grade          string             `json:"grade"`
	Penalties      map[string]float64 `json:"penalties"`
}

// VitalSigns holds the headline measurements the score is built from.
type VitalSigns struct {
	DeadFilePercent       float64 `json:"dead_file_pct"`
	DeadExportPercent     float64 `json:"dead_export_pct"`
	AvgCyclomatic         float64 `json:"avg_cyclomatic"`
	CriticalComplexityPct float64 `json:"critical_complexity_pct"`
	HotspotCount          int     `json:"hotspot_count"`
	MaintainabilityAvg    float64 `json:"maintainability_avg"`
}

// Crap returns the CRAP score of a function with cyclomatic cc and a coverage
// fraction cov in [0,1]: cc^2 * (1-cov)^3 + cc.
func Crap(cc int, cov float64) float64 {
	if cc <= 0 {
		return 0
	}
	if cov < 0 {
		cov = 0
	}
	if cov > 1 {
		cov = 1
	}
	v := float64(cc*cc)*math.Pow(1-cov, 3) + float64(cc)
	return math.Round(v*10) / 10
}

// Run computes the requested sections over the input snapshot.
func Run(in Input) *Result {
	start := time.Now()
	r := &Result{Model: "static_estimated"}
	if in.Cov != nil {
		r.Model = "istanbul"
	}
	r.ChurnAvailable = in.Churn.Available
	r.ChurnShallow = in.Churn.Shallow
	r.ChurnSince = in.Churn.Since
	r.ChurnMinCommits = in.Churn.MinCommits
	r.collectCounts(in)
	r.computeFindings(in)
	r.computeFileScores(in)
	r.computeVitals(in, r)
	r.computeHotspots(in)
	r.computeScore(in)
	if in.Opts.Targets {
		r.computeTargets(in)
	}
	if in.Opts.CoverageGaps {
		r.Gaps = computeCoverageGaps(in.Facts, in.Cfg)
	}
	r.applyTop(in.Opts.Top)
	ms := time.Since(start).Milliseconds()
	if ms < 1 {
		ms = 1
	}
	r.ElapsedMS = ms
	return r
}

// inSubset reports whether a rel path is inside the run's subset filter.
func inSubset(in Input, rel string) bool {
	return in.Subset == nil || in.Subset[rel]
}

// collectCounts fills the header stats.
func (r *Result) collectCounts(in Input) {
	r.FilesAnalyzed = len(sortedFiles(in))
	total := 0
	for _, ff := range sortedFiles(in) {
		for _, key := range ff.Entities {
			e := in.Facts.Entities[key]
			if e != nil && e.Func != nil && !e.Local && !e.InterfaceMethod {
				total++
			}
		}
	}
	r.FuncsAnalyzed = total
}

// ---------------------------------------------------------------------------
// Threshold resolution.
// ---------------------------------------------------------------------------

type ceilings struct {
	maxCC int
	maxCO int
	maxCR float64
	unit  int
	file  int
}

func (in Input) global() ceilings {
	return ceilings{
		maxCC: in.Cfg.MaxCyclomatic(),
		maxCO: in.Cfg.MaxCognitive(),
		maxCR: in.Cfg.MaxCrapF(),
		unit:  in.Cfg.MaxUnitSize(),
		file:  in.Cfg.MaxFileLines(),
	}
}

// ceilingsFor applies health.thresholdOverrides entries on top of the
// defaults for a file and function name.
func (in Input) ceilingsFor(rel, name string) ceilings {
	c := in.global()
	for i := range in.Cfg.Health.ThresholdOverrides {
		ov := &in.Cfg.Health.ThresholdOverrides[i]
		if !matchAny(ov.Files, rel) {
			continue
		}
		fnScoped := len(ov.Functions) > 0
		if fnScoped && !contains(ov.Functions, name) {
			continue
		}
		if ov.MaxCyclomatic != nil {
			c.maxCC = *ov.MaxCyclomatic
		}
		if ov.MaxCognitive != nil {
			c.maxCO = *ov.MaxCognitive
		}
		if ov.MaxCrap != nil {
			c.maxCR = *ov.MaxCrap
		}
		if ov.MaxUnitSize != nil {
			c.unit = *ov.MaxUnitSize
		}
		if ov.MaxFileLines != nil && !fnScoped {
			c.file = *ov.MaxFileLines
		}
	}
	return c
}

func matchAny(patterns []string, rel string) bool {
	for _, p := range patterns {
		if config.MatchPath(p, rel) {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// funcQual returns "Recv.Name" for methods and "Name" otherwise.
func funcQual(e *facts.Entity) string {
	if e.Recv != "" {
		return e.Recv + "." + e.Name
	}
	return e.Name
}

// ---------------------------------------------------------------------------
// Complexity findings.
// ---------------------------------------------------------------------------

func (r *Result) computeFindings(in Input) {
	if in.Cfg != nil {
		_ = in.Cfg.SuggestInline()
		_ = in.Cfg.CyclomaticPolicy()
	}
	for _, ff := range sortedFiles(in) {
		fileCeilings := in.ceilingsFor(ff.Rel, "")
		if fileCeilings.file > 0 && ff.Loc > fileCeilings.file {
			r.Findings = append(r.Findings, Finding{
				Path: ff.Rel, Name: "<file>", Line: 1,
				Lines:    ff.Loc,
				Exceeded: []string{"file_lines"},
				Band:     bandOfRatio(float64(ff.Loc), float64(fileCeilings.file)),
			})
		}
		for _, key := range ff.Entities {
			e := in.Facts.Entities[key]
			if e == nil || e.Func == nil || e.Local || e.InterfaceMethod || ff.InTest {
				continue
			}
			fi := e.Func
			c := in.ceilingsFor(ff.Rel, funcQual(e))
			cov := r.coverageOf(in, ff.Rel, e)
			crp := Crap(fi.Cyclomatic, cov)
			var exceeded []string
			if fi.Cyclomatic > c.maxCC {
				exceeded = append(exceeded, "cyclomatic")
			}
			if fi.Cognitive > c.maxCO {
				exceeded = append(exceeded, "cognitive")
			}
			if c.maxCR > 0 && crp >= c.maxCR {
				exceeded = append(exceeded, "crap")
			}
			if c.unit > 0 && fi.Loc > c.unit {
				r.LargeFuncs = append(r.LargeFuncs, Finding{
					Path: ff.Rel, Name: funcQual(e), Line: e.Line, Col: e.Col,
					Cyclomatic: fi.Cyclomatic, Cognitive: fi.Cognitive,
					Lines: fi.Loc, Crap: crp,
				})
			}
			if len(exceeded) == 0 {
				continue
			}
			r.AboveCeiling++
			f := Finding{
				Path: ff.Rel, Name: funcQual(e), Line: e.Line, Col: e.Col,
				Cyclomatic: fi.Cyclomatic, Cognitive: fi.Cognitive,
				Lines: fi.Loc,
			}
			if contains(exceeded, "crap") {
				f.Crap = crp
			}
			f.Exceeded = exceeded
			f.Band = worstBand(fi, crp, c)
			r.Findings = append(r.Findings, f)
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		ri, rj := bandRank(r.Findings[i].Band), bandRank(r.Findings[j].Band)
		if ri != rj {
			return ri > rj
		}
		if r.Findings[i].Cyclomatic != r.Findings[j].Cyclomatic {
			return r.Findings[i].Cyclomatic > r.Findings[j].Cyclomatic
		}
		if r.Findings[i].Path != r.Findings[j].Path {
			return r.Findings[i].Path < r.Findings[j].Path
		}
		return r.Findings[i].Line < r.Findings[j].Line
	})
}

func worstBand(fi *facts.FuncInfo, crp float64, c ceilings) string {
	best := 0.0
	if c.maxCC > 0 {
		best = math.Max(best, float64(fi.Cyclomatic)/float64(c.maxCC))
	}
	if c.maxCO > 0 {
		best = math.Max(best, float64(fi.Cognitive)/float64(c.maxCO))
	}
	if c.maxCR > 0 {
		best = math.Max(best, crp/c.maxCR)
	}
	return bandOf(best)
}

func bandOfRatio(v, max float64) string {
	if max <= 0 {
		return "moderate"
	}
	return bandOf(v / max)
}

func bandOf(ratio float64) string {
	switch {
	case ratio >= 2.5:
		return "critical"
	case ratio >= 1.5:
		return "high"
	}
	return "moderate"
}

func bandRank(band string) int {
	switch band {
	case "critical":
		return 3
	case "high":
		return 2
	}
	return 1
}

// coverageOf returns the exact coverage fraction when the profile covers the
// function, else the documented static estimate (85% cross-package, 40%
// same-package, 0% unreferenced).
func (r *Result) coverageOf(in Input, rel string, e *facts.Entity) float64 {
	if e.Func == nil {
		return 0
	}
	if in.Cov != nil {
		if p := in.Cov.Percent(rel, e.Line, e.Line+e.Func.Loc); p != nil {
			return *p
		}
		if in.ModulePath != "" {
			if p := in.Cov.Percent(in.ModulePath+"/"+rel, e.Line, e.Line+e.Func.Loc); p != nil {
				return *p
			}
		}
	}
	for _, u := range in.Facts.Uses[e.Key] {
		if !u.SelfPackage && u.File != e.File {
			return 0.85
		}
	}
	if len(in.Facts.Uses[e.Key]) > 0 {
		return 0.40
	}
	return 0
}

func sortedFiles(in Input) []*facts.FileFacts {
	out := append([]*facts.FileFacts(nil), in.Facts.NonTestFiles()...)
	if in.Subset != nil {
		var kept []*facts.FileFacts
		for _, ff := range out {
			if in.Subset[ff.Rel] {
				kept = append(kept, ff)
			}
		}
		out = kept
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
func round2(v float64) float64 { return math.Round(v*100) / 100 }
