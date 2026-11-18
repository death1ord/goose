// Package engine wires the pipeline: load the project, build the graph and
// facts, run the analyses, and produce a report document. Commands and the
// MCP server share it.
package engine

import (
	"context"
	"regexp"
	"strings"
	"time"

	"go/ast"

	"goose/internal/architecture"
	"goose/internal/config"
	"goose/internal/deadcode"
	"goose/internal/dupes"
	"goose/internal/facts"
	"goose/internal/gitx"
	"goose/internal/graph"
	"goose/internal/health"
	"goose/internal/loader"
	"goose/internal/report"
)

// Context bundles one analysis run's shared state.
type Context struct {
	Loaded *loader.Loaded
	Proj   *facts.Project
	Graph  *graph.Graph
	Cfg    *config.Config
	Std    map[string]bool
	Root   string

	// Caches shared by repeated Health calls (--group-by recomputes per
	// bucket); keyed by the requested input so distinct runs stay correct.
	churnCache map[string]*health.ChurnData
	covCache   map[string]*health.Coverage
}

// LoadAndBuild loads the project and constructs facts and the graph once, so
// that every analysis reuses one type-checked snapshot.
func LoadAndBuild(ctx context.Context, cfg *config.Config, tests bool) (*Context, error) {
	maxFileSizeMB := cfg.MaxFileSize()
	var cacheDir, cacheKey string
	if !cfg.NoCache {
		cacheDir = resolveCacheDir(cfg)
		if key, err := computeCacheKey(cfg.Root, tests, maxFileSizeMB); err == nil {
			cacheKey = key
			if ld, proj, ok := loadCachedSnapshot(cacheDir, cacheKey, cfg.Audit.CacheMaxAgeDays); ok {
				g := graph.Build(proj)
				return &Context{
					Loaded: ld, Proj: proj, Graph: g, Cfg: cfg,
					Root: cfg.Root,
				}, nil
			}
		}
	}
	ld, err := loader.Load(ctx, loader.Options{Dir: cfg.Root, Tests: tests, MaxFileSizeMB: maxFileSizeMB})
	if err != nil {
		return nil, err
	}
	proj := facts.Build(ld)
	if !cfg.NoCache && cacheKey != "" {
		saveCachedSnapshot(cacheDir, cacheKey, ld, proj, cfg.Cache.MaxSizeMB, cfg.Audit.CacheMaxAgeDays)
	}
	g := graph.Build(proj)
	return &Context{
		Loaded: ld, Proj: proj, Graph: g, Cfg: cfg,
		Root: cfg.Root,
	}, nil
}

// LoadSyntaxAndBuild loads the project using fast syntax/AST parsing without
// spawning go list or type-checking. Suitable for dupes, list,architecture,
// and --no-type-aware runs.
func LoadSyntaxAndBuild(ctx context.Context, cfg *config.Config, tests bool) (*Context, error) {
	ld, err := loader.LoadSyntax(ctx, loader.Options{Dir: cfg.Root, Tests: tests, MaxFileSizeMB: cfg.MaxFileSize()})
	if err != nil {
		return nil, err
	}
	proj := facts.Build(ld)
	g := graph.Build(proj)
	return &Context{
		Loaded: ld, Proj: proj, Graph: g, Cfg: cfg,
		Root: cfg.Root,
	}, nil
}

// DeadCode runs the dead-code analysis and returns a report document.
func (c *Context) DeadCode(opts deadcode.Options) *report.Doc {
	opts.Std = c.Std
	a := &deadcode.Analysis{
		Proj: c.Proj, Graph: c.Graph, Cfg: c.Cfg, Opts: opts,
	}
	a.Opts.Unresolved = c.UnresolvedImports()
	res := deadcode.Run(a)
	doc := report.NewDoc("dead-code")
	doc.Findings = res.Findings
	doc.CascadeHidden = res.CascadeHidden
	doc.Diagnostics = res.Diags
	doc.Summary = map[string]any{
		"files_analyzed":    len(c.Proj.Files),
		"packages_analyzed": len(c.Graph.Packages),
		"total_issues":      len(visible(res.Findings)),
	}
	for _, f := range res.Findings {
		if f.Hidden {
			continue
		}
		key := report.CamelCountKey(f.Kind)
		n, _ := doc.Summary[key].(int)
		doc.Summary[key] = n + 1
	}
	for _, sk := range c.Loaded.SkippedFiles {
		doc.Diagnostics = append(doc.Diagnostics, report.Diag{
			Path: c.relFile(sk.Path), Kind: "source-never-analyzed",
			Message:  "File exceeds the analysis size limit and was not analyzed.",
			Degrades: true,
			Extra:    map[string]any{"size_bytes": sk.Bytes},
		})
	}
	addNextSteps(doc, opts.Production)
	return doc
}

func visible(fs []*report.Finding) []*report.Finding {
	var out []*report.Finding
	for _, f := range fs {
		if !f.Hidden {
			out = append(out, f)
		}
	}
	return out
}

// Traced renders a trace for a target symbol.
func (c *Context) Traced(target string) string {
	a := &deadcode.Analysis{Proj: c.Proj, Graph: c.Graph, Cfg: c.Cfg}
	return deadcode.Trace(a, target)
}

// Boundaries summarizes the configured architecture zones for list output.
func (c *Context) Boundaries() (*architecture.BoundarySummary, error) {
	a := &architecture.Analysis{Proj: c.Proj, Graph: c.Graph, Cfg: c.Cfg}
	return a.SummarizeBoundaries()
}

// Architecture runs the architecture analysis (cycles, boundaries, policy)
// and returns a report document plus the run result for list-style output.
func (c *Context) Architecture(o architecture.Options) (*report.Doc, *architecture.Result, error) {
	syntax := map[string]*ast.File{}
	for p, e := range c.Loaded.Files {
		if e.Syntax != nil {
			syntax[p] = e.Syntax
		}
	}
	a := &architecture.Analysis{Proj: c.Proj, Graph: c.Graph, Cfg: c.Cfg, Syntax: syntax}
	res, err := a.Run(o)
	if err != nil {
		return nil, nil, err
	}
	doc := report.NewDoc("architecture")
	doc.Findings = res.Findings
	doc.Diagnostics = res.Diags
	doc.Summary = map[string]any{
		"files_analyzed":    len(c.Proj.Files),
		"packages_analyzed": len(c.Graph.Packages),
		"total_issues":      len(res.Findings),
	}
	for _, f := range res.Findings {
		key := report.CamelCountKey(f.Kind)
		n, _ := doc.Summary[key].(int)
		doc.Summary[key] = n + 1
	}
	return doc, res, nil
}

// Dupes runs the duplication analysis. changedSince, when non-nil, restricts
// the scope to groups with a changed instance.
func (c *Context) Dupes(o dupes.Options, changedSince map[string]bool) *dupes.Result {
	if o.Ignore == nil {
		patterns := c.Cfg.Duplicates.Ignore
		if c.Cfg.Duplicates.IgnoreDefaults == nil || *c.Cfg.Duplicates.IgnoreDefaults {
			patterns = append(append([]string{}, defaultDupesIgnores...), patterns...)
		}
		o.Ignore = func(rel string) bool {
			for _, p := range patterns {
				if config.MatchPath(p, rel) {
					return true
				}
			}
			return false
		}
	}
	o.ChangedSince = changedSince
	return dupes.Detect(c.Proj, o)
}

// defaultDupesIgnores are the built-in duplicates ignore patterns:
// generated framework output and, by default, test paths, matching fallow's
// ignoreDefaults set.
var defaultDupesIgnores = []string{
	"**/.next/**", "**/.nuxt/**", "**/.svelte-kit/**", "**/.turbo/**",
	"**/.parcel-cache/**", "**/.vite/**", "**/.cache/**", "**/out/**",
	"**/storybook-static/**", "**/*.test.*", "**/*.spec.*", "**/__tests__/**",
	"**/__mocks__/**",
}

// HealthInput assembles a health.Input from the loaded context, including git
// churn and a coverage profile when requested.
type HealthInput struct {
	Options  health.Options
	Coverage string // explicit coverage path, "" to auto-detect or skip
	// ChurnWindow is the git history window for hotspots (a fallow-style
	// duration like "6m"); empty uses the default.
	ChurnWindow string
	// ChurnMinCommits filters hotspots; 0 uses the default.
	ChurnMinCommits int
	// DepSignals come from a dead-code run so the score can weigh deps,
	// cycles, and duplication.
	UnusedDeps  *int
	Cycles      *int
	Duplication *float64
	// Subset restricts counts, vital signs, and scores to one --group-by
	// bucket of project-relative paths. nil analyzes everything.
	Subset map[string]bool
}

// Health runs the health analysis over this context.
func (c *Context) Health(in HealthInput) *health.Result {
	var cov *health.Coverage
	if path := c.resolveCoveragePath(in.Coverage); path != "" {
		if c.covCache == nil {
			c.covCache = map[string]*health.Coverage{}
		}
		if cached, ok := c.covCache[path]; ok {
			cov = cached
		} else if parsed, err := health.ParseCoverage(path); err == nil {
			cov = parsed
			c.covCache[path] = cov
		}
	}
	churn := c.churnCached(in.ChurnWindow, in.ChurnMinCommits)
	opts := in.Options
	healthInput := health.Input{
		Facts: c.Proj, Graph: c.Graph, Cfg: c.Cfg, Cov: cov,
		Churn: churn, Opts: opts, ModulePath: c.Proj.Module.Path,
		UnusedDeps: in.UnusedDeps, Cycles: in.Cycles, Duplication: in.Duplication,
		Subset: in.Subset,
	}
	return health.Run(healthInput)
}

// churnCached memoizes churn history per window so a grouped run reads git
// once. The min-commits filter is applied downstream, so the cache key is
// the window alone.
func (c *Context) churnCached(window string, minCommits int) health.ChurnData {
	if c.churnCache == nil {
		c.churnCache = map[string]*health.ChurnData{}
	}
	if cached, ok := c.churnCache[window]; ok {
		out := *cached
		out.MinCommits = minCommits
		return out
	}
	cd := c.churn(window, minCommits)
	copyCD := cd
	c.churnCache[window] = &copyCD
	return cd
}

// resolveCoveragePath picks the coverage input: explicit arg, then config
// health.coverage, then an auto-detected coverage/coverage-final.json.
func (c *Context) resolveCoveragePath(explicit string) string {
	if explicit == "" {
		explicit = c.Cfg.Health.Coverage
	}
	if explicit != "" {
		return explicit
	}
	return ""
}

// churn loads git churn history for the hotspot window. Empty window is the
// fallow default (6 months); minCommits 0 keeps the default filter. It never
// fails the run.
func (c *Context) churn(window string, minCommits int) health.ChurnData {
	repo := gitx.Open(c.Cfg.Root)
	if !repo.Inside || !gitx.Available() {
		return health.ChurnData{}
	}
	if window == "" {
		window = "6m"
	}
	events, _, err := repo.LogNumstat(repo.Root, window)
	if err != nil {
		return health.ChurnData{}
	}
	cd := health.ChurnData{
		Available: true, Shallow: repo.Shallow,
		Since: churnWindowLabel(window), MinCommits: minCommits,
	}
	// Events carry the full history; the min-commits filter lives in the
	// hotspot pass, so cached copies can re-apply it per run.
	for _, ev := range events {
		cd.Events = append(cd.Events, health.ChurnEvent{
			Path: ev.Path, Timestamp: ev.Timestamp, Author: ev.Author,
			Added: ev.Added, Deleted: ev.Deleted,
		})
	}
	health.AggregateChurn(&cd, nowSec())
	return cd
}

// nowSec is split out so tests can freeze the clock.
var nowSec = func() int64 { return time.Now().Unix() }

// churnWindowLabel renders a duration window in the words used by the
// hotspot section header ("6m" → "6 months").
func churnWindowLabel(w string) string {
	if w == "" {
		return "6 months"
	}
	n := strings.TrimRight(w, "dwy")
	n = strings.TrimRight(n, "m")
	switch w[len(w)-1:] {
	case "d":
		if n == "1" {
			return "1 day"
		}
		return n + " days"
	case "w":
		if n == "1" {
			return "1 week"
		}
		return n + " weeks"
	case "m":
		if n == "1" {
			return "1 month"
		}
		return n + " months"
	case "y":
		if n == "1" {
			return "1 year"
		}
		return n + " years"
	}
	return w
}

// ---------------------------------------------------------------------------
// Standard library and unresolved imports.
// ---------------------------------------------------------------------------

var importErrRe = regexp.MustCompile(`^(.*?)(\d+):(\d+):.*?could not import ([^\s(]+)`)

// UnresolvedImports extracts import paths that failed to resolve, from the
// type-check errors. It reports the declaring file and line of the import.
func (c *Context) UnresolvedImports() []deadcode.UnresolvedImport {
	seen := map[string]bool{}
	var out []deadcode.UnresolvedImport
	for _, msg := range c.Loaded.TypeErrors {
		m := importErrRe.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		fileRaw, lineStr, _, spec := m[1], m[2], m[3], m[4]
		if IsStdPath(spec, c.Std) {
			continue
		}
		file := c.relFile(fileRaw)
		if file == "" {
			continue
		}
		key := file + "|" + spec
		if seen[key] {
			continue
		}
		seen[key] = true
		line := atoiDefault(lineStr, 1)
		out = append(out, deadcode.UnresolvedImport{
			Specifier: spec, File: file, Line: line, Package: importRoot(spec),
		})
	}
	return out
}

// IsStdPath reports membership in the standard library.
func IsStdPath(spec string, std map[string]bool) bool {
	if len(std) > 0 {
		return std[spec]
	}
	return deadcode.IsGorootStd(spec)
}

// importRoot extracts the module root of an import path.
func importRoot(spec string) string {
	parts := strings.Split(spec, "/")
	if len(parts) >= 2 && strings.HasPrefix(parts[0], "@") {
		return strings.Join(parts[:2], "/")
	}
	dots := 0
	for i, p := range parts {
		if strings.Contains(p, ".") {
			dots++
			if dots == 1 && i+1 < len(parts) && looksLikeScope(parts[i+1]) {
				return strings.Join(parts[:2], "/")
			}
			return strings.Join(parts[:i+1], "/")
		}
	}
	return spec
}

func looksLikeScope(s string) bool {
	return !strings.Contains(s, ".") && len(s) <= 40
}

// relFile turns a possibly absolute or /-prefixed filename into a module-
// relative path.
func (c *Context) relFile(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "\\", "/")
	// Exact or suffix match against a known project file.
	for path, ff := range c.Proj.Files {
		if path == raw || strings.HasSuffix(path, "/"+raw) || strings.HasSuffix(raw, "/"+baseOf(path)) && strings.Contains(path, raw) {
			return ff.Rel
		}
	}
	if c.Proj.Module.Dir != "" && strings.HasPrefix(raw, c.Proj.Module.Dir+"/") {
		return strings.TrimPrefix(raw, c.Proj.Module.Dir+"/")
	}
	return raw
}

// addNextSteps appends the suggested follow-up commands.
func addNextSteps(doc *report.Doc, production bool) {
	if doc.TotalIssues() == 0 {
		return
	}
	doc.NextSteps = append(doc.NextSteps,
		report.NextStep{Command: "goose fix --dry-run", Description: "Preview the auto-fixes for the dead code."},
		report.NextStep{Command: "goose fix", Description: "Remove the unused code."},
	)
	if !production {
		doc.NextSteps = append(doc.NextSteps,
			report.NextStep{Command: "goose dead-code --save-baseline goose-baseline.json", Description: "Save the current issues so only new ones fail CI."},
		)
	}
}

func baseOf(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func atoiDefault(s string, def int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return def
	}
	return n
}
