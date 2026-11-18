package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"goose/internal/architecture"
	"goose/internal/config"
	"goose/internal/deadcode"
	"goose/internal/dupes"
	"goose/internal/engine"
	goosefix "goose/internal/fix"
	"goose/internal/gitx"
	"goose/internal/health"
	"goose/internal/report"
	"goose/internal/version"
)

// Command is one subcommand.
type Command struct {
	Name       string
	Summary    string
	Run        func(ctx context.Context, f *Flags) int
	BoolFlags  []string
	ValueFlags map[string]func(*Flags, string) error
}

// registry keeps commands in help order.
var registry []*Command

// Register adds a command and wires its flags into the parser.
func Register(c *Command) {
	registry = append(registry, c)
	registerCommandFlags(c.Name, c.BoolFlags, c.ValueFlags)
}

// Run executes argv (without the program name) and returns the exit code.
func Run(ctx context.Context, argv []string) int {
	registerCommands()
	// --help with no command prints the command list.
	if len(argv) == 0 {
		return parseAndRunCombined(ctx, argv)
	}
	// The first positional before any flag is the subcommand.
	cmdName, rest := splitCommand(argv)
	if cmdName == "" {
		return parseAndRunCombined(ctx, argv)
	}
	if cmdName == "help" {
		printHelp()
		return 0
	}
	for _, c := range registry {
		if c.Name == cmdName {
			f, err := Parse(rest)
			if err != nil {
				return usage(err)
			}
			if f.Help {
				fmt.Printf("goose %s — %s\n", c.Name, c.Summary)
				return 0
			}
			if len(f.Group) > 0 && (c.Name != "health" || f.GroupBy == "") {
				return usage(ErrUsage{"--group is valid with `goose health --group-by` only"})
			}
			if err := validateRunFlags(c.Name, f); err != nil {
				return usage(err)
			}
			applyThreads(f)
			return c.Run(ctx, f)
		}
	}
	// A positional that is not a command is a path scope for the combined run.
	return parseAndRunCombined(ctx, argv)
}

func parseAndRunCombined(ctx context.Context, argv []string) int {
	f, err := Parse(argv)
	if err != nil {
		return usage(err)
	}
	if err := validateRunFlags("", f); err != nil {
		return usage(err)
	}
	applyThreads(f)
	return runCombined(ctx, f)
}

// applyThreads bounds the Go scheduler with --threads. go/packages caps its
// parallel load and type-check work at runtime.GOMAXPROCS(0), so this is the
// honest lever for load-phase parallelism; the analyses themselves are
// single-pass and read the one shared snapshot.
func applyThreads(f *Flags) {
	if f.Threads > 0 {
		runtime.GOMAXPROCS(f.Threads)
	}
}

// splitCommand pulls a leading subcommand name (or alias) out of argv,
// resolving it to its canonical command name.
func splitCommand(argv []string) (string, []string) {
	if len(argv) == 0 || isFlag(argv[0]) {
		return "", argv
	}
	known := map[string]string{}
	for _, c := range registry {
		known[c.Name] = c.Name
	}
	for alias, canon := range aliases {
		known[alias] = canon
	}
	canon, ok := known[argv[0]]
	if !ok {
		return "", argv
	}
	return canon, argv[1:]
}

var aliases = map[string]string{
	"check": "dead-code",
}

func usage(err error) int {
	os.Stderr.WriteString("goose: " + err.Error() + "\n")
	return 2
}

// ---------------------------------------------------------------------------
// Shared run plumbing.
// ---------------------------------------------------------------------------

// runContext loads config plus the engine context for a run.
func runContext(ctx context.Context, f *Flags) (*engine.Context, *config.Config, error) {
	return buildRunContext(ctx, f, f.NoTypeAware)
}

// runSyntaxContext loads config plus a syntax-only engine context for commands
// that do not require go/types resolution (dupes, list, architecture).
func runSyntaxContext(ctx context.Context, f *Flags) (*engine.Context, *config.Config, error) {
	return buildRunContext(ctx, f, true)
}

func buildRunContext(ctx context.Context, f *Flags, syntaxOnly bool) (*engine.Context, *config.Config, error) {
	root := f.Root
	if root == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, err
	}
	cfg, warns, err := config.Discover(loadOptions(f, abs))
	if err != nil {
		return nil, nil, err
	}
	if !f.Quiet && cfg.LoadedFrom != "" && f.Format == "human" {
		fmt.Fprintf(os.Stderr, "loaded config: %s\n", cfg.LoadedFrom)
	}
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, w)
	}
	applyProduction(f, cfg)
	if f.MaxFileSizeSet {
		v := f.MaxFileSizeMB
		cfg.Analysis.MaxFileSizeMb = &v
	}
	cfg.NoCache = f.NoCache
	tests := !cfg.ProdFor("dead-code") || !f.Production
	var ec *engine.Context
	if syntaxOnly {
		ec, err = engine.LoadSyntaxAndBuild(ctx, cfg, tests)
	} else {
		ec, err = engine.LoadAndBuild(ctx, cfg, tests)
	}
	if err != nil {
		return nil, cfg, err
	}
	ec.Cfg = cfg
	return ec, cfg, nil
}

func loadOptions(f *Flags, root string) config.LoadOptions {
	return config.LoadOptions{
		Root:   root,
		Config: f.Config,
	}
}

func applyProduction(f *Flags, cfg *config.Config) {
	if f.NoProduction {
		cfg.Production = config.ProductionMode{}
	}
	if f.Production {
		cfg.Production = config.ProductionMode{Enabled: true, DeadCode: true, Health: true, Dupes: true}
	}
	// Production mode analyzes a subset of the project, so a baseline saved
	// from a full run can never be judged by it (fallow counts production as
	// a change-scope reason).
	if cfg.Production.Enabled {
		f.BaselineScoped = true
	}
}

// renderOptions maps flags to report options.
func renderOptions(f *Flags, root string) report.Options {
	prefix := f.ReportPathPrefix
	if prefix == "" {
		prefix = reportPathPrefix(root)
	}
	o := report.Options{
		Format:  f.Format,
		Pretty:  f.Pretty,
		Lean:    f.Lean,
		Colors:  colorsEnabled(f),
		Details: f.Format == "github-summary" || f.Format == "pr-comment-github" || f.Format == "review-github",
		Explain: f.Explain,
		Quiet:   f.Quiet,
		Summary: f.SummaryOnly,
		Prefix:  prefix,
		Version: version.Version,
	}
	if f.Ownership != nil {
		o.Ownership = f.Ownership
	}
	return o
}

// colorsEnabled turns ANSI on for a terminal human run.
func colorsEnabled(f *Flags) bool {
	if f.Format != "human" || f.Quiet || os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// reportPathPrefix adds the offset between --root and the git toplevel, so CI
// annotations land in the right file.
func reportPathPrefix(root string) string {
	repo := gitx.Open(root)
	if !repo.Inside || repo.Root == root {
		return ""
	}
	if strings.HasPrefix(root, repo.Root+"/") {
		return strings.TrimPrefix(strings.TrimPrefix(root, repo.Root), "/")
	}
	return ""
}

// emit writes the rendered document, honoring --output-file and the gate exit
// code, and returns the process exit code.
func emit(f *Flags, doc *report.Doc, root string, machineExitsClean bool) int {
	opts := renderOptions(f, root)
	if f.Ownership != nil && !f.Quiet {
		// Formats that cannot carry grouping render one flat document and
		// say so; SARIF and CodeClimate annotate each result instead.
		report.PrintGroupingNote(f.Format, f.Ownership.Mode)
	}
	text := doc.Render(opts)
	writeOutput(f, text)
	gateLine := doc.GateSummaryLine()
	if gateLine != "" && !f.Quiet && f.Format != "json" {
		fmt.Fprintln(os.Stderr, gateLine)
	}
	machine := f.Format != "" && f.Format != "human" && f.Format != "compact" && f.Format != "markdown"
	code := doc.ExitCode(f.FailOnIssues, machine && machineExitsClean)
	if f.FailOnParseError && parseFailure(doc) {
		code = 1
	}
	return code
}

func writeOutput(f *Flags, text string) {
	if f.OutputFile != "" {
		if err := os.WriteFile(f.OutputFile, []byte(text), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "goose: cannot write %s: %v\n", f.OutputFile, err)
			os.Exit(2)
		}
		if !f.Quiet {
			fmt.Fprintf(os.Stderr, "Report written to %s\n", f.OutputFile)
		}
		return
	}
	os.Stdout.WriteString(text)
	if !strings.HasSuffix(text, "\n") {
		os.Stdout.WriteString("\n")
	}
}

func parseFailure(doc *report.Doc) bool {
	for _, d := range doc.Diagnostics {
		if d.Kind == "source-parse-degraded" {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------

func registerCommands() {
	if registered {
		return
	}
	registered = true

	Register(&Command{
		Name:    "dead-code",
		Summary: "Find unused code: files, symbols, fields, methods, dependencies",
		Run:     runDeadCode,
		BoolFlags: []string{"--unused-files", "--unused-exports", "--unused-unexported",
			"--unused-types", "--unused-fields", "--unused-methods", "--unused-deps",
			"--unlisted-deps", "--unresolved", "--stale-suppressions", "--no-colors"},
		ValueFlags: map[string]func(*Flags, string) error{
			"--trace":      store("--trace"),
			"--trace-file": store("--trace-file"),
		},
	})

	Register(&Command{
		Name:    "dupes",
		Summary: "Find duplicated code blocks (clone groups and families)",
		Run:     runDupes,
		BoolFlags: []string{"--near", "--skip-local", "--cross-language",
			"--ignore-imports", "--no-ignore-imports", "--ignore-symlinks",
			"--no-ignore-symlinks", "--no-fragments", "--summary", "--explain"},
		ValueFlags: map[string]func(*Flags, string) error{
			"--mode":                   store("--mode"),
			"--min-tokens":             storeInt("--min-tokens"),
			"--min-lines":              storeInt("--min-lines"),
			"--min-occurrences":        storeInt("--min-occurrences"),
			"--threshold":              store("--threshold"),
			"--top":                    storeInt("--top"),
			"--baseline":               func(f *Flags, v string) error { f.Baseline = v; return nil },
			"--save-baseline":          func(f *Flags, v string) error { f.SaveBaseline = v; return nil },
			"--fail-on-stale-baseline": func(f *Flags, _ string) error { f.FailOnStaleBaseline = true; return nil },
			"--trace":                  store("--trace"),
		},
	})

	Register(&Command{
		Name:    "audit",
		Summary: "Changed-file quality gate: dead code, complexity, and duplication with a verdict",
		Run:     runAudit,
		BoolFlags: []string{"--production-dead-code", "--production-health",
			"--production-dupes", "--brief", "--no-colors"},
		ValueFlags: map[string]func(*Flags, string) error{
			"--gate":               store("--gate"),
			"--worsened":           store("--worsened"),
			"--dead-code-baseline": store("--dead-code-baseline"),
			"--health-baseline":    store("--health-baseline"),
			"--dupes-baseline":     store("--dupes-baseline"),
			"--coverage":           store("--coverage"),
		},
	})

	Register(&Command{
		Name:    "review",
		Summary: "Advisory audit brief (audit --brief); always exits 0",
		Run: func(ctx context.Context, f *Flags) int {
			f.BoolExtra["--brief"] = true
			return runAudit(ctx, f)
		},
		BoolFlags: []string{"--production-dead-code", "--production-health",
			"--production-dupes", "--brief", "--no-colors"},
	})

	Register(&Command{
		Name:      "list",
		Summary:   "Inventory the project: files, entry points, boundaries, suppressions",
		Run:       runList,
		BoolFlags: []string{"--files", "--entry-points", "--boundaries", "--suppressions", "--no-colors"},
	})

	Register(&Command{
		Name:      "fix",
		Summary:   "Auto-remove unused code: files, symbols, stale suppressions, unused deps",
		Run:       runFix,
		BoolFlags: []string{"--dry-run", "--yes", "--force"},
	})

	Register(&Command{
		Name:      "architecture",
		Summary:   "Import cycles, boundary violations, and rule-pack policy violations",
		Run:       runArchitecture,
		BoolFlags: []string{"--cycles", "--boundaries", "--policy", "--no-colors"},
	})

	Register(&Command{
		Name:      "health",
		Summary:   "Code health: complexity, hotspots, file scores, refactoring targets, score",
		Run:       runHealth,
		BoolFlags: []string{"--report-only", "--coverage-gaps", "--no-colors"},
		ValueFlags: map[string]func(*Flags, string) error{
			"--coverage":    store("--coverage"),
			"--sort":        store("--sort"),
			"--top":         storeInt("--top"),
			"--min-commits": storeInt("--min-commits"),
		},
	})

	Register(&Command{
		Name: "explain", Summary: "Explain one issue type",
		Run: runExplain,
	})

	Register(&Command{
		Name: "version", Summary: "Print the tools version",
		Run: func(ctx context.Context, f *Flags) int {
			fmt.Println("goose " + version.Version)
			return 0
		},
	})

	Register(&Command{
		Name:      "init",
		Summary:   "Create a goose config file",
		Run:       runInit,
		BoolFlags: []string{"--toml"},
	})

	Register(&Command{
		Name:      "all",
		Summary:   "Run all four engines: dead-code, architecture, health, and dupes",
		BoolFlags: []string{"--coverage-gaps", "--no-colors"},
		ValueFlags: map[string]func(*Flags, string) error{
			"--coverage": store("--coverage"),
		},
		Run: func(ctx context.Context, f *Flags) int {
			f.All = true
			return runAnalysis(ctx, f, "all")
		},
	})

	Register(&Command{
		Name:    "mcp",
		Summary: "Start Model Context Protocol (MCP) server over stdio",
		Run:     runMCP,
	})
}

var registered bool

func store(name string) func(*Flags, string) error {
	return func(f *Flags, v string) error {
		f.Extra[name] = v
		return nil
	}
}

// storeInt records a numeric option after validating it parses as an int.
func storeInt(name string) func(*Flags, string) error {
	return func(f *Flags, v string) error {
		if _, err := strconv.Atoi(v); err != nil {
			return ErrUsage{name + " needs an integer"}
		}
		f.Extra[name] = v
		return nil
	}
}

// runDeadCode implements goose dead-code (alias check), and the bare combined
// run.
func runDeadCode(ctx context.Context, f *Flags) int {
	return runAnalysis(ctx, f, "dead-code")
}

// runDupes implements goose dupes: clone groups, families, gates, and
// baselines, with the fallow exit contract.
func runDupes(ctx context.Context, f *Flags) int {
	start := time.Now()
	ec, cfg, err := runSyntaxContext(ctx, f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	if len(f.Args) > 0 && f.Path == "" {
		f.Path = f.Args[0]
		f.Args = f.Args[1:]
	}

	opts := dupes.FromConfig(cfg)
	if v := f.Extra["--mode"]; v != "" {
		switch v {
		case "strict", "mild", "weak", "semantic":
			opts.Mode = dupes.Mode(v)
		default:
			return usage(ErrUsage{"--mode must be strict, mild, weak, or semantic"})
		}
	}
	for _, pair := range []struct {
		flag string
		dst  *int
	}{
		{"--min-tokens", &opts.MinTokens},
		{"--min-lines", &opts.MinLines},
		{"--min-occurrences", &opts.MinOccurrences},
	} {
		if v := f.Extra[pair.flag]; v != "" {
			n, _ := strconv.Atoi(v)
			*pair.dst = n
		}
	}
	if opts.MinOccurrences < 2 {
		opts.MinOccurrences = 2
	}
	if opts.MinTokens < 8 {
		opts.MinTokens = 8
	}
	if opts.MinLines < 2 {
		opts.MinLines = 2
	}
	opts.SkipLocal = opts.SkipLocal || f.BoolExtra["--skip-local"]
	if f.BoolExtra["--no-ignore-imports"] {
		opts.IgnoreImports = false
	}
	if f.BoolExtra["--no-fragments"] {
		opts.Fragments = false
	}
	if f.Path != "" {
		opts.PathScope = f.Path
	}
	changed, err := changedScope(f, ec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	diffScoped := changed != nil
	res := ec.Dupes(opts, changed)
	if diffScoped {
		var kept []dupes.Group
		for _, g := range res.Groups {
			match := false
			for _, inst := range g.Instances {
				if changed[inst.Path] {
					match = true
					break
				}
			}
			if match {
				kept = append(kept, g)
			}
		}
		res.Groups = kept
		res.Stats.CloneGroups = len(kept)
	}

	if target := f.Extra["--trace"]; target != "" {
		return traceDupes(res, target)
	}

	var st *dupes.Staleness
	if f.Baseline != "" {
		b, err := dupes.LoadBaseline(f.Baseline)
		if err != nil {
			fmt.Fprintln(os.Stderr, "goose:", err)
			return 2
		}
		n := dupes.ApplyBaseline(res, b)
		st = &dupes.Staleness{BaselineEntries: len(b.Entries), StaleEntries: n, CurrentEntries: len(res.Groups)}
	}
	if f.SaveBaseline != "" {
		if err := dupes.SaveBaseline(f.SaveBaseline, res, version.Version); err != nil {
			fmt.Fprintln(os.Stderr, "goose: cannot save baseline:", err)
			return 2
		}
		if !f.Quiet {
			fmt.Fprintf(os.Stderr, "Baseline saved to %s\n", f.SaveBaseline)
		}
	}

	threshold := 0.0
	if v := f.Extra["--threshold"]; v != "" {
		threshold, _ = strconv.ParseFloat(v, 64)
	}
	if threshold <= 0 {
		threshold = cfg.Duplicates.Threshold
	}
	top := 0
	if v := f.Extra["--top"]; v != "" {
		top, _ = strconv.Atoi(v)
	}
	if top > 0 && f.GroupBy != "" {
		return usage(ErrUsage{"--top and --group-by cannot be combined on dupes"})
	}
	own, err := buildOwnership(f, ec, cfg)
	if err != nil {
		if _, isUsage := err.(ErrUsage); isUsage {
			return usage(err)
		}
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	f.Ownership = own
	elapsedMS := time.Since(start).Milliseconds()
	if elapsedMS < 1 {
		elapsedMS = 1
	}
	doc := res.Doc(threshold, f.FailOnIssues, opts.Fragments, elapsedMS)
	doc.ElapsedMS = elapsedMS
	if st != nil {
		doc.Envelope["baseline_staleness"] = st
	}
	if f.FailOnStaleBaseline && st != nil && st.StaleEntries > 0 {
		doc.Gates["stale-baseline"] = &report.Gate{Status: "failed", Enforced: true, Observed: st.StaleEntries, Threshold: 0}
	}

	if f.Format == "human" {
		if f.SummaryOnly {
			fmt.Printf("%d clone groups · %d lines (%.2f%%) duplicated across %d files (%d analyzed)\n",
				res.Stats.CloneGroups, res.Stats.DuplicatedLines, res.Stats.DuplicationPercentage,
				res.Stats.FilesWithDuplication, res.Stats.FilesAnalyzed)
		} else if own != nil {
			fmt.Print(dupesGroupedHuman(res, own))
			if st != nil && st.StaleEntries*4 >= st.BaselineEntries && st.BaselineEntries > 0 {
				fmt.Fprintf(os.Stderr, "goose: %d of %d baseline entries no longer match anything; save the baseline again.\n", st.StaleEntries, st.BaselineEntries)
			}
			if groupDupesFails(threshold, res, f, st) {
				return 1
			}
			return 0
		} else if top > 0 && len(res.Groups) > top {
			fmt.Print(dupesHuman(top, 0, f.ChangedSince, res.Stats, res.Groups, true))
		} else {
			fmt.Print(dupesHuman(0, 0, f.ChangedSince, res.Stats, res.Groups, false))
		}
		if st != nil && st.StaleEntries*4 >= st.BaselineEntries && st.BaselineEntries > 0 {
			fmt.Fprintf(os.Stderr, "goose: %d of %d baseline entries no longer match anything; save the baseline again.\n", st.StaleEntries, st.BaselineEntries)
		}
		mark := "✓"
		if threshold > 0 && res.Stats.DuplicationPercentage > threshold {
			fmt.Fprintf(os.Stderr, "Duplication (%.1f%%) exceeds threshold (%.1f%%)\n", res.Stats.DuplicationPercentage, threshold)
			mark = "✗"
			_ = mark
			return 1
		}
		if f.FailOnIssues && len(res.Groups) > 0 {
			return 1
		}
		if f.FailOnStaleBaseline && st != nil && st.StaleEntries > 0 {
			return 1
		}
		return 0
	}
	if top > 0 {
		// A presentation cap: keep the top groups for non-human formats too.
		if top < len(res.Groups) {
			doc2 := (&dupes.Result{Groups: res.Groups[:top], Families: res.Families, Stats: res.Stats}).Doc(threshold, f.FailOnIssues, opts.Fragments, elapsedMS)
			doc2.Envelope["clone_groups_shown"] = top
			doc2.Envelope["clone_groups_omitted"] = len(res.Groups) - top
			doc2.ElapsedMS = elapsedMS
			doc = doc2
		}
	}
	return emit(f, doc, cfg.Root, true)
}

// groupDupesFails applies the fallow exit rules under a grouped human run.
func groupDupesFails(threshold float64, res *dupes.Result, f *Flags, st *dupes.Staleness) bool {
	if threshold > 0 && res.Stats.DuplicationPercentage > threshold {
		fmt.Fprintf(os.Stderr, "Duplication (%.1f%%) exceeds threshold (%.1f%%)\n", res.Stats.DuplicationPercentage, threshold)
		return true
	}
	if f.FailOnIssues && len(res.Groups) > 0 {
		return true
	}
	if f.FailOnStaleBaseline && st != nil && st.StaleEntries > 0 {
		return true
	}
	return false
}

// dupesGroupedHuman prints one block of clone groups per bucket, attributed
// by largest owner (ties alphabetically), like fallow's dupes --group-by.
func dupesGroupedHuman(res *dupes.Result, own *report.Ownership) string {
	buckets := map[string][]dupes.Group{}
	for _, g := range res.Groups {
		counts := map[string]int{}
		for _, in := range g.Instances {
			counts[own.Key(in.Path)]++
		}
		best, bestN := report.UnownedLabel, -1
		for k := range counts {
			n := counts[k]
			if n > bestN || (n == bestN && k < best) {
				best, bestN = k, n
			}
		}
		buckets[best] = append(buckets[best], g)
	}
	keys := make([]string, 0, len(buckets))
	totals := map[string]int{}
	for k := range buckets {
		keys = append(keys, k)
		totals[k] = len(buckets[k])
	}
	report.SortGroupKeys(keys, totals)
	var b strings.Builder
	b.WriteString("── Duplication ─────────────────────────────────────\n")
	fmt.Fprintf(&b, "\nGrouped by %s\n", own.Mode)
	for _, k := range keys {
		suffix := "s"
		if len(buckets[k]) == 1 {
			suffix = ""
		}
		fmt.Fprintf(&b, "\n◆ %s (%d clone group%s)\n", k, len(buckets[k]), suffix)
		block := dupesHuman(0, 0, "", res.Stats, buckets[k], false)
		// Drop the per-bucket banner and stats footer; the grouping matrix
		// renders one of each.
		if nl := strings.Index(block, "\n"); nl >= 0 {
			block = block[nl:]
		}
		if i := strings.LastIndex(block, "\n\u2713 "); i >= 0 {
			block = block[:i+1]
		} else if i := strings.LastIndex(block, "\n\u2717 "); i >= 0 {
			block = block[:i+1]
		}
		b.WriteString(block)
	}
	fmt.Fprintf(&b, "\n\u2713 %d lines (%.1f%%) duplicated across %d files (%d analyzed)\n",
		res.Stats.DuplicatedLines, res.Stats.DuplicationPercentage,
		res.Stats.FilesWithDuplication, res.Stats.FilesAnalyzed)
	return b.String()
}

// architectureKinds are the finding kinds the architecture surface reports.
var architectureKinds = map[string]bool{
	"circular-dependency": true,
	"package-cycle":       true,
	"boundary-violation":  true,
	"boundary-coverage":   true,
	"policy-violation":    true,
	"deep-import":         true,
}

// archOptions maps selector flags to the analysis options.
func archOptions(f *Flags, cfg *config.Config) architecture.Options {
	sel := architecture.Options{
		Cycles:     f.BoolExtra["--cycles"],
		Boundaries: f.BoolExtra["--boundaries"],
		Policy:     f.BoolExtra["--policy"],
		Production: f.Production || cfg.ProdFor("architecture"),
	}
	sel.SelectorsSet = sel.Cycles || sel.Boundaries || sel.Policy
	return sel
}

// requestedRuleOffNotes prints fallow's requested_rule_off notes: an explicit
// selector naming a rule that config switched off is worth a stderr line.
func requestedRuleOffNotes(f *Flags, sel architecture.Options, cfg *config.Config) {
	if f.Quiet || !sel.SelectorsSet {
		return
	}
	for _, pair := range []struct {
		wanted bool
		rule   string
		flag   string
	}{
		{sel.Cycles, "circular-dependencies", "--cycles"},
		{sel.Boundaries, "boundary-violation", "--boundaries"},
		{sel.Policy, "policy-violation", "--policy"},
	} {
		if pair.wanted && cfg.RuleSeverity(pair.rule, "") == config.Off {
			fmt.Fprintf(os.Stderr, "Note: %s is off in config, so %s did not check it.\n", pair.rule, pair.flag)
		}
	}
}

// runFix implements goose fix: it plans the removal of every auto-fixable
// finding, previews the plan with --dry-run, and applies it with --yes,
// rolling everything back when the module stops building.
func runFix(ctx context.Context, f *Flags) int {
	dryRun := f.BoolExtra["--dry-run"]
	yes := f.BoolExtra["--yes"] || f.BoolExtra["--force"]
	if !dryRun && !yes {
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprint(os.Stderr, "goose fix rewrites source files. Type yes to continue: ")
			var answer string
			_, _ = fmt.Fscanln(os.Stdin, &answer)
			if strings.TrimSpace(answer) == "yes" {
				yes = true
			}
		}
		if !yes {
			msg := "fix command requires --yes in non-interactive environments. Use --dry-run to preview changes first, then pass --yes to confirm."
			if f.Format == "json" {
				writeOutput(f, report.ErrorJSONWith(map[string]any{
					"kind": "error", "message": msg,
					"code":      "GOOSE_FIX_CONFIRMATION_REQUIRED",
					"help":      "Run `goose fix --dry-run` and review the preview, then pass --yes to apply the approved changes.",
					"exit_code": 2,
				}))
			} else {
				fmt.Fprintln(os.Stderr, "goose: "+msg)
			}
			return 2
		}
	}

	ec, cfg, err := runContext(ctx, f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	doc := ec.DeadCode(deadcode.Options{
		Production:          cfg.ProdFor("dead-code") || f.Production,
		IncludeEntryExports: f.IncludeEntryExports || cfg.IncludeEntryExports,
	})
	plan := goosefix.Build(cfg.Root, doc.Findings)

	if dryRun {
		writeOutput(f, fixJSON(plan, true, nil))
		if !f.Quiet && f.Format != "json" {
			fmt.Fprint(os.Stderr, fixHumanPreview(plan))
		}
		return 0
	}

	res := plan.Apply(cfg.Root)
	writeOutput(f, fixJSON(&res.Plan, false, res))
	if !f.Quiet && f.Format != "json" {
		if res.BuildOK {
			fmt.Fprintf(os.Stderr, "Removed %d items. The build passes.\n", res.AutoFixes)
		} else {
			fmt.Fprintf(os.Stderr, "goose: fix rolled back; the build failed after the edits:\n%s\n", res.BuildErr)
		}
	}
	if !res.BuildOK {
		return 1
	}
	return 0
}

// fixJSON renders the fix envelope shared by dry-run and apply.
func fixJSON(plan *goosefix.Plan, dry bool, res *goosefix.Result) string {
	fixes := make([]any, 0, len(plan.Targets)+len(plan.Files)+len(plan.ModTidy))
	for _, t := range plan.Targets {
		fixes = append(fixes, map[string]any{
			"type": fixTypeFor(t.Kind), "path": relOf(plan, t.File),
			"name": t.Symbol, "line": t.Line, "kind": t.Kind,
		})
	}
	for _, fp := range plan.Files {
		fixes = append(fixes, map[string]any{
			"type": "remove_file", "path": relOf(plan, fp), "kind": "unused-file",
		})
	}
	for _, m := range plan.ModTidy {
		fixes = append(fixes, map[string]any{
			"type": "remove_dependency", "package": m, "path": "go.mod",
			"kind": "unused-dependency",
		})
	}
	root := map[string]any{
		"kind":           "fix",
		"schema_version": version.SchemaVersion,
		"version":        version.Version,
		"dry_run":        dry,
		"fixes":          fixes,
		"summary": map[string]any{
			"auto_fixes": plan.AutoFixes,
			"files":      len(plan.Files),
			"edits":      plan.Edits,
			"skipped":    plan.Skipped,
		},
	}
	if res != nil {
		root["applied"] = res.Applied
		root["build_ok"] = res.BuildOK
		root["rolled_back"] = res.RolledBack
		if res.BuildErr != "" && !res.BuildOK {
			root["build_error"] = res.BuildErr
		}
	}
	s, err := report.JSONString(root)
	if err != nil {
		return "{}"
	}
	return s
}

// relOf renders absolute plan paths as module-relative.
func relOf(plan *goosefix.Plan, abs string) string {
	if plan.Root != "" && strings.HasPrefix(abs, plan.Root+"/") {
		return strings.TrimPrefix(abs, plan.Root+"/")
	}
	return abs
}

func fixTypeFor(kind string) string {
	switch kind {
	case "unused-export":
		return "remove_export"
	case "unused-method":
		return "remove_method"
	case "unused-field":
		return "remove_field"
	case "unused-type":
		return "remove_type"
	case "unused-dependency":
		return "remove_dependency"
	case "stale-suppression":
		return "remove_suppression"
	}
	return "remove_symbol"
}

// fixHumanPreview lists what a dry run would remove, one line each.
func fixHumanPreview(plan *goosefix.Plan) string {
	var b strings.Builder
	if plan.AutoFixes == 0 && len(plan.ModTidy) == 0 {
		b.WriteString("Nothing to fix.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "Would remove %d items (%d files edited, %d deleted):\n", plan.AutoFixes+len(plan.ModTidy), plan.Edits, len(plan.Files))
	for _, t := range plan.Targets {
		label := t.Symbol
		if t.Recv != "" {
			label = t.Recv + "." + t.Symbol
		}
		if t.Kind == "stale-suppression" {
			label = "suppression " + t.Comment
		}
		fmt.Fprintf(&b, "  - %s %s :%d\n", fixTypeFor(t.Kind), label, t.Line)
	}
	for _, fp := range plan.Files {
		fmt.Fprintf(&b, "  - remove_file %s\n", fp)
	}
	for _, m := range plan.ModTidy {
		fmt.Fprintf(&b, "  - remove_dependency %s (go.mod)\n", m)
	}
	b.WriteString("\nApply with: goose fix --yes\n")
	return b.String()
}

// runArchitecture implements goose architecture, mirroring the dead-code
// surface: same envelope plumbing, own kind and schema version.
func runArchitecture(ctx context.Context, f *Flags) int {
	start := time.Now()
	ec, cfg, err := runSyntaxContext(ctx, f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	if len(f.Args) > 0 && f.Path == "" {
		f.Path = f.Args[0]
		f.Args = f.Args[1:]
	}
	sel := archOptions(f, cfg)
	requestedRuleOffNotes(f, sel, cfg)
	doc, _, err := ec.Architecture(sel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	if err := scopeFilter(f, ec, doc); err != nil {
		return usage(err)
	}
	baselinePass(f, doc, cfg.Root)
	own, err := buildOwnership(f, ec, cfg)
	if err != nil {
		if _, isUsage := err.(ErrUsage); isUsage {
			return usage(err)
		}
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	f.Ownership = own
	ms := time.Since(start).Milliseconds()
	if ms < 1 {
		ms = 1
	}
	doc.ElapsedMS = ms
	return emit(f, doc, cfg.Root, true)
}

// mergeArchitecture adds architecture findings to a dead-code/combined doc,
// like fallow's dead-code still reporting structure findings, and prints the
// hint pointing at the dedicated command.
func mergeArchitecture(f *Flags, ec *engine.Context, cfg *config.Config, doc *report.Doc) int {
	sel := architecture.Options{Production: f.Production || cfg.ProdFor("architecture")}
	_, res, err := ec.Architecture(sel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	if len(res.Findings) > 0 {
		doc.Findings = append(doc.Findings, res.Findings...)
		doc.Diagnostics = append(doc.Diagnostics, res.Diags...)
		for _, x := range res.Findings {
			n, _ := doc.Summary["total_issues"].(int)
			doc.Summary["total_issues"] = n + 1
			key := report.CamelCountKey(x.Kind)
			c, _ := doc.Summary[key].(int)
			doc.Summary[key] = c + 1
		}
		if !f.Quiet && f.Format == "human" {
			fmt.Fprintln(os.Stderr, "Tip: run `goose architecture` for import cycles, boundaries and policy rules.")
		}
	}
	return 0
}

// applyArchitectureOnlySkip implements bare-run --only/--skip architecture.
func applyArchitectureOnlySkip(f *Flags, doc *report.Doc) {
	keepArch := false
	dropArch := false
	for _, o := range f.Only {
		if o == "architecture" {
			keepArch = true
		}
	}
	for _, s := range f.Skip {
		if s == "architecture" {
			dropArch = true
		}
	}
	if !keepArch && !dropArch {
		return
	}
	var kept []*report.Finding
	for _, x := range doc.Findings {
		isArch := architectureKinds[x.Kind]
		if keepArch && !isArch {
			continue
		}
		if dropArch && isArch {
			continue
		}
		kept = append(kept, x)
	}
	doc.Findings = kept
}

// runHealth implements goose health: complexity findings, file scores,
// hotspots, refactoring targets, and the project score, with the fallow
// gate contract (error-severity findings or a score below --min-score fail).
func runHealth(ctx context.Context, f *Flags) int {
	ec, cfg, err := runContext(ctx, f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	changed, err := changedScope(f, ec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	diffScoped := changed != nil
	if len(f.Args) > 0 && f.Path == "" {
		f.Path = f.Args[0]
		f.Args = f.Args[1:]
	}
	opts := health.Options{
		Complexity:   true,
		FileScores:   true,
		Hotspots:     true,
		Targets:      true,
		CoverageGaps: f.BoolExtra["--coverage-gaps"],
		Score:        f.Score,
		MinScore:     f.MinScore,
		MinSeverity:  f.MinSeverity,
		ReportOnly:   f.BoolExtra["--report-only"],
		Production:   f.Production || cfg.ProdFor("health"),
	}
	for _, s := range f.Skip {
		switch s {
		case "complexity":
			opts.Complexity = false
		case "files", "file-scores":
			opts.FileScores = false
		case "hotspots":
			opts.Hotspots = false
		case "targets":
			opts.Targets = false
		case "score":
			opts.Score = false
		}
	}
	if len(f.Only) > 0 {
		opts.Complexity, opts.FileScores, opts.Hotspots, opts.Targets = false, false, false, false
		for _, s := range f.Only {
			switch s {
			case "complexity":
				opts.Complexity = true
			case "files", "file-scores":
				opts.FileScores = true
			case "hotspots":
				opts.Hotspots = true
			case "targets":
				opts.Targets = true
			case "score":
				opts.Score = true
			}
		}
	}

	// The score weighs dead-code and architecture signals; run the cheap
	// parts of those analyses to feed it.
	var unusedDeps, cycles *int
	if opts.Score {
		doc := ec.DeadCode(deadcode.Options{Production: cfg.ProdFor("dead-code")})
		n := 0
		for _, x := range doc.Findings {
			if !x.Hidden && x.Kind == "unused-dependency" {
				n++
			}
		}
		unusedDeps = &n
		c := len(ec.Graph.Cycles())
		cycles = &c
	}

	minCommits := 0
	if v := f.Extra["--min-commits"]; v != "" {
		minCommits, _ = strconv.Atoi(v)
	}
	res := ec.Health(engine.HealthInput{
		Options:         opts,
		Coverage:        f.Extra["--coverage"],
		ChurnWindow:     f.ChurnSince,
		ChurnMinCommits: minCommits,
		UnusedDeps:      unusedDeps,
		Cycles:          cycles,
	})
	if f.Path != "" {
		scopeHealth(res, f.Path)
	}
	if diffScoped {
		filterF := func(in []health.Finding) []health.Finding {
			var out []health.Finding
			for _, x := range in {
				if changed[x.Path] {
					out = append(out, x)
				}
			}
			return out
		}
		filterFS := func(in []health.FileScore) []health.FileScore {
			var out []health.FileScore
			for _, x := range in {
				if changed[x.Path] {
					out = append(out, x)
				}
			}
			return out
		}
		filterHS := func(in []health.Hotspot) []health.Hotspot {
			var out []health.Hotspot
			for _, x := range in {
				if changed[x.Path] {
					out = append(out, x)
				}
			}
			return out
		}
		filterTS := func(in []health.Target) []health.Target {
			var out []health.Target
			for _, x := range in {
				if changed[x.Path] {
					out = append(out, x)
				}
			}
			return out
		}
		res.Findings = filterF(res.Findings)
		res.LargeFuncs = filterF(res.LargeFuncs)
		res.FileScores = filterFS(res.FileScores)
		res.Hotspots = filterHS(res.Hotspots)
		res.Targets = filterTS(res.Targets)
		if res.Gaps != nil {
			var keptFiles []health.UntestedFile
			for _, uf := range res.Gaps.Files {
				if changed[uf.Path] {
					keptFiles = append(keptFiles, uf)
				}
			}
			var keptExports []health.UntestedExport
			for _, ue := range res.Gaps.Exports {
				if changed[ue.Path] {
					keptExports = append(keptExports, ue)
				}
			}
			res.Gaps.Files = keptFiles
			res.Gaps.Exports = keptExports
			res.Gaps.Summary.UntestedFiles = len(keptFiles)
			res.Gaps.Summary.UntestedExports = len(keptExports)
		}
		res.AboveCeiling = len(res.Findings)
	}

	if f.Baseline != "" {
		data, err := os.ReadFile(f.Baseline)
		if err != nil {
			fmt.Fprintln(os.Stderr, "goose:", err)
			return 2
		}
		var b struct {
			Kind    string         `json:"kind"`
			Entries map[string]int `json:"entries"`
		}
		if err := json.Unmarshal(data, &b); err != nil {
			fmt.Fprintln(os.Stderr, "goose: invalid health baseline:", err)
			return 2
		}
		var kept []health.Finding
		for _, hf := range res.Findings {
			k1 := hf.Path + ":" + hf.Name
			k2 := hf.Path + "|" + hf.Name
			if b.Entries[k1] > 0 {
				b.Entries[k1]--
				continue
			}
			if b.Entries[k2] > 0 {
				b.Entries[k2]--
				continue
			}
			kept = append(kept, hf)
		}
		res.Findings = kept
		res.AboveCeiling = len(kept)
	}
	if f.SaveBaseline != "" {
		entries := map[string]int{}
		for _, hf := range res.Findings {
			entries[hf.Path+":"+hf.Name]++
		}
		b := struct {
			Kind    string         `json:"kind"`
			Entries map[string]int `json:"entries"`
		}{
			Kind:    "health",
			Entries: entries,
		}
		data, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "goose: cannot marshal baseline:", err)
			return 2
		}
		if err := os.WriteFile(f.SaveBaseline, data, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "goose: cannot save baseline:", err)
			return 2
		}
		if !f.Quiet {
			fmt.Fprintf(os.Stderr, "Baseline saved to %s\n", f.SaveBaseline)
		}
	}
	own, err := buildOwnership(f, ec, cfg)
	if err != nil {
		if _, isUsage := err.(ErrUsage); isUsage {
			return usage(err)
		}
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	f.Ownership = own
	var groupBodies map[string]*health.Result
	var groupOrder []string
	var groupOwners map[string][]string
	var groupFilter *report.GroupFilter
	if own != nil {
		groupBodies, groupOrder, groupOwners = healthGroupBodies(ec, opts, f, cfg, minCommits, res, unusedDeps, cycles, own)
		gf, ferr := report.NewGroupFilter(f.Group)
		if ferr != nil {
			return usage(ErrUsage{"--group: " + ferr.Error()})
		}
		groupFilter = gf
		f.GroupFilter = gf
	}

	top := 0
	if v := f.Extra["--top"]; v != "" {
		top, _ = strconv.Atoi(v)
	}

	// Snapshot trend: the baseline loads before any save so a trend never
	// compares a run against its own snapshot (fallow ordering).
	var trend *health.Trend
	var baseline *health.TrendBaseline
	if f.Trend {
		if f.ChangedSince != "" && !f.Quiet {
			fmt.Fprintln(os.Stderr, "goose: warning: --trend comparison may be inaccurate with --changed-since; snapshots are typically from full-project runs")
		}
		bl, terr := health.LoadTrendBaseline(cfg.Root, f.TrendFrom)
		if terr != nil {
			fmt.Fprintln(os.Stderr, "goose:", terr)
			return 2
		}
		baseline = bl
		for _, p := range bl.Unreadable {
			fmt.Fprintf(os.Stderr, "goose: warning: skipping unreadable snapshot %s\n", p)
		}
		if bl.Snapshot != nil {
			trend = health.BuildTrend(bl.Snapshot, bl.SnapshotsLoaded, res)
		} else if !f.Quiet {
			fmt.Fprintln(os.Stderr, "goose: no snapshots found. Run `goose health --save-snapshot` to save a baseline, then use --trend on subsequent runs to track progress.")
		}
	}

	if err := saveHealthSnapshot(f, ec, cfg, res, own, groupBodies, groupOrder, groupFilter); err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}

	view := report.HealthView{
		Res: res, Cfg: cfg, Trend: trend, TrendBaseline: baseline,
		Sections: report.HealthSections{
			Complexity:   opts.Complexity,
			LargeFuncs:   opts.Complexity,
			FileScores:   opts.FileScores,
			Hotspots:     opts.Hotspots,
			Targets:      opts.Targets,
			Score:        opts.Score,
			CoverageGaps: opts.CoverageGaps,
		},
		Gaps:        res.Gaps,
		Top:         top,
		Sort:        f.Extra["--sort"],
		Colors:      colorsEnabled(f),
		FailOnIssue: f.FailOnIssues,
		Explain:     f.Explain,
		MinSeverity: f.MinSeverity,
		MinScore:    f.MinScore,
		MinSet:      f.MinScoreSet,
		Lean:        f.Lean,
		FullTables:  f.FullTables,
		// A --top replaces the lean table cap: the lean tables follow the
		// row count the user chose. --top and --full-tables never coexist
		// (validateRunFlags refuses them together).
		TableCap: top,
	}

	switch f.Format {
	case "json":
		if own != nil {
			s, _, unmatched := report.HealthGroupedJSON(view, res, groupBodies, own, groupOrder, groupOwners, groupFilter)
			writeOutput(f, s)
			for _, p := range unmatched {
				fmt.Fprintf(os.Stderr, "goose: --group pattern %q matched no group\n", p)
			}
		} else {
			writeOutput(f, report.HealthJSON(view))
		}
	case "compact":
		report.PrintGroupingNote(f.Format, groupMode(own))
		writeOutput(f, report.HealthCompact(view))
	case "markdown", "github-summary", "pr-comment-github", "pr-comment-gitlab":
		report.PrintGroupingNote(f.Format, groupMode(own))
		writeOutput(f, report.HealthMarkdown(view))
	case "human":
		if own != nil && !f.SummaryOnly {
			fmt.Print(report.HealthGroupedHuman(view, groupBodies, own, groupOrder, groupOwners, groupFilter, colorsEnabled(f)))
			if report.HealthFailing(view) {
				return 1
			}
			return 0
		}
		if f.SummaryOnly {
			fmt.Printf("%d functions above threshold · %d hotspots · score %.1f/100 (%s) · %d files analyzed (%.2fs)\n",
				res.AboveCeiling, len(res.Hotspots), res.Score.Score, res.Score.Grade,
				res.FilesAnalyzed, float64(res.ElapsedMS)/1000)
			break
		}
		writeOutput(f, report.HealthHuman(view))
	default:
		doc := report.HealthDoc(view)
		if trend != nil {
			doc.Envelope["health_trend"] = trend
		}
		return emit(f, doc, cfg.Root, true)
	}

	if opts.ReportOnly {
		return 0
	}
	if report.HealthFailing(view) {
		return 1
	}
	return 0
}

// saveHealthSnapshot persists the --save-snapshot record after rendering, so
// a trend loaded earlier never compares a run against its own snapshot.
func saveHealthSnapshot(f *Flags, ec *engine.Context, cfg *config.Config, res *health.Result, own *report.Ownership, groupBodies map[string]*health.Result, groupOrder []string, groupFilter *report.GroupFilter) error {
	if !f.SnapshotSet {
		return nil
	}
	repo := gitx.Open(cfg.Root)
	sha, branch := "", ""
	if repo.Inside {
		sha, branch = repo.CurrentSHA(), repo.Branch()
	}
	snap := health.BuildSnapshot(res, version.Version, sha, branch, repo.Shallow)
	if own != nil && len(groupOrder) > 0 {
		grouping := &health.SnapshotGrouping{GroupedBy: own.Mode}
		for _, k := range groupOrder {
			if groupFilter != nil && !groupFilter.Keep(k) {
				continue // a filtered save stores only the kept groups
			}
			if body := groupBodies[k]; body != nil {
				grouping.Groups = append(grouping.Groups, health.GroupSnapshotOf(k, body))
			}
		}
		snap.Groups = grouping
	}
	saved, err := health.SaveSnapshot(snap, cfg.Root, f.SaveSnapshot)
	if err != nil {
		return err
	}
	if !f.Quiet {
		fmt.Fprintf(os.Stderr, "Saved vital signs snapshot to %s\n", saved)
	}
	return nil
}

// groupMode labels the active grouping for a note, or "" when off.
func groupMode(own *report.Ownership) string {
	if own == nil {
		return ""
	}
	return own.Mode
}

// healthGroupBodies recomputes health per --group-by bucket over the project
// file set, mirroring fallow: each group's counts, vital signs, and score
// come from its own files. Graph edges (fan-in) stay project-wide.
func healthGroupBodies(ec *engine.Context, opts health.Options, f *Flags, cfg *config.Config, minCommits int, project *health.Result, unusedDeps, cycles *int, own *report.Ownership) (map[string]*health.Result, []string, map[string][]string) {
	set := map[string]bool{}
	for p := range ec.Proj.Files {
		rel := ec.Proj.Files[p].Rel
		set[rel] = true
	}
	buckets := map[string]map[string]bool{}
	owners := map[string][]string{}
	for rel := range set {
		k := own.Key(rel)
		if buckets[k] == nil {
			buckets[k] = map[string]bool{}
			if own.Mode == "section" {
				o := own.Owners(rel)
				if o == nil {
					o = []string{}
				}
				owners[k] = o
			}
		}
		buckets[k][rel] = true
	}
	keys := make([]string, 0, len(buckets))
	totals := map[string]int{}
	for k, b := range buckets {
		keys = append(keys, k)
		totals[k] = len(b)
	}
	report.SortGroupKeys(keys, totals)
	out := map[string]*health.Result{}
	for _, k := range keys {
		groupOpts := opts
		groupOpts.Top = 0 // per-group lists stay uncapped; --top refused with grouping
		out[k] = ec.Health(engine.HealthInput{
			Options:         groupOpts,
			Coverage:        f.Extra["--coverage"],
			ChurnWindow:     f.ChurnSince,
			ChurnMinCommits: minCommits,
			Subset:          buckets[k],
		})
	}
	return out, keys, owners
}

// scopeHealth narrows every result section to files under a path prefix, like
// a positional path scope on fallow health.
func scopeHealth(res *health.Result, prefix string) {
	prefix = strings.TrimSuffix(prefix, "/")
	inPath := func(p string) bool {
		return p == prefix || strings.HasPrefix(p, prefix+"/")
	}
	filterF := func(in []health.Finding) []health.Finding {
		out := in[:0:0]
		for _, x := range in {
			if inPath(x.Path) {
				out = append(out, x)
			}
		}
		return out
	}
	filterFS := func(in []health.FileScore) []health.FileScore {
		out := in[:0:0]
		for _, x := range in {
			if inPath(x.Path) {
				out = append(out, x)
			}
		}
		return out
	}
	filterHS := func(in []health.Hotspot) []health.Hotspot {
		out := in[:0:0]
		for _, x := range in {
			if inPath(x.Path) {
				out = append(out, x)
			}
		}
		return out
	}
	filterTS := func(in []health.Target) []health.Target {
		out := in[:0:0]
		for _, x := range in {
			if inPath(x.Path) {
				out = append(out, x)
			}
		}
		return out
	}
	res.Findings = filterF(res.Findings)
	res.LargeFuncs = filterF(res.LargeFuncs)
	res.FileScores = filterFS(res.FileScores)
	res.Hotspots = filterHS(res.Hotspots)
	res.Targets = filterTS(res.Targets)
	n := 0
	for _, f := range res.Findings {
		if len(f.Exceeded) > 0 {
			n++
		}
	}
	res.AboveCeiling = n
	res.FilesScored = len(res.FileScores)
}

// dupesHuman renders the terminal clone listing.
func dupesHuman(top, _ int, _ string, stats dupes.Stats, groups []dupes.Group, brief bool) string {
	var b strings.Builder
	shown := groups
	omitted := 0
	if top > 0 && len(groups) > top {
		shown = groups[:top]
		omitted = len(groups) - top
	}
	b.WriteString("── Code Health ─────────────────────────────────────\n\n")
	if len(shown) == 0 {
		b.WriteString("\nNo duplication found\n\n")
	} else {
		fmt.Fprintf(&b, "\n● Duplication (%d clone groups)\n", len(groups))
		for _, g := range shown {
			fmt.Fprintf(&b, "\n  %d lines  %d instances  %s\n", g.Lines, len(g.Instances), g.Fingerprint)
			for _, in := range g.Instances {
				fmt.Fprintf(&b, "    %s:%d-%d\n", in.Path, in.StartLine, in.EndLine)
			}
		}
		b.WriteString("\n  Identical token blocks detected via suffix-array analysis.\n")
		b.WriteString("  https://github.com/rf/goose/blob/main/docs/explanations/duplication.md\n")
		if omitted > 0 {
			fmt.Fprintf(&b, "  ... and %d more clone groups\n", omitted)
		}
	}
	mark := "✓"
	if stats.DuplicationPercentage > 0 {
		mark = "✓"
	}
	_ = brief
	fmt.Fprintf(&b, "\n%s %d lines (%.1f%%) duplicated across %d files (%d analyzed)\n",
		mark, stats.DuplicatedLines, stats.DuplicationPercentage, stats.FilesWithDuplication, stats.FilesAnalyzed)
	return b.String()
}

// traceDupes prints one clone group by fingerprint or the clones at a loc.
func traceDupes(res *dupes.Result, target string) int {
	if strings.HasPrefix(target, "dup:") {
		for _, g := range res.Groups {
			if g.Fingerprint == target {
				fmt.Printf("%s  %d tokens  %d lines  %d instances\n", g.Fingerprint, g.Tokens, g.Lines, len(g.Instances))
				for _, in := range g.Instances {
					fmt.Printf("  %s:%d-%d\n", in.Path, in.StartLine, in.EndLine)
				}
				fmt.Printf("  extract-function: pull %d shared lines into one helper, saving ~%d lines\n",
					g.Lines, g.Lines*(len(g.Instances)-1))
				return 0
			}
		}
		fmt.Fprintln(os.Stderr, "goose: no clone group with fingerprint "+target)
		return 2
	}
	// FILE:LINE form.
	file, lineStr, ok := strings.Cut(target, ":")
	if !ok {
		fmt.Fprintln(os.Stderr, "usage: goose dupes --trace <file:line | dup:<fingerprint>>")
		return 2
	}
	line, _ := strconv.Atoi(lineStr)
	found := false
	for _, g := range res.Groups {
		for _, in := range g.Instances {
			if in.Path == file && line >= in.StartLine && line <= in.EndLine {
				found = true
				fmt.Printf("%s  %d tokens  %d lines  %d instances\n", g.Fingerprint, g.Tokens, g.Lines, len(g.Instances))
				for _, i2 := range g.Instances {
					fmt.Printf("  %s:%d-%d\n", i2.Path, i2.StartLine, i2.EndLine)
				}
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		fmt.Fprintln(os.Stderr, "goose: no clone at "+target)
		return 2
	}
	return 0
}

func runCombined(ctx context.Context, f *Flags) int {
	if f.VersionWanted {
		fmt.Println("goose " + version.Version)
		return 0
	}
	if f.Help {
		printHelp()
		return 0
	}
	f.All = true
	return runAnalysis(ctx, f, "combined")
}

// runAnalysis performs the load, the dead-code analysis, the optional scope
// filter, the baseline pass, and output.
func runAnalysis(ctx context.Context, f *Flags, kind string) int {
	start := time.Now()
	ec, cfg, err := runContext(ctx, f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	doc := ec.DeadCode(deadcode.Options{
		Production:          cfg.ProdFor("dead-code") || f.Production,
		IncludeEntryExports: f.IncludeEntryExports || cfg.IncludeEntryExports,
		ShowCascade:         f.ShowCascade || cfg.ShowCascade,
	})
	// --trace short-circuits the report.
	if target := f.Extra["--trace"]; target != "" {
		fmt.Print(ec.Traced(target))
		return 0
	}
	// fallow's dead-code still carries the structure findings until the next
	// major version; merge them before scoping and baselining.
	if code := mergeArchitecture(f, ec, cfg, doc); code != 0 {
		return code
	}
	if f.All || kind == "combined" || kind == "all" {
		mergeHealthAndDupes(f, ec, cfg, doc)
	}
	categoryFlags := []string{
		"--unused-files", "--unused-exports", "--unused-unexported",
		"--unused-types", "--unused-fields", "--unused-methods",
		"--unused-deps", "--unlisted-deps", "--unresolved", "--stale-suppressions",
	}
	hasCategoryFilter := false
	for _, flag := range categoryFlags {
		if f.BoolExtra[flag] {
			hasCategoryFilter = true
			break
		}
	}
	if hasCategoryFilter {
		var kept []*report.Finding
		for _, x := range doc.Findings {
			match := false
			switch {
			case f.BoolExtra["--unused-files"] && (x.Rule == "unused-files" || x.Kind == "unused-file"):
				match = true
			case f.BoolExtra["--unused-exports"] && (x.Rule == "unused-exports" || x.Kind == "unused-export"):
				match = true
			case f.BoolExtra["--unused-unexported"] && (x.Rule == "unused-unexported" || x.Kind == "unused-unexported"):
				match = true
			case f.BoolExtra["--unused-types"] && (x.Rule == "unused-types" || x.Kind == "unused-type"):
				match = true
			case f.BoolExtra["--unused-fields"] && (x.Rule == "unused-fields" || x.Kind == "unused-field"):
				match = true
			case f.BoolExtra["--unused-methods"] && (x.Rule == "unused-methods" || x.Kind == "unused-method"):
				match = true
			case f.BoolExtra["--unused-deps"] && (x.Rule == "unused-dependencies" || x.Rule == "unused-test-dependencies" || x.Kind == "unused-dependency" || x.Kind == "unused-test-dependency"):
				match = true
			case f.BoolExtra["--unlisted-deps"] && (x.Rule == "unlisted-dependencies" || x.Kind == "unlisted-dependency"):
				match = true
			case f.BoolExtra["--unresolved"] && (x.Rule == "unresolved-imports" || x.Kind == "unresolved-import"):
				match = true
			case f.BoolExtra["--stale-suppressions"] && (x.Rule == "stale-suppressions" || x.Kind == "stale-suppression"):
				match = true
			}
			if match {
				kept = append(kept, x)
			}
		}
		doc.Findings = kept
	}
	// Positional arguments after the command are a path scope, like fallow.
	if len(f.Args) > 0 && f.Path == "" {
		f.Path = f.Args[0]
		f.Args = f.Args[1:]
	}
	if err := scopeFilter(f, ec, doc); err != nil {
		return usage(err)
	}
	applyArchitectureOnlySkip(f, doc)
	baselinePass(f, doc, cfg.Root)
	own, err := buildOwnership(f, ec, cfg)
	if err != nil {
		if _, isUsage := err.(ErrUsage); isUsage {
			return usage(err)
		}
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	f.Ownership = own
	if kind == "combined" || kind == "all" {
		doc.Kind = kind
		doc.Envelope["kind"] = kind
	}
	ms := time.Since(start).Milliseconds()
	if ms < 1 {
		ms = 1
	}
	doc.ElapsedMS = ms
	return emit(f, doc, cfg.Root, true)
}

func mergeHealthAndDupes(f *Flags, ec *engine.Context, cfg *config.Config, doc *report.Doc) {
	var dupPct *float64
	if shouldIncludeEngine(f, "dupes") {
		dOpts := dupes.FromConfig(cfg)
		dRes := ec.Dupes(dOpts, nil)
		dDoc := dRes.Doc(cfg.Duplicates.Threshold, f.FailOnIssues, dOpts.Fragments, 1)
		for _, x := range dDoc.Findings {
			doc.Findings = append(doc.Findings, x)
			n, _ := doc.Summary["total_issues"].(int)
			doc.Summary["total_issues"] = n + 1
			key := report.CamelCountKey(x.Kind)
			c, _ := doc.Summary[key].(int)
			doc.Summary[key] = c + 1
		}
		doc.Summary["clone_groups"] = dRes.Stats.CloneGroups
		doc.Summary["duplication_percentage"] = dRes.Stats.DuplicationPercentage
		dupPct = &dRes.Stats.DuplicationPercentage
		for k, g := range dDoc.Gates {
			doc.Gates[k] = g
		}
	}

	if shouldIncludeEngine(f, "health") {
		hOpts := health.Options{
			Complexity:   true,
			FileScores:   true,
			Hotspots:     true,
			Targets:      true,
			CoverageGaps: f.BoolExtra["--coverage-gaps"],
			Score:        true,
			MinScore:     f.MinScore,
			MinSeverity:  f.MinSeverity,
			Production:   f.Production || cfg.ProdFor("health"),
		}
		hRes := ec.Health(engine.HealthInput{
			Options:     hOpts,
			Coverage:    f.Extra["--coverage"],
			ChurnWindow: f.ChurnSince,
			Duplication: dupPct,
		})
		hView := report.HealthView{
			Res: hRes, Cfg: cfg,
			Sections: report.HealthSections{
				Complexity:   true,
				LargeFuncs:   true,
				FileScores:   true,
				Hotspots:     true,
				Targets:      true,
				Score:        true,
				CoverageGaps: hOpts.CoverageGaps,
			},
			Gaps:        hRes.Gaps,
			FailOnIssue: f.FailOnIssues,
			MinSeverity: f.MinSeverity,
			MinScore:    f.MinScore,
			MinSet:      f.MinScoreSet,
		}
		hDoc := report.HealthDoc(hView)
		for _, x := range hDoc.Findings {
			doc.Findings = append(doc.Findings, x)
			n, _ := doc.Summary["total_issues"].(int)
			doc.Summary["total_issues"] = n + 1
			key := report.CamelCountKey(x.Kind)
			c, _ := doc.Summary[key].(int)
			doc.Summary[key] = c + 1
		}
		doc.Summary["health_score"] = hRes.Score.Score
		doc.Summary["health_grade"] = hRes.Score.Grade
		for k, g := range hDoc.Gates {
			doc.Gates[k] = g
		}
	}
}

func shouldIncludeEngine(f *Flags, name string) bool {
	for _, s := range f.Skip {
		if s == name {
			return false
		}
	}
	if len(f.Only) == 0 {
		return true
	}
	for _, o := range f.Only {
		if o == name {
			return true
		}
	}
	return false
}

// scopeFilter narrows findings to --changed-since / --diff-file / --diff-stdin
// / path scope. It returns a non-nil error when a diff source is unreadable.
func scopeFilter(f *Flags, ec *engine.Context, doc *report.Doc) error {
	if f.ChangedSince == "" && f.DiffFile == "" && !f.DiffStdin && f.Path == "" && len(f.Workspace) == 0 {
		return nil
	}
	// A narrowed run can never judge a whole-project baseline, so the stale
	// gate stands down later with a note (fallow's change_scoped rule).
	f.BaselineScoped = true
	diff, err := changedScope(f, ec)
	if err != nil {
		return err
	}
	diffScoped := diff != nil
	prefix := strings.TrimSuffix(f.Path, "/")
	keep := func(path string) bool {
		if f.Path != "" && !(path == prefix || strings.HasPrefix(path, prefix+"/")) {
			return false
		}
		if len(f.Workspace) > 0 && !workspaceMatch(ec, f.Workspace, path) {
			return false
		}
		if diffScoped && !diff[path] {
			return false
		}
		return true
	}
	var kept []*report.Finding
	for _, x := range doc.Findings {
		if keep(x.Path) {
			kept = append(kept, x)
		}
	}
	doc.Findings = kept
	return nil
}

func workspaceMatch(ec *engine.Context, patterns []string, path string) bool {
	for ff := range ec.Proj.Files {
		rel := ec.Proj.Files[ff].Rel
		if rel != path {
			continue
		}
		pkg := ec.Proj.Files[ff].PkgPath
		for _, p := range patterns {
			neg := strings.HasPrefix(p, "!")
			p = strings.TrimPrefix(p, "!")
			match := p == pkg || strings.HasPrefix(pkg, p+"/") || config.MatchName(p, pkg)
			if neg && match {
				return false
			}
			if !neg && match {
				return true
			}
		}
		return false
	}
	return true
}

func changedSet(root, ref string) map[string]bool {
	repo := gitx.Open(root)
	if !repo.Inside {
		return nil
	}
	files, err := repo.ChangedFiles(ref)
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	for _, f := range files {
		set[f] = true
	}
	return set
}

func baselinePass(f *Flags, doc *report.Doc, root string) {
	if f.Baseline != "" {
		b, err := deadcode.LoadBaseline(f.Baseline)
		if err != nil {
			fmt.Fprintln(os.Stderr, "goose:", err)
			os.Exit(2)
		}
		kept, st := deadcode.ApplyBaseline(doc.Findings, b)
		doc.Findings = kept
		doc.Summary["baseline_staleness"] = map[string]any{
			"baseline_entries": st.BaselineEntries,
			"matched_entries":  st.MatchedEntries,
			"current_findings": st.CurrentFindings,
		}
		// A baseline a run cannot judge must never gate it: a scope-narrowed
		// run only sees part of the project, and --save-baseline pointing at
		// the file being loaded makes staleness impossible by construction
		// (fallow's inert rule). Only the stale gate stands down; the growth
		// ratchet compares the file at a base ref, which scoping cannot
		// distort. An armed gate says so on stderr instead of passing
		// quietly. An empty or foreign-shaped baseline suppresses nothing:
		// the run reports it and an armed gate fails closed, like fallow.
		inert := baselineStaleInert(f, root)
		if inert != "" {
			baselineStoodDown(f, "stale-baseline", f.Baseline, inert)
		}
		if st.UnrecognisedFormat {
			fmt.Fprintf(os.Stderr, "goose: the baseline %s has no entries this command recognises. It suppresses nothing; re-save it with: goose %s --save-baseline %s\n", f.Baseline, doc.Kind, f.Baseline)
		}
		if f.FailOnStaleBaseline && inert == "" && st.GateTrips() {
			doc.Gates["stale-baseline"] = &report.Gate{Status: "failed", Enforced: true, Observed: st.MatchedEntries, Threshold: st.BaselineEntries,
				Detail: fmt.Sprintf("%d of %d baseline entries matched no current finding", st.BaselineEntries-st.MatchedEntries, st.BaselineEntries)}
			if st.UnrecognisedFormat {
				doc.Gates["stale-baseline"].Detail = "the baseline holds no entries this command recognises"
			}
		}
		// Growth ratchet: a change may add a finding and re-save the
		// baseline in the same commit; the loaded baseline stays quiet and
		// stale detection passes. Compare the baseline file with its own
		// version at a base ref and fail on keys it grew.
		if f.FailOnBaselineGrowth {
			added, isNew, baseLabel, err := baselineGrowth(f, root, f.Baseline)
			if err != nil {
				fmt.Fprintln(os.Stderr, "goose:", err)
				os.Exit(2)
			}
			switch {
			case isNew:
				if !f.Quiet {
					fmt.Fprintf(os.Stderr, "Note: --fail-on-baseline-growth found no %s at %s, so it is a new baseline. The gate passes.\n", f.Baseline, baseLabel)
				}
				doc.Gates["baseline-growth"] = &report.Gate{Status: "passed", Enforced: true, Observed: 0, Threshold: 0}
			case added > 0:
				doc.Gates["baseline-growth"] = &report.Gate{
					Status: "failed", Enforced: true,
					Observed: added, Threshold: 0,
					Detail: fmt.Sprintf("baseline grew by %d key(s) vs %s", added, baseLabel),
				}
			default:
				doc.Gates["baseline-growth"] = &report.Gate{Status: "passed", Enforced: true, Observed: 0, Threshold: 0}
			}
		}
	}
	if f.SaveBaseline != "" {
		if err := deadcode.SaveBaseline(f.SaveBaseline, doc.Findings, version.Version); err != nil {
			fmt.Fprintln(os.Stderr, "goose: cannot save baseline:", err)
			os.Exit(2)
		}
		if !f.Quiet {
			fmt.Fprintf(os.Stderr, "Baseline saved to %s (%d entries)\n", f.SaveBaseline, len(doc.Visible()))
		}
	}
}

// printHelp lists commands.
func printHelp() {
	fmt.Println(`goose — codebase intelligence for Go

Usage:
  goose [command] [flags]

Commands:
  dead-code, check   Find unused files, symbols, fields, methods, and deps`)
	for _, c := range registry {
		if c.Name == "dead-code" || c.Name == "version" || c.Name == "explain" || c.Name == "init" {
			continue
		}
		fmt.Printf("  %-16s %s\n", c.Name, c.Summary)
	}
	fmt.Println(`
Run 'goose <command> --help' for command flags. Global flags:
  -r, --root            project directory   -f, --format  output format (see docs)
  -c, --config          config file         --quiet       report only
  --fail-on-issues      gate findings       --ci          sarif + fail + quiet
  --changed-since       git ref scope       --baseline    compare to baseline
  --production          drop test files     --all         run all 4 engines`)
}

// ---------------------------------------------------------------------------
// Tiny commands.
// ---------------------------------------------------------------------------

var explanations = map[string]string{
	"unused-file":             "A file is unused when no entry point can reach its package by\nimport. Entry points are main packages and --root config entries.",
	"unused-export":           "An export is unused when no other package references it. Entry\npackages keep their exports by default, because a host or a plugin\nreads them by path.",
	"unused-unexported":       "An unexported symbol is unused when nothing in its own package\nreads it. Interface implementations and used interfaces keep their\nmethods.",
	"unused-field":            "A struct field is unused when code never reads or writes it, and no\nreflect-based marshal reaches this type through a struct tag.",
	"unused-method":           "A method is unused when nothing calls it and no used interface or\nimplementor keeps it alive.",
	"unused-dependency":       "A dependency is unused when no file imports it. Test-only imports\ncount as used in non-production runs.",
	"unlisted-dependency":     "An import is unlisted when its module path does not appear in any\ngo.mod require of the project.",
	"unresolved-import":       "An import is unresolved when go list cannot find it. Generate it,\nvendor it, or add it to ignoreUnresolvedImports.",
	"circular-dependency":     "A package cycle forms when A imports B and B imports A (possibly\nthrough more packages). Go itself rejects import cycles between\npackages in one module; cycles across workspaces still block\nindependent builds.",
	"boundary-violation":      "A boundary violation crosses an architecture zone rule you defined\nin boundaries.",
	"deep-import":             "A deep import bypasses a top-level package root to import a nested\nsubpackage directly.",
	"complexity-finding":      "A function exceeds the cyclomatic or cognitive ceiling. Split the\ndecision logic into named helpers.",
	"stale-suppression":       "A goose-ignore comment no longer matches any finding. Delete it.",
	"write-only-field":        "A struct field is initialized or assigned but never read anywhere in\nthe project.",
	"write-only-variable":     "A package-level variable is assigned to but never read.",
	"can-be-unexported":       "An exported symbol is only referenced within its own declaring\npackage and can be unexported to shrink the package API.",
	"unused-interface-method": "An explicit method on a live interface has zero call sites across\nthe project.",
	"unused-parameter":        "A function or method parameter is never read inside its body.",
	"unused-receiver":         "A named method receiver is never referenced inside the method body.",
	"struct-padding":          "A struct wastes memory on alignment padding; reordering its fields\nby alignment shrinks its 64-bit size.",
	"nil-error-interface":     "A typed nil pointer is returned as an error interface, producing a\nnon-nil error interface value (err != nil is true).",
	"context-leak":            "context.WithCancel, WithTimeout, or WithDeadline is called without\ncalling the returned CancelFunc on all paths.",
	"defer-in-loop":           "A defer statement inside a for/range loop delays resource cleanup\nuntil the enclosing function returns.",
	"unclosed-body":           "An *http.Response.Body or *sql.Rows result is never closed.",
	"copylocks":               "A sync primitive (Mutex, RWMutex, WaitGroup, Once, Cond, Map, Pool)\nis copied by value.",
	"security-sink":           "A dynamically constructed command, SQL query, or insecure TLS\nconfiguration reaches a dangerous execution sink.",
	"secret-in-code":          "A hardcoded private key, API token, or secret credential literal\nappears in source code.",
	"feature-flag":            "A feature flag check via SDK call or environment variable prefix was\ndetected.",
	"stale-feature-flag":      "A feature flag check matches a stale feature flag configuration.",
	"diverged-clone-sibling":  "One instance of a duplicated code block was modified in the diff\nwhile its clone sibling was left untouched.",
}

func runExplain(ctx context.Context, f *Flags) int {
	topic := ""
	if len(f.Args) > 0 {
		topic = f.Args[0]
	}
	if topic == "" {
		var names []string
		for k := range explanations {
			names = append(names, k)
		}
		fmt.Println(strings.Join(names, "\n"))
		return 0
	}
	if text, ok := explanations[topic]; ok {
		fmt.Printf("goose: %s\n\n%s\n\n%s\n", topic, text, report.DocLink(topic))
		return 0
	}
	return unknownError("issue type " + topic)
}

func runInit(ctx context.Context, f *Flags) int {
	name := ".gooserc.json"
	body := "{\n  \"$schema\": \"./schema.json\",\n  \"rules\": {}\n}\n"
	if f.BoolExtra["--toml"] {
		name = "goose.toml"
		body = "[rules]\n"
	}
	if _, err := os.Stat(name); err == nil {
		fmt.Fprintln(os.Stderr, "goose: "+name+" already exists")
		return 2
	}
	if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	fmt.Println("Created " + name)
	return 0
}

func unknownError(msg string) int {
	fmt.Fprintln(os.Stderr, "goose: unknown "+msg)
	return 2
}
