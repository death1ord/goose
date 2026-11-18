// Package cli implements the goose command line: global flags, subcommands,
// and the exit-code contract that mirrors fallow.
package cli

import (
	"strconv"
	"strings"

	"goose/internal/report"
)

// Flags is the parsed flag set shared by every command.
type Flags struct {
	Global

	// Positional arguments after flag parsing. The first one is the
	// subcommand when it names a known command; commands read the rest.
	Args []string

	// Path is the positional file-or-directory scope of a run, like
	// `goose health src/api`. Commands consume it after taking the
	// subcommand name out of Args.
	Path string

	// Command-specific option store, populated per command.
	Extra     map[string]string
	BoolExtra map[string]bool
	ListExtra map[string][]string

	// Ownership is the resolved --group-by resolver, set by runners before
	// rendering; nil means the run is ungrouped.
	Ownership *report.Ownership
	// GroupFilter holds the compiled --group selector for a grouped run.
	GroupFilter *report.GroupFilter
}

// Global holds the flags that behave the same on every command.
type Global struct {
	Root   string
	Config string

	Format       string
	Pretty       bool
	Quiet        bool
	CI           bool
	FailOnIssues bool

	Production      bool
	NoProduction    bool
	ProductionDC    bool
	ProductionH     bool
	ProductionDupes bool

	IncludeEntryExports bool
	ShowCascade         bool

	ChangedSince string
	ChurnSince   string
	DiffFile     string
	DiffStdin    bool

	Baseline             string
	SaveBaseline         string
	FailOnStaleBaseline  bool
	FailOnBaselineGrowth bool
	BaselineBase         string

	// BaselineScoped is set by a runner when the analysis only saw part of
	// the project (path, diff, base ref, workspace, or production mode). A
	// scoped run cannot judge a whole-project baseline, and
	// --fail-on-stale-baseline / --fail-on-baseline-growth stand down with a
	// note instead of failing on files the run never analyzed.
	BaselineScoped bool

	FailOnParseError bool

	Only []string
	Skip []string

	Workspace []string

	Explain     bool
	SummaryOnly bool
	Lean        bool
	FullTables  bool
	GroupBy     string

	MaxFileSizeMB  float64
	MaxFileSizeSet bool
	Threads        int
	NoCache        bool
	Performance    bool

	OutputFile       string
	SarifFile        string
	ReportPathPrefix string

	// Group selects buckets of a --group-by health run (exact keys, globs,
	// !-negations). Only valid with health --group-by.
	Group []string

	SaveSnapshot string
	SnapshotSet  bool
	Trend        bool
	TrendFrom    string
	Score        bool
	MinScore     float64
	MinScoreSet  bool
	MinSeverity  string

	TypeAware   bool
	NoTypeAware bool
	All         bool

	Help          bool
	VersionWanted bool
}

// NewFlags returns a flag set with the documented defaults.
func NewFlags() *Flags {
	return &Flags{
		Global:    Global{Format: "human"},
		Extra:     map[string]string{},
		BoolExtra: map[string]bool{},
		ListExtra: map[string][]string{},
	}
}

// ErrUsage marks a usage error; the process exits with code 2.
type ErrUsage struct{ Msg string }

func (e ErrUsage) Error() string { return e.Msg }

// optionalValue flags take a value when one follows that is not another
// flag; --save-snapshot uses the documented default snapshot path when bare.
var optionalValueFlags = map[string]func(*Flags, string) error{
	"--save-snapshot": func(f *Flags, v string) error {
		f.SaveSnapshot = v
		f.SnapshotSet = true
		f.Score = true
		return nil
	},
}

// boolFlag names take no value; valueFlag names take one; listFlag names may
// repeat. Aliases map to the same target.
var (
	boolFlags = map[string]func(f *Flags){
		"--pretty":                  func(f *Flags) { f.Pretty = true },
		"-q":                        func(f *Flags) { f.Quiet = true },
		"--quiet":                   func(f *Flags) { f.Quiet = true },
		"--ci":                      func(f *Flags) { f.CI = true; f.Format = "sarif"; f.FailOnIssues = true; f.Quiet = true },
		"--fail-on-issues":          func(f *Flags) { f.FailOnIssues = true },
		"--production":              func(f *Flags) { f.Production = true },
		"--no-production":           func(f *Flags) { f.NoProduction = true },
		"--production-dead-code":    func(f *Flags) { f.ProductionDC = true },
		"--production-health":       func(f *Flags) { f.ProductionH = true },
		"--production-dupes":        func(f *Flags) { f.ProductionDupes = true },
		"--include-entry-exports":   func(f *Flags) { f.IncludeEntryExports = true },
		"--show-cascade":            func(f *Flags) { f.ShowCascade = true },
		"--diff-stdin":              func(f *Flags) { f.DiffStdin = true },
		"--fail-on-stale-baseline":  func(f *Flags) { f.FailOnStaleBaseline = true },
		"--fail-on-baseline-growth": func(f *Flags) { f.FailOnBaselineGrowth = true },
		"--fail-on-parse-error":     func(f *Flags) { f.FailOnParseError = true },
		"--explain":                 func(f *Flags) { f.Explain = true },
		"--summary":                 func(f *Flags) { f.SummaryOnly = true },
		"--lean":                    func(f *Flags) { f.Lean = true },
		"--full-tables":             func(f *Flags) { f.FullTables = true },
		"--no-cache":                func(f *Flags) { f.NoCache = true },
		"--performance":             func(f *Flags) { f.Performance = true },
		"--trend":                   func(f *Flags) { f.Trend = true; f.Score = true },
		"--score":                   func(f *Flags) { f.Score = true },
		"--type-aware":              func(f *Flags) { f.TypeAware = true },
		"--no-type-aware":           func(f *Flags) { f.NoTypeAware = true },
		"--all":                     func(f *Flags) { f.All = true },
		"--coverage-gaps":           func(f *Flags) { f.BoolExtra["--coverage-gaps"] = true },
		"-h":                        func(f *Flags) { f.Help = true },
		"--help":                    func(f *Flags) { f.Help = true },
		"--version":                 func(f *Flags) { f.VersionWanted = true },
	}
	valueFlags = map[string]func(*Flags, string) error{
		"-r":              func(f *Flags, v string) error { f.Root = v; return nil },
		"--root":          func(f *Flags, v string) error { f.Root = v; return nil },
		"-c":              func(f *Flags, v string) error { f.Config = v; return nil },
		"--config":        func(f *Flags, v string) error { f.Config = v; return nil },
		"-f":              setFormat,
		"--format":        setFormat,
		"--output":        setFormat,
		"--changed-since": func(f *Flags, v string) error { f.ChangedSince = v; return nil },
		"--base":          func(f *Flags, v string) error { f.ChangedSince = v; return nil },
		"--since": func(f *Flags, v string) error {
			if !validChurnWindow(v) {
				return ErrUsage{"--since needs a window like 90d, 6m, 1y, or 2w"}
			}
			f.ChurnSince = v
			return nil
		},
		"--diff-file":     func(f *Flags, v string) error { f.DiffFile = v; return nil },
		"--baseline":      func(f *Flags, v string) error { f.Baseline = v; return nil },
		"--save-baseline": func(f *Flags, v string) error { f.SaveBaseline = v; return nil },
		"--baseline-base": func(f *Flags, v string) error { f.BaselineBase = v; return nil },
		"--group-by":      func(f *Flags, v string) error { f.GroupBy = v; return nil },
		"--max-file-size": func(f *Flags, v string) error {
			n, err := strconv.ParseFloat(v, 64)
			if err != nil || n < 0 {
				return ErrUsage{"--max-file-size needs a non-negative number"}
			}
			f.MaxFileSizeMB = n
			f.MaxFileSizeSet = true
			return nil
		},
		"--threads": func(f *Flags, v string) error {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return ErrUsage{"--threads needs a positive integer"}
			}
			f.Threads = n
			return nil
		},
		"--output-file":        func(f *Flags, v string) error { f.OutputFile = v; return nil },
		"-o":                   func(f *Flags, v string) error { f.OutputFile = v; return nil },
		"--sarif-file":         func(f *Flags, v string) error { f.SarifFile = v; return nil },
		"--report-path-prefix": func(f *Flags, v string) error { f.ReportPathPrefix = v; return nil },
		"--coverage":           func(f *Flags, v string) error { f.Extra["--coverage"] = v; return nil },
		"--min-score": func(f *Flags, v string) error {
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return ErrUsage{"--min-score needs a number"}
			}
			f.MinScore = n
			f.MinScoreSet = true
			f.Score = true
			return nil
		},
		"--min-severity": func(f *Flags, v string) error { f.MinSeverity = v; return nil },
		"--trend-from": func(f *Flags, v string) error {
			f.TrendFrom = v
			f.Trend = true
			f.Score = true
			return nil
		},
	}
	listFlags = map[string]func(*Flags, string){
		"--workspace": func(f *Flags, v string) { f.Workspace = appendCommaList(f.Workspace, v) },
		"-w":          func(f *Flags, v string) { f.Workspace = appendCommaList(f.Workspace, v) },
		"--only":      func(f *Flags, v string) { f.Only = appendCommaList(f.Only, v) },
		"--skip":      func(f *Flags, v string) { f.Skip = appendCommaList(f.Skip, v) },
		"--group":     func(f *Flags, v string) { f.Group = appendCommaList(f.Group, v) },
	}
)

// validChurnWindow accepts fallow's duration spellings: a positive integer
// with a d/w/m/y suffix. Anything else is rejected so a typo cannot widen or
// narrow the hotspot window silently.
func validChurnWindow(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 2 {
		return false
	}
	suffix := v[len(v)-1]
	if suffix != 'd' && suffix != 'w' && suffix != 'm' && suffix != 'y' {
		return false
	}
	n, err := strconv.Atoi(v[:len(v)-1])
	return err == nil && n > 0
}

func setFormat(f *Flags, v string) error {
	switch v {
	case "human", "json", "compact", "markdown", "sarif", "codeclimate",
		"gitlab-codequality", "pr-comment-github", "pr-comment-gitlab",
		"review-github", "review-gitlab", "badge", "github-annotations",
		"github-summary":
		f.Format = v
		return nil
	default:
		return ErrUsage{"--format must be one of human, json, compact, markdown, sarif, codeclimate, gitlab-codequality, pr-comment-github, pr-comment-gitlab, review-github, review-gitlab, badge, github-annotations, github-summary"}
	}
}

func appendCommaList(dst []string, v string) []string {
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			dst = append(dst, p)
		}
	}
	return dst
}

// Register makes a command's option names known to the parser. bools take no
// value and land in BoolExtra; values take one and call their setter.
func registerCommandFlags(command string, bools []string, values map[string]func(*Flags, string) error) {
	for _, b := range bools {
		cmdBool[b] = command
	}
	for name, fn := range values {
		cmdValue[name] = fn
	}
}

// active command registrations keyed by flag name, filled by registerCommandFlags.
var (
	cmdBool  = map[string]string{}
	cmdValue = map[string]func(*Flags, string) error{}
)

// isKnownBool reports whether a flag name is a boolean anywhere.
func isKnownBool(name string) bool {
	if _, ok := boolFlags[name]; ok {
		return true
	}
	_, ok := cmdBool[name]
	return ok
}

// isOptionalValue reports whether a flag takes a value when one is given.
func isOptionalValue(name string) bool {
	_, ok := optionalValueFlags[name]
	return ok
}

// isKnownValue reports whether a flag name takes a value anywhere.
func isKnownValue(name string) bool {
	if _, ok := valueFlags[name]; ok {
		return true
	}
	_, ok := cmdValue[name]
	return ok
}

// isKnownList reports whether a flag name is a repeatable list.
func isKnownList(name string) bool {
	_, ok := listFlags[name]
	return ok
}

// Parse splits args into positionals and flags. Commands read Extra for their
// own options and Args for subcommand arguments.
func Parse(args []string) (*Flags, error) {
	f := NewFlags()
	var positionals []string
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if isFlag(a) {
			name, inline, hasInline := splitFlag(a)
			switch {
			case isKnownBool(name):
				if fn, ok := boolFlags[name]; ok {
					fn(f)
				} else {
					// command bool → BoolExtra
					if f.BoolExtra == nil {
						f.BoolExtra = map[string]bool{}
					}
					f.BoolExtra[name] = true
				}
				i++
			case isOptionalValue(name):
				if inline != "" {
					if err := optionalValueFlags[name](f, inline); err != nil {
						return nil, err
					}
					i++
					continue
				}
				j := i + 1
				val := ""
				if j < len(args) && !isFlag(args[j]) && args[j] != "--" {
					val = args[j]
					i = j + 1
				} else {
					i++
				}
				if err := optionalValueFlags[name](f, val); err != nil {
					return nil, err
				}
				_ = val
				continue
			case isKnownList(name):
				if i+1 >= len(args) {
					return nil, ErrUsage{name + " needs a value"}
				}
				listFlags[name](f, args[i+1])
				i += 2
			case isKnownValue(name):
				var val string
				if hasInline {
					val = inline
					i++
				} else {
					if i+1 >= len(args) {
						return nil, ErrUsage{name + " needs a value"}
					}
					val = args[i+1]
					i += 2
				}
				if fn, ok := valueFlags[name]; ok {
					if err := fn(f, val); err != nil {
						return nil, err
					}
				} else if fn, ok := cmdValue[name]; ok {
					if err := fn(f, val); err != nil {
						return nil, err
					}
				}
			default:
				return nil, ErrUsage{"unknown flag: " + name}
			}
			continue
		}
		positionals = append(positionals, a)
		i++
	}
	f.Args = positionals
	if f.FailOnBaselineGrowth && f.Baseline == "" {
		return nil, ErrUsage{"--fail-on-baseline-growth needs a baseline to compare. Pass --baseline <file>, or remove the flag"}
	}
	if f.BaselineBase != "" && !f.FailOnBaselineGrowth {
		return nil, ErrUsage{"--baseline-base needs --fail-on-baseline-growth. Add the flag, or remove --baseline-base"}
	}
	if f.GroupBy != "" {
		if _, ok := report.NormalizeGroupBy(f.GroupBy); !ok {
			return nil, ErrUsage{"--group-by must be one of: owner, directory, package, section"}
		}
	}
	if f.Lean && f.Format != "json" {
		return nil, ErrUsage{"--lean requires JSON output. Use --format json --lean, or remove --lean"}
	}
	if f.FullTables && !f.Lean {
		return nil, ErrUsage{"--full-tables needs --lean with --format json. Add --lean, or remove --full-tables"}
	}
	if f.Production && f.NoProduction {
		return nil, ErrUsage{"--production and --no-production cannot be combined"}
	}
	if f.TypeAware && f.NoTypeAware {
		return nil, ErrUsage{"--type-aware and --no-type-aware cannot be combined"}
	}
	if len(f.Group) > 0 && f.GroupBy == "" {
		return nil, ErrUsage{"--group needs --group-by. Add a mode, or remove --group"}
	}
	return f, nil
}

// validateRunFlags applies the command-dependent flag rules that Parse cannot
// see, with fallow's exit-2 contract: --lean only carries a lean profile on
// dead-code, health, and the bare run; --full-tables plus --top is a
// health-only contradiction.
func validateRunFlags(command string, f *Flags) error {
	switch command {
	case "", "combined", "all", "dead-code", "health":
	default:
		if f.Lean {
			return ErrUsage{"--lean applies to goose dead-code, goose health and bare goose. Remove --lean"}
		}
	}
	if command == "health" && f.FullTables && f.Extra["--top"] != "" {
		return ErrUsage{"--full-tables keeps every table row, but --top cuts the tables. Remove one of them."}
	}
	return nil
}

// isFlag treats a leading "-" (but not a bare "-" or a negative number) as a
// flag marker.
func isFlag(a string) bool {
	if !strings.HasPrefix(a, "-") {
		return false
	}
	if a == "-" || a == "--" {
		return false
	}
	if len(a) > 1 && (a[1] >= '0' && a[1] <= '9') {
		return false
	}
	return true
}

func splitFlag(a string) (string, string, bool) {
	if eq := strings.Index(a, "="); eq > 0 {
		return a[:eq], a[eq+1:], true
	}
	return a, "", false
}
