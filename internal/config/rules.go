package config

import (
	"strings"

	"goose/internal/glob"
)

// ruleDefaults holds the canonical goose rule names and their defaults.
// The severity model is fallow's: error fails the run, warn reports and
// exits 0, off disables detection. Rules that only made sense for the
// TypeScript/JS ecosystem (CSS, components, pnpm catalogs) are dropped; Go
// rules (fields, methods, unused-unexported) replace their role.
var ruleDefaults = map[string]Severity{
	// Dead code.
	"unused-files":              Error,
	"unused-exports":            Error, // exported symbols no project package references
	"unused-unexported":         Error, // unexported symbols unused inside their package
	"unused-types":              Error, // declared types nothing references
	"unused-fields":             Error, // struct fields never read or written
	"unused-methods":            Error, // methods never called and never interface-implied
	"unused-constants":          Error,
	"unused-variables":          Error, // package-level vars
	"unused-dependencies":       Error, // required in go.mod, never imported
	"unused-test-dependencies":  Warn,
	"unlisted-dependencies":     Error, // imported but absent from go.mod requires
	"unresolved-imports":        Error, // imports go list cannot resolve
	"duplicate-exports":         Off,   // Go commonly exports the same name from many packages
	"private-type-leaks":        Off,   // exported API exposing an unexported type
	"deprecated-exports-in-use": Off,
	"write-only-fields":         Off,   // struct fields written/initialized but never read
	"write-only-variables":      Off,   // package vars assigned but never read
	"can-be-unexported":         Off,   // exported symbols used only within their own package
	"unused-interface-methods":  Off,   // interface methods never called on the interface
	"unused-parameters":         Off,   // function parameters never read in the body
	"unused-receivers":          Off,   // method receivers never read in the body
	"struct-padding":            Off,   // struct field ordering wastes alignment padding

	// Go correctness & runtime hazards.
	"nil-error-interface": Warn, // returning a typed nil pointer as an error/interface
	"context-leak":        Warn, // context.WithCancel/Timeout without calling cancel
	"defer-in-loop":       Warn, // defer statement inside a for/range loop
	"unclosed-body":       Warn, // http.Response.Body or sql.Rows not closed
	"copylocks":           Warn, // passing a struct containing sync locks by value

	// Architecture.
	"circular-dependencies": Error,
	"package-cycle":         Error, // cycles between project modules
	"boundary-violation":    Error,
	"policy-violation":      Warn,
	"deep-import":           Off, // importing below a repository's public root

	// Complexity, reported by the health analysis.
	"complexity-cyclomatic": Error,
	"complexity-cognitive":  Error,
	"complexity-crap":       Error,
	"complexity-file-lines": Error,
	"large-function":        Warn,
	"large-file":            Warn,

	// Duplication.
	"duplicated-code": Warn,

	// Test coverage.
	"coverage-gaps":              Warn, // runtime code no test reaches
	"require-suppression-reason": Off,

	// Feature flags (opt-in catalogue).
	"feature-flags":       Off,
	"stale-feature-flags": Off,

	// Security candidates (opt-in, always needs verification).
	"security-sink":   Off,
	"secrets-in-code": Off,

	// Audit diff rules, the PR hygiene checks.
	"weakened-tests":         Warn,
	"added-suppression":      Warn,
	"test-only-branch":       Warn,
	"diverged-clone-sibling": Off,
	"added-dependency":       Off,

	// Suppression hygiene.
	"stale-suppressions": Warn,
}

// ruleAliases maps accepted spellings to canonical names.
var ruleAliases = map[string]string{
	"circular-dependency":     "circular-dependencies",
	"package-cycles":          "package-cycle",
	"unused-export":           "unused-exports",
	"unused-file":             "unused-files",
	"unused-type":             "unused-types",
	"unused-field":            "unused-fields",
	"unused-method":           "unused-methods",
	"unused-constant":         "unused-constants",
	"unused-variable":         "unused-variables",
	"unused-dependency":       "unused-dependencies",
	"unresolved-import":       "unresolved-imports",
	"boundary-violations":     "boundary-violation",
	"duplication":             "duplicated-code",
	"duplicate-code":          "duplicated-code",
	"added-suppressions":      "added-suppression",
	"added-dependencies":      "added-dependency",
	"diverged-clone-siblings": "diverged-clone-sibling",
	"test-only-branches":      "test-only-branch",
	"complexity-lines":         "complexity-file-lines",
	"deep-imports":             "deep-import",
	"write-only-field":         "write-only-fields",
	"write-only-variable":      "write-only-variables",
	"unused-interface-method":  "unused-interface-methods",
	"unused-parameter":         "unused-parameters",
	"unused-receiver":          "unused-receivers",
	"secret-in-code":           "secrets-in-code",
	"stale-feature-flag":       "stale-feature-flags",
	"context-leaks":            "context-leak",
	"unclosed-bodies":          "unclosed-body",
	"copylock":                 "copylocks",
	"private-type-leak":        "private-type-leaks",
	"deprecated-export-in-use": "deprecated-exports-in-use",
}

// CanonicalRule resolves an alias to its canonical rule name.
func CanonicalRule(name string) string {
	n := strings.TrimSpace(name)
	if c, ok := ruleAliases[n]; ok {
		return c
	}
	return n
}

// KnownRule reports whether a name is a rule goose recognizes.
func KnownRule(name string) bool {
	_, ok := ruleDefaults[CanonicalRule(name)]
	return ok
}

// DefaultSeverity returns the documented default for a canonical rule name.
func DefaultSeverity(name string) Severity {
	if s, ok := ruleDefaults[name]; ok {
		return s
	}
	return Warn
}

// RuleNames returns canonical rule names in sorted order.
func RuleNames() []string {
	return SortedRules()
}

func compilePath(pattern string) (*glob.Pattern, error) {
	return glob.Compile(pattern, glob.Options{})
}

// MatchName applies package-name glob semantics, where `*` crosses `/`. It is
// used by ignoreDependencies and ignoreUnresolvedImports. The file-path glob
// matcher is MatchPath in config.go.
func MatchName(pattern, name string) bool {
	return glob.MatchName(pattern, name)
}
