package report

import (
	"strings"

	"goose/internal/config"
)

// kindToRule maps finding kinds to canonical rule names where Plural is not
// enough.
var kindToRule = map[string]string{
	"boundary-violation":         "boundary-violation",
	"complexity-finding":         "complexity-cyclomatic",
	"clone-group":                "duplicated-code",
	"package-cycle":              "package-cycle",
	"security-candidate":         "security-sink",
	"feature-flag":               "feature-flags",
	"coverage-gap":               "coverage-gaps",
	"coverage-gap-export":        "coverage-gaps",
	"file-lines":                 "complexity-file-lines",
	"unused-file":                "unused-files",
	"unused-export":              "unused-exports",
	"unused-unexported":          "unused-unexported",
	"unused-type":                "unused-types",
	"unused-field":               "unused-fields",
	"unused-method":              "unused-methods",
	"unused-constant":            "unused-constants",
	"unused-variable":            "unused-variables",
	"unused-dependency":          "unused-dependencies",
	"unused-test-dependency":     "unused-test-dependencies",
	"unlisted-dependency":        "unlisted-dependencies",
	"unresolved-import":          "unresolved-imports",
	"duplicate-export":           "duplicate-exports",
	"circular-dependency":        "circular-dependencies",
	"policy-violation":           "policy-violation",
	"stale-suppression":          "stale-suppressions",
	"missing-suppression-reason": "require-suppression-reason",
	"large-function":             "large-function",
	"large-file":                 "large-file",
	"write-only-field":           "write-only-fields",
	"write-only-variable":        "write-only-variables",
	"can-be-unexported":          "can-be-unexported",
	"unused-interface-method":    "unused-interface-methods",
	"unused-parameter":           "unused-parameters",
	"unused-receiver":            "unused-receivers",
	"struct-padding":             "struct-padding",
	"nil-error-interface":        "nil-error-interface",
	"context-leak":               "context-leak",
	"defer-in-loop":              "defer-in-loop",
	"unclosed-body":              "unclosed-body",
	"copylocks":                  "copylocks",
	"deep-import":                "deep-import",
	"stale-feature-flag":         "stale-feature-flags",
	"secret-in-code":             "secrets-in-code",
	"diverged-clone-sibling":     "diverged-clone-sibling",
	"private-type-leak":          "private-type-leaks",
	"deprecated-export-in-use":   "deprecated-exports-in-use",
}

// RuleForKind returns the canonical rule gating a finding kind.
func RuleForKind(kind string) string {
	if r, ok := kindToRule[kind]; ok && config.KnownRule(r) {
		return config.CanonicalRule(r)
	}
	plural := Plural(kind)
	if config.KnownRule(plural) {
		return config.CanonicalRule(plural)
	}
	if config.KnownRule(kind) {
		return config.CanonicalRule(kind)
	}
	return plural
}

// camelCountKey renders the summary key for a finding kind: unused-file ->
// unusedFiles.
func CamelCountKey(kind string) string {
	plural := Plural(kind)
	parts := strings.Split(plural, "-")
	for i := 1; i < len(parts); i++ {
		p := parts[i]
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "")
}
