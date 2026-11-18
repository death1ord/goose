// Package report defines the finding model and every output format: human,
// compact, JSON, SARIF, CodeClimate, Markdown, the CI formats, and badges.
// The envelope shapes match fallow's documented JSON contracts.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"goose/internal/config"
)

// Action is one suggested follow-up on a finding. Agents and scripts act on
// these fields; fix consumes the auto-fixable ones.
type Action struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Comment     string `json:"comment,omitempty"`
	Note        string `json:"note,omitempty"`
	AutoFixable bool   `json:"auto_fixable"`
	FilePath    string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	// Extra keys (package, name, ...) carry fix parameters.
	Extra map[string]any `json:"-"`
}

// MarshalJSON merges Extra into the action object.
func (a Action) MarshalJSON() ([]byte, error) {
	m := map[string]any{}
	m["type"] = a.Type
	if a.Description != "" {
		m["description"] = a.Description
	}
	if a.Comment != "" {
		m["comment"] = a.Comment
	}
	if a.Note != "" {
		m["note"] = a.Note
	}
	m["auto_fixable"] = a.AutoFixable
	if a.FilePath != "" {
		m["file"] = a.FilePath
	}
	if a.Line != 0 {
		m["line"] = a.Line
	}
	for k, v := range a.Extra {
		m[k] = v
	}
	return marshalMap(m)
}

// Finding is one analysis result ready for every output.
type Finding struct {
	// Kind is the finding token, e.g. "unused-export". The JSON section name
	// is the plural of it.
	Kind string
	// Rule is the canonical rule name that gates it.
	Rule string
	// Path is project-relative with forward slashes.
	Path string
	Line int // 1-based
	Col  int // 0-based
	// Message is the human description.
	Message string
	// Severity is the effective severity of the finding after rules.
	Severity config.Severity
	// ID is the stable finding id, dc1:<kind>:<16hex>.
	ID string
	// Extra holds kind-specific JSON fields (export_name, package_name, ...).
	Extra map[string]any
	// Actions lists follow-ups.
	Actions []Action
	// Hidden marks a cascade-hidden finding; excluded from the report count.
	Hidden bool
	// Caveats records analysis incompleteness notes.
	Caveats []string
}

// SectionName returns the JSON root key that holds findings of this kind.
func (f *Finding) SectionName() string { return Plural(f.Kind) }

// Fingerprint computes a stable finding id: rule kind, path, and the identity
// names, never line numbers.
func Fingerprint(kind, path string, identity ...string) string {
	h := sha256.New()
	h.Write([]byte("dc1|" + kind + "|" + path))
	for _, x := range identity {
		h.Write([]byte("|" + x))
	}
	sum := h.Sum(nil)
	return "dc1:" + kind + ":" + hex.EncodeToString(sum[:8])
}

// Plural renders the JSON section key for a finding kind.
func Plural(kind string) string {
	if strings.HasSuffix(kind, "s") {
		return kind + "es"
	}
	if strings.HasSuffix(kind, "y") {
		return strings.TrimSuffix(kind, "y") + "ies"
	}
	return kind + "s"
}

// Singular renders the finding kind from a section key, when ambiguous.
func Singular(section string) string {
	if strings.HasSuffix(section, "ies") {
		return strings.TrimSuffix(section, "ies") + "y"
	}
	return strings.TrimSuffix(section, "s")
}

// SortFindings orders findings deterministically by section, path, line, col,
// and extra identity fields.
func SortFindings(fs []*Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Col != b.Col {
			return a.Col < b.Col
		}
		return identityOf(a) < identityOf(b)
	})
}

func identityOf(f *Finding) string {
	for _, key := range []string{"export_name", "symbol", "package_name", "member", "field", "cycle_index", "from_path", "to_path"} {
		if v, ok := f.Extra[key]; ok {
			return fmt.Sprint(v)
		}
	}
	return f.Message
}

// DocLink returns the documentation link shown under a human section.
func DocLink(kind string) string {
	return "https://github.com/rf/goose/blob/main/docs/explanations/dead-code.md#" + strings.ReplaceAll(kind, " ", "-")
}
