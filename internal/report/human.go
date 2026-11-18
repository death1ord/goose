package report

import (
	"fmt"
	"sort"
	"strings"

	"goose/internal/config"
)

// sectionOrder is the canonical display order of dead-code section kinds.
var sectionOrder = []string{
	"unused-file", "unused-export", "unused-unexported", "unused-type",
	"unused-field", "unused-method", "unused-constant", "unused-variable",
	"unused-dependency", "unused-test-dependency", "unlisted-dependency",
	"unresolved-import", "duplicate-export", "circular-dependency",
	"package-cycle", "boundary-violation", "policy-violation",
	"stale-suppression", "missing-suppression-reason",
}

// orderedSections returns (kind, findings) pairs sorted for display.
func (d *Doc) orderedSections() []struct {
	Kind     string
	Findings []*Finding
} {
	byKind := map[string][]*Finding{}
	for _, f := range d.Visible() {
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}
	var kinds []string
	for _, k := range sectionOrder {
		if len(byKind[k]) > 0 {
			kinds = append(kinds, k)
		}
	}
	known := map[string]bool{}
	for _, k := range kinds {
		known[k] = true
	}
	var extra []string
	for k := range byKind {
		if !known[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	kinds = append(kinds, extra...)
	out := make([]struct {
		Kind     string
		Findings []*Finding
	}, 0, len(kinds))
	for _, k := range kinds {
		fs := byKind[k]
		SortFindings(fs)
		out = append(out, struct {
			Kind     string
			Findings []*Finding
		}{k, fs})
	}
	return out
}

// identityField returns the short identity label of a finding for the listing.
func identityField(f *Finding) string {
	for _, key := range []string{"symbol", "export_name", "type_name", "member", "field", "method", "package_name", "specifier", "name"} {
		if v, ok := f.Extra[key]; ok && fmt.Sprint(v) != "" {
			s := fmt.Sprint(v)
			if key == "package_name" {
				s += " (" + fmt.Sprint(f.Extra["location"]) + ")"
			}
			return s
		}
	}
	return ""
}

// Human renders the terminal report. colors toggles ANSI.
func (d *Doc) Human(colors bool) string {
	var b strings.Builder
	dim, red, yellow := "", "", ""
	if colors {
		dim, red, yellow = "\x1b[2m", "\x1b[31m", "\x1b[33m"
	}
	_ = red
	_ = yellow
	b.WriteString(headerFor(d, colors) + "\n")
	for _, sec := range d.orderedSections() {
		title := SectionTitle(sec.Kind)
		warn := false
		for _, f := range sec.Findings {
			if f.Severity == config.Warn {
				warn = true
			}
		}
		marker := "●"
		if sec.Kind == "stale-suppression" || sec.Kind == "missing-suppression-reason" {
			marker = "○"
		}
		fmt.Fprintf(&b, "\n%s %s (%d)\n", marker, title, len(sec.Findings))
		// Group by path, preserving sorted order.
		type pathGroup struct {
			path string
			fs   []*Finding
		}
		var groups []pathGroup
		index := map[string]int{}
		for _, f := range sec.Findings {
			if i, ok := index[f.Path]; ok {
				groups[i].fs = append(groups[i].fs, f)
				continue
			}
			index[f.Path] = len(groups)
			groups = append(groups, pathGroup{f.Path, []*Finding{f}})
		}
		for _, g := range groups {
			multi := len(g.fs) > 1
			if multi {
				fmt.Fprintf(&b, "  %s (%d)\n", g.path, len(g.fs))
			} else {
				fmt.Fprintf(&b, "  %s\n", g.path)
			}
			for _, f := range g.fs {
				if sec.Kind == "unused-file" {
					continue
				}
				ident := identityField(f)
				if ident == "" {
					ident = strings.TrimPrefix(f.Message, "unused ")
				}
				suffix := ""
				if f.Kind == "unused-export" && hasFlag(f, "is_re_export") {
					suffix = " (re-export)"
				}
				if sec.Kind == "unresolved-import" {
					fmt.Fprintf(&b, "    :%d %s\n", f.Line, dim+ident+reset(colors))
					continue
				}
				fmt.Fprintf(&b, "    :%d %s%s\n", f.Line, ident, suffix)
			}
			_ = warn
		}
		if desc := SectionDescription(sec.Kind); desc != "" {
			fmt.Fprintf(&b, "  %s\n", desc)
		}
		fmt.Fprintf(&b, "  %s\n", DocLink(sec.Kind))
		if fixable := hasFixable(sec.Findings); fixable {
			fmt.Fprintf(&b, "  %s\n", "To auto-fix: goose fix --dry-run")
		}
		if hint := SuppressHint(sec.Kind); hint != "" && len(sec.Findings) > 0 {
			fmt.Fprintf(&b, "  To suppress: %s\n", hint)
		}
	}
	if d.TotalIssues() == 0 {
		fmt.Fprintf(&b, "\n%s No issues found%s\n", dim, reset(colors))
	}
	if len(d.Diagnostics) > 0 {
		for _, dg := range d.Diagnostics {
			if strings.Contains(dg.Kind, "unmatched") || strings.Contains(dg.Kind, "redundant") || strings.Contains(dg.Kind, "ineffective") || strings.Contains(dg.Kind, "never-analyzed") {
				fmt.Fprintf(&b, "\nNote: %s (%s)\n", dg.Message, dg.Path)
			}
		}
	}
	fmt.Fprintf(&b, "\n%s %s (%.2fs)\n", d.HumanMark(colors), d.tailCounts(), float64(d.ElapsedMS)/1000.0)
	if line := d.GateSummaryLine(); line != "" {
		b.WriteString(line + "\n")
	}
	return b.String()
}

// HumanMark renders the colored run mark.
func (d *Doc) HumanMark(colors bool) string {
	_ = colors
	return d.Mark()
}

// headerFor renders the category banner. The architecture surface uses its
// own heading, the same fallow layout used for the check category.
func headerFor(d *Doc, colors bool) string {
	label := "Code Health"
	switch d.Kind {
	case "architecture":
		label = "Architecture"
	case "combined":
		label = "Code Health"
	case "dupes":
		label = "Duplication"
	}
	head := label + " "
	pad := 51 - len([]rune(head))
	if pad < 1 {
		pad = 1
	}
	return bold(colors) + head + strings.Repeat("─", pad) + reset(colors)
}

func reset(on bool) string {
	if on {
		return "\x1b[0m"
	}
	return ""
}

func (d *Doc) tailCounts() string {
	counts := map[string]int{}
	for _, f := range d.Visible() {
		counts[f.Kind]++
	}
	var parts []string
	for _, k := range sectionOrder {
		if n, ok := counts[k]; ok && n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, tailNoun(k, n)))
		}
	}
	for _, k := range sortedExtras(counts) {
		parts = append(parts, fmt.Sprintf("%d %s", counts[k], tailNoun(k, counts[k])))
	}
	if len(parts) == 0 {
		return "no issues"
	}
	return strings.Join(parts, " · ")
}

// sortedExtras lists kinds outside the canonical order, alphabetically.
func sortedExtras(counts map[string]int) []string {
	var out []string
	for k := range counts {
		if _, ok := countsInOrder(k); !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

var tailNouns = map[string]string{
	"unused-file": "file", "unused-export": "export",
	"unused-unexported": "symbol", "unused-type": "type",
	"unused-field": "field", "unused-method": "method",
	"unused-constant": "constant", "unused-variable": "variable",
	"unused-dependency": "dependency", "unused-test-dependency": "test dependency",
	"unlisted-dependency": "unlisted dependency", "unresolved-import": "unresolved import",
	"duplicate-export": "duplicate export", "circular-dependency": "cycle",
	"package-cycle": "package cycle", "boundary-violation": "boundary violation",
	"policy-violation": "policy violation", "stale-suppression": "stale suppression",
	"missing-suppression-reason": "suppression without a reason",
	"write-only-field": "write-only field", "write-only-variable": "write-only variable",
	"can-be-unexported": "over-exported symbol", "unused-interface-method": "unused interface method",
	"unused-parameter": "unused parameter", "unused-receiver": "unused receiver",
	"struct-padding": "padded struct", "nil-error-interface": "typed-nil return",
	"context-leak": "context leak", "defer-in-loop": "defer in loop",
	"unclosed-body": "unclosed resource", "copylocks": "lock copy",
	"deep-import": "deep import", "feature-flag": "feature flag",
	"stale-feature-flag": "stale feature flag", "security-candidate": "security candidate",
	"secret-in-code": "hardcoded secret", "diverged-clone-sibling": "diverged clone",
}

// pluralWord pluralizes an English count noun the way the fallow summary does.
func pluralWord(word string, n int) string {
	if n == 1 {
		return word
	}
	switch {
	case strings.HasSuffix(word, "y"):
		return strings.TrimSuffix(word, "y") + "ies"
	case strings.HasSuffix(word, "s"), strings.HasSuffix(word, "x"),
		strings.HasSuffix(word, "z"), strings.HasSuffix(word, "ch"),
		strings.HasSuffix(word, "sh"):
		return word + "es"
	}
	return word + "s"
}

func tailNoun(kind string, n int) string {
	base, ok := tailNouns[kind]
	if !ok {
		base = pluralWord(strings.ReplaceAll(kind, "-", " "), n)
		return base
	}
	return pluralWord(base, n)
}

func countsInOrder(kind string) (int, bool) {
	for i, k := range sectionOrder {
		if k == kind {
			return i, true
		}
	}
	return 0, false
}

// Compact renders one line per finding.
func (d *Doc) Compact() string {
	var b strings.Builder
	for _, sec := range d.orderedSections() {
		for _, f := range sec.Findings {
			if f.Kind == "clone-group" {
				filePath := f.Path
				line := f.Line
				col := f.Col
				instanceCount := 0
				tokens := 0
				if v, ok := f.Extra["instances"]; ok {
					switch iv := v.(type) {
					case int:
						instanceCount = iv
					case int64:
						instanceCount = int(iv)
					case float64:
						instanceCount = int(iv)
					case []any:
						instanceCount = len(iv)
						if len(iv) > 0 {
							if m, ok := iv[0].(map[string]any); ok {
								if p, ok := m["file"].(string); ok && filePath == "" {
									filePath = p
								}
								if l, ok := m["start_line"].(float64); ok && line == 0 {
									line = int(l)
								} else if l, ok := m["start_line"].(int); ok && line == 0 {
									line = l
								}
								if c, ok := m["start_col"].(float64); ok && col == 0 {
									col = int(c)
								} else if c, ok := m["start_col"].(int); ok && col == 0 {
									col = c
								}
							}
						}
					}
				}
				if v, ok := f.Extra["tokens"]; ok {
					switch tv := v.(type) {
					case int:
						tokens = tv
					case int64:
						tokens = int(tv)
					case float64:
						tokens = int(tv)
					}
				}
				if instanceCount > 0 && tokens > 0 {
					b.WriteString(fmt.Sprintf("clone-group:%s:%d:%d (%d instances, %d tokens)\n", filePath, line, col, instanceCount, tokens))
				} else if instanceCount > 0 {
					b.WriteString(fmt.Sprintf("clone-group:%s:%d:%d (%d instances)\n", filePath, line, col, instanceCount))
				} else {
					b.WriteString(fmt.Sprintf("clone-group:%s:%d:%d\n", filePath, line, col))
				}
				continue
			}
			ident := identityField(f)
			if ident == "" {
				b.WriteString(fmt.Sprintf("%s:%s\n", shortKind(f.Kind), f.Path))
				continue
			}
			b.WriteString(fmt.Sprintf("%s:%s:%d:%s\n", shortKind(f.Kind), f.Path, f.Line, ident))
		}
	}
	for _, dg := range d.Diagnostics {
		if strings.Contains(dg.Kind, "unmatched") || strings.Contains(dg.Kind, "redundant") {
			fmt.Fprintf(&b, "note:%s:%s\n", dg.Kind, dg.Pattern)
		}
	}
	return b.String()
}

// shortKind keeps the singular finding token.
func shortKind(kind string) string { return kind }

// Markdown renders the PR-friendly report.
func (d *Doc) Markdown(withDetails bool, marker string) string {
	var b strings.Builder
	n := d.TotalIssues()
	if n == 1 {
		fmt.Fprintf(&b, "## Goose: 1 issue found\n")
	} else if n > 1 {
		fmt.Fprintf(&b, "## Goose: %d issues found\n", n)
	} else {
		fmt.Fprintf(&b, "## Goose: no issues found\n")
	}
	for _, sec := range d.orderedSections() {
		fmt.Fprintf(&b, "\n### %s (%d)\n\n", SectionTitle(sec.Kind), len(sec.Findings))
		body := renderSectionMarkdown(sec.Kind, sec.Findings)
		if withDetails {
			fmt.Fprintf(&b, "<details>\n<summary>Show %d</summary>\n\n%s\n</details>\n", len(sec.Findings), body)
		} else {
			b.WriteString(body)
		}
	}
	if d.CascadeHidden > 0 {
		fmt.Fprintf(&b, "\n_%d findings in unused files are hidden; use `--show-cascade` to list them._\n", d.CascadeHidden)
	}
	if marker != "" {
		fmt.Fprintf(&b, "\n<!-- goose: %s -->\n", marker)
	}
	return b.String()
}

func renderSectionMarkdown(kind string, fs []*Finding) string {
	var b strings.Builder
	for _, f := range fs {
		ident := identityField(f)
		if kind == "unused-file" || ident == "" {
			fmt.Fprintf(&b, "- `%s`\n", f.Path)
			continue
		}
		fmt.Fprintf(&b, "- `%s`\n", f.Path)
		fmt.Fprintf(&b, "  - :%d `%s`\n", f.Line, ident)
	}
	return b.String()
}

func hasFlag(f *Finding, key string) bool {
	v, ok := f.Extra[key]
	bv, _ := v.(bool)
	return ok && bv
}

func hasFixable(fs []*Finding) bool {
	for _, f := range fs {
		for _, a := range f.Actions {
			if a.AutoFixable {
				return true
			}
		}
	}
	return false
}
