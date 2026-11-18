package report

import (
	"strings"

	"goose/internal/config"
)

// Options controls rendering.
type Options struct {
	Format  string
	Pretty  bool
	Lean    bool
	Colors  bool
	Details bool // <details> wrappers in CI markdown
	Explain bool
	Quiet   bool
	Summary bool
	Prefix  string // repository-root path prefix for CI formats
	Version string
	// Ownership, when set, activates --group-by output on the formats that
	// carry groups; others render flat and print a fallback note.
	Ownership *Ownership
}

// Render produces the output text in the requested format.
func (d *Doc) Render(o Options) string {
	switch o.Format {
	case "", "human":
		if o.Ownership != nil && d.Kind != "dupes" {
			return d.GroupedHuman(d.PartitionDoc(o.Ownership), o.Ownership, o.Colors)
		}
		return d.Human(o.Colors)
	case "compact":
		return d.Compact()
	case "markdown":
		return d.Markdown(o.Details, "")
	case "json":
		return d.JSON(o)
	case "sarif":
		return d.SARIF(o)
	case "codeclimate", "gitlab-codequality":
		return d.CodeClimate(o)
	case "github-annotations":
		return d.GitHubAnnotations(o)
	case "github-summary":
		return d.GitHubSummary(o)
	case "pr-comment-github":
		return d.Markdown(o.Details, githubMarker) + prFooter(d, "GitHub")
	case "pr-comment-gitlab":
		return d.Markdown(o.Details, gitlabMarker) + prFooter(d, "GitLab")
	case "review-github":
		return d.ReviewGithub(o)
	case "review-gitlab":
		return d.ReviewGitlab(o)
	case "badge":
		return d.Badge()
	default:
		return d.Human(o.Colors)
	}
}

// FindingJSON renders the JSON shape of one finding with no path prefix.
func FindingJSON(f *Finding) map[string]any {
	return findingJSONObject(f, Options{})
}

// findingJSONObject builds the JSON shape of one finding.
func findingJSONObject(f *Finding, o Options) map[string]any {
	m := map[string]any{}
	m["path"] = withPrefix(f.Path, o.Prefix)
	if f.Line > 0 {
		m["line"] = f.Line
		m["col"] = f.Col
	}
	for k, v := range f.Extra {
		m[k] = v
	}
	if f.ID != "" {
		m["finding_id"] = f.ID
	}
	if len(f.Actions) > 0 {
		acts := make([]any, 0, len(f.Actions))
		for _, a := range f.Actions {
			acts = append(acts, a)
		}
		m["actions"] = acts
		autoFixable := false
		for _, a := range f.Actions {
			if a.AutoFixable {
				autoFixable = true
				break
			}
		}
		m["auto_fixable"] = autoFixable
	}
	if f.Severity != "" {
		m["effective_severity"] = string(f.Severity)
	}
	if len(f.Caveats) > 0 {
		m["caveats"] = f.Caveats
	}
	return m
}

// JSON renders the typed JSON document.
func (d *Doc) JSON(o Options) string {
	d.Lean = o.Lean
	if o.Ownership != nil {
		if d.Kind == "dupes" {
			return d.DupesGroupedJSON(o.Ownership, o)
		}
		return d.jsonBody(d.groupedJSONBody(d.PartitionDoc(o.Ownership), o.Ownership, o), o)
	}
	root := map[string]any{}
	for k, v := range d.Envelope {
		root[k] = v
	}
	if d.ElapsedMS != 0 {
		root["elapsed_ms"] = d.ElapsedMS
	}
	if d.Lean {
		root["profile"] = "lean"
	}
	total := d.TotalIssues()
	root["total_issues"] = total
	for _, sec := range d.orderedSections() {
		key := Plural(sec.Kind)
		items := make([]any, 0, len(sec.Findings))
		for _, f := range sec.Findings {
			items = append(items, findingJSONObject(f, o))
		}
		if d.Lean && len(items) == 0 {
			continue
		}
		root[key] = items
	}
	if d.Summary != nil && len(d.Summary) > 0 {
		root["summary"] = pruneZeroes(d.Summary, d.Lean)
	}
	if d.ScoreFields != nil {
		for k, v := range d.ScoreFields {
			root[k] = v
		}
	}
	if d.CascadeHidden > 0 {
		root["cascade_hidden"] = d.CascadeHidden
	}
	if len(d.Diagnostics) > 0 {
		root["workspace_diagnostics"] = d.diagnosticsJSON(o)
	}
	if len(d.Gates) > 0 {
		gm := map[string]any{}
		for name, g := range d.Gates {
			gm[name] = g
		}
		root["gate_outcomes"] = gm
	}
	if len(d.Requests) > 0 {
		rm := map[string]any{}
		for name, r := range d.Requests {
			rm[name] = r
		}
		root["request_outcomes"] = rm
	}
	if len(d.NextSteps) > 0 {
		ns := make([]any, 0, len(d.NextSteps))
		for _, n := range d.NextSteps {
			ns = append(ns, n)
		}
		root["next_steps"] = ns
	}
	if o.Explain {
		root["_meta"] = d.meta()
	}
	return d.jsonBody(root, o)
}

// jsonBody serializes a root object honoring --pretty.
func (d *Doc) jsonBody(root map[string]any, o Options) string {
	if o.Pretty {
		s, err := MarshalIndent(root)
		if err != nil {
			return "{}"
		}
		return string(s)
	}
	s, err := JSONString(root)
	if err != nil {
		return "{}"
	}
	return s
}

func (d *Doc) diagnosticsJSON(o Options) []any {
	lean := d.Lean
	out := []any{}
	seen := map[string]int{}
	for _, dg := range d.Diagnostics {
		if lean {
			if _, ok := seen[dg.Kind]; ok {
				seen[dg.Kind]++
				// bump count on the earlier entry
				for i := range out {
					m, _ := out[i].(map[string]any)
					if m != nil && m["kind"] == dg.Kind {
						c, _ := m["count"].(int)
						m["count"] = c + 1
						break
					}
				}
				continue
			}
			seen[dg.Kind] = 1
		}
		m := map[string]any{"path": dg.Path, "kind": dg.Kind}
		for k, v := range map[string]string{"message": dg.Message, "pattern": dg.Pattern, "rule": dg.Rule, "flag": dg.Flag, "cause": dg.Cause, "reason": dg.Reason} {
			if v != "" {
				m[k] = v
			}
		}
		if dg.Degrades {
			m["degrades_analysis"] = true
		}
		for k, v := range dg.Extra {
			m[k] = v
		}
		out = append(out, m)
	}
	return out
}

func pruneZeroes(m map[string]any, lean bool) map[string]any {
	if !lean {
		return m
	}
	out := map[string]any{}
	for k, v := range m {
		if n, ok := v.(int); ok && n == 0 {
			continue
		}
		out[k] = v
	}
	return out
}

func (d *Doc) meta() map[string]any {
	defs := map[string]any{}
	for _, sec := range d.orderedSections() {
		if desc := SectionDescription(sec.Kind); desc != "" {
			defs[sec.Kind] = map[string]any{"description": desc, "docs": DocLink(sec.Kind)}
		}
	}
	return map[string]any{"metrics": defs}
}

func withPrefix(p, prefix string) string {
	if prefix == "" {
		return p
	}
	if strings.HasSuffix(prefix, "/") {
		return prefix + p
	}
	return prefix + "/" + p
}

var _ = config.Error
