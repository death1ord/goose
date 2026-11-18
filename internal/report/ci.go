package report

import (
	"fmt"
	"sort"
	"strings"

	"goose/internal/config"
	"goose/internal/version"
)

// level maps a severity to the SARIF/GitHub level.
func level(sev config.Severity) string {
	if sev == config.Warn {
		return "warning"
	}
	return "error"
}

// ccSeverity maps severity to the Code Climate level.
func ccSeverity(sev config.Severity) string {
	if sev == config.Warn {
		return "minor"
	}
	return "major"
}

const (
	githubMarker = "goose-report-github"
	gitlabMarker = "goose-report-gitlab"
)

// SARIF renders the SARIF 2.1.0 document.
func (d *Doc) SARIF(o Options) string {
	rules := map[string]map[string]any{}
	results := []any{}
	for _, f := range d.Visible() {
		ruleID := "goose/" + f.Kind
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = map[string]any{
				"id":                   ruleID,
				"name":                 ruleID,
				"shortDescription":     map[string]any{"text": SectionTitle(f.Kind)},
				"fullDescription":      map[string]any{"text": SectionDescription(f.Kind)},
				"defaultConfiguration": map[string]any{"level": level(f.Severity)},
				"helpUri":              DocLink(f.Kind),
			}
		}
		region := map[string]any{"startLine": max1(f.Line), "startColumn": f.Col + 1}
		res := map[string]any{
			"ruleId":  ruleID,
			"level":   level(f.Severity),
			"message": map[string]any{"text": f.Message},
			"locations": []any{
				map[string]any{"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": withPrefix(f.Path, o.Prefix)},
					"region":           region,
				}},
			},
		}
		if f.ID != "" {
			fp := map[string]any{
				"fallowFinding/v1": f.ID,
			}
			h := strings.Split(f.ID, ":")
			if len(h) == 3 {
				fp["tools.fallow.fingerprint/v1"] = h[2]
			}
			res["partialFingerprints"] = fp
		}
		if o.Ownership != nil {
			prop := "owner"
			if d.Kind == "health" || d.Kind == "dupes" {
				prop = "group"
			}
			res["properties"] = map[string]any{prop: o.Ownership.Key(f.Path)}
		}
		results = append(results, res)
	}
	ruleList := make([]any, 0, len(rules))
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ruleList = append(ruleList, rules[id])
	}
	docs := map[string]any{}
	for _, dg := range d.Diagnostics {
		docs[dg.Kind] = map[string]any{"setting": dg.Rule, "pattern": dg.Pattern}
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name":    "goose",
				"version": version.Version,
				"rules":   ruleList,
			}},
			"results": results,
		}},
	}
	s, err := JSONString(doc)
	if err != nil {
		return "{}"
	}
	return s
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// CodeClimate renders the Code Climate JSON array.
func (d *Doc) CodeClimate(o Options) string {
	out := []any{}
	for _, f := range d.Visible() {
		fp := f.ID
		if fp == "" {
			fp = Fingerprint(f.Kind, f.Path, f.Message)
		}
		issue := map[string]any{
			"type":        "issue",
			"check_name":  "goose/" + f.Kind,
			"description": f.Message,
			"categories":  []string{"Bug Risk"},
			"severity":    ccSeverity(f.Severity),
			"fingerprint": short(fp),
			"location": map[string]any{
				"path":  withPrefix(f.Path, o.Prefix),
				"lines": map[string]any{"begin": max1(f.Line)},
			},
		}
		if o.Ownership != nil {
			issue["owner"] = o.Ownership.Key(f.Path)
		}
		out = append(out, issue)
	}
	s, err := JSONString(out)
	if err != nil {
		return "[]"
	}
	return s
}

// short keeps the final id segment as the fingerprint.
func short(fp string) string {
	if i := strings.LastIndex(fp, ":"); i >= 0 {
		return fp[i+1:]
	}
	return fp
}

// GitHubAnnotations renders the ::error / ::warning workflow command lines.
func (d *Doc) GitHubAnnotations(o Options) string {
	var b strings.Builder
	if note := d.requestLine(); note != "" {
		fmt.Fprintf(&b, "::notice::%s\n", note)
	}
	errs := []*Finding{}
	warns := []*Finding{}
	for _, f := range d.Visible() {
		if f.Severity == config.Warn {
			warns = append(warns, f)
		} else {
			errs = append(errs, f)
		}
	}
	for _, f := range append(errs, warns...) {
		lvl := "error"
		if f.Severity == config.Warn {
			lvl = "warning"
		}
		fmt.Fprintf(&b, "::%s file=%s,line=%d,col=%d,title=%s::%s\n",
			lvl, withPrefix(f.Path, o.Prefix), max1(f.Line), f.Col+1,
			SectionTitle(f.Kind), escapeAnno(f.Message))
	}
	return b.String()
}

func escapeAnno(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// GitHubSummary renders the job-summary markdown.
func (d *Doc) GitHubSummary(o Options) string {
	var b strings.Builder
	n := d.TotalIssues()
	if n == 0 {
		b.WriteString("## Goose: no issues found\n")
	} else {
		fmt.Fprintf(&b, "## Goose: %d issues\n\n", n)
		b.WriteString("| Category | Count |\n|:--|--:|\n")
		for _, sec := range d.orderedSections() {
			fmt.Fprintf(&b, "| %s | %d |\n", SectionTitle(sec.Kind), len(sec.Findings))
		}
		if d.TotalIssues() > 0 && o.Details {
			b.WriteString("\n<details>\n<summary>Details</summary>\n\n")
		} else if d.TotalIssues() > 0 {
			b.WriteString("\n")
		}
		if d.TotalIssues() > 0 {
			b.WriteString(d.Markdown(true, ""))
		}
		if o.Details && d.TotalIssues() > 0 {
			b.WriteString("\n</details>\n")
		}
	}
	if line := d.requestLine(); line != "" {
		fmt.Fprintf(&b, "\nRequest outcomes: %s\n", line)
	}
	return b.String()
}

// requestLine renders the compact request_outcomes summary used by CI formats.
func (d *Doc) requestLine() string {
	if len(d.Requests) == 0 {
		return ""
	}
	var parts []string
	names := make([]string, 0, len(d.Requests))
	for name := range d.Requests {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		r := d.Requests[name]
		if r.Status == "not-applied" {
			parts = append(parts, fmt.Sprintf("%s not applied (%s)", name, r.Reason))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "; ")
}

func prFooter(d *Doc, host string) string {
	line := d.requestLine()
	if line == "" {
		return fmt.Sprintf("\n<sub>goose · %s</sub>\n", host)
	}
	return fmt.Sprintf("\n<sub>goose · %s · %s</sub>\n", host, line)
}

// Badge renders a shields.io-style SVG for the health score.
func (d *Doc) Badge() string {
	score := "?"
	color := "yellow"
	if v, ok := d.ScoreFields["health_score"].(map[string]any); ok {
		if s, ok := v["score"].(float64); ok {
			score = fmt.Sprintf("%.0f", s)
			switch {
			case s >= 90:
				color = "brightgreen"
			case s >= 80:
				color = "green"
			case s >= 70:
				color = "yellowgreen"
			case s >= 60:
				color = "yellow"
			default:
				color = "red"
			}
		}
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="108" height="20" role="img" aria-label="goose: %s"><linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="r"><rect width="108" height="20" rx="3" fill="#fff"/></clipPath><g clip="url(#r)"><rect width="48" height="20" fill="#555"/><rect x="48" width="60" height="20" fill="%s"/><rect width="108" height="20" fill="url(#s)"/></g><g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110"><text x="250" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="380">goose</text><text x="250" y="140" transform="scale(.1)" textLength="380">goose</text><text x="770" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="500">%s</text><text x="770" y="140" transform="scale(.1)" textLength="500">%s</text></g></svg>`, score, color, score, score)
}
