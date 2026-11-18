package report

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"goose/internal/glob"
)

// --group-by modes mirror fallow: owner (CODEOWNERS), directory (first path
// component), package (workspace package), section (GitLab CODEOWNERS
// [Section] headers).

// Group labels for unmatched files, mirroring fallow's constants.
const (
	UnownedLabel   = "(unowned)"
	NoSectionLabel = "(no section)"
	RootPkgLabel   = "(root)"
)

// NormalizeGroupBy maps a --group-by value (with fallow's aliases) to a
// canonical mode. ok=false for anything else, which callers turn into exit 2.
func NormalizeGroupBy(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "owner", "team", "codeowner":
		return "owner", true
	case "directory":
		return "directory", true
	case "package", "workspace", "pkg":
		return "package", true
	case "section", "gl-section":
		return "section", true
	}
	return "", false
}

// CodeownersRule is one CODEOWNERS line: pattern, owners, section, negation.
type CodeownersRule struct {
	Pattern string
	Owners  []string
	Section string // "" before any [Section] header
	Negate  bool
	Globs   []*glob.Pattern
}

// CodeownersData is a parsed CODEOWNERS file.
type CodeownersData struct {
	Rules []CodeownersRule
	// SectionOwners maps a section name to its default owners.
	SectionOwners map[string][]string
	Sections      bool
}

// ParseCodeowners reads GitHub/GitLab CODEOWNERS text. Section headers look
// like `[Name] @a @b`; rules are `pattern @owner @owner`, with a leading `!`
// for GitLab negations. Patterns follow gitignore-ish semantics translated
// the way fallow does: a trailing `/` matches contents only, a pattern
// without an inner `/` matches at any depth, and a plain pattern matches the
// file or everything below a directory. Last match wins.
func ParseCodeowners(text string) *CodeownersData {
	co := &CodeownersData{SectionOwners: map[string][]string{}}
	section := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			end := strings.Index(line, "]")
			if end > 0 {
				name := strings.TrimSpace(line[1:end])
				section = name
				co.Sections = true
				if rest := strings.Fields(line[end+1:]); len(rest) > 0 {
					co.SectionOwners[name] = rest
				}
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pat := fields[0]
		r := CodeownersRule{Section: section}
		if strings.HasPrefix(pat, "!") && len(pat) > 1 {
			r.Negate = true
			r.Pattern = pat[1:]
		} else {
			r.Pattern = pat
		}
		r.Owners = fields[1:]
		for _, g := range translateCodeownersPattern(r.Pattern) {
			pat, err := glob.Compile(g, glob.Options{})
			if err == nil {
				r.Globs = append(r.Globs, pat)
			}
		}
		co.Rules = append(co.Rules, r)
	}
	return co
}

// translateCodeownersPattern turns one CODEOWNERS pattern into globs, exactly
// like fallow's translate_pattern: anchored and directory-only variants.
func translateCodeownersPattern(pattern string) []string {
	anchored := false
	rest := pattern
	if strings.HasPrefix(rest, "/") {
		anchored, rest = true, rest[1:]
	}
	dirOnly := false
	if strings.HasSuffix(rest, "/") {
		dirOnly, rest = true, strings.TrimSuffix(rest, "/")
	}
	if rest == "" {
		return []string{"**"}
	}
	base := rest
	if !anchored && !strings.Contains(rest, "/") {
		base = "**/" + rest
	}
	contents := base + "/**"
	if dirOnly {
		return []string{contents}
	}
	last := base
	if i := strings.LastIndex(base, "/"); i >= 0 {
		last = base[i+1:]
	}
	if last == "*" || last == "**" {
		return []string{base}
	}
	return []string{base, contents}
}

// lastMatch returns the index of the last rule matching rel, or -1.
func (co *CodeownersData) lastMatch(rel string) int {
	best := -1
	for ri := range co.Rules {
		for _, g := range co.Rules[ri].Globs {
			if g.Match(rel) {
				best = ri
				break
			}
		}
	}
	return best
}

// OwnerOf resolves the first owner of the last matching rule. A negation
// match or an owner-less rule makes the file unowned.
func (co *CodeownersData) OwnerOf(rel string) (string, bool) {
	i := co.lastMatch(rel)
	if i < 0 {
		return "", false
	}
	r := co.Rules[i]
	if r.Negate || len(r.Owners) == 0 {
		return "", false
	}
	return r.Owners[0], true
}

// SectionOf resolves the section name of the last matching rule. The bool
// reports whether a non-negation rule matched at all; an empty name with
// true means a rule before any [Section] header.
func (co *CodeownersData) SectionOf(rel string) (string, bool) {
	i := co.lastMatch(rel)
	if i < 0 || co.Rules[i].Negate {
		return "", false
	}
	return co.Rules[i].Section, true
}

// Workspace names one package bucket for --group-by package.
type Workspace struct {
	RelRoot string // repo-relative, forward slashes, no trailing slash
	Name    string
}

// Ownership resolves finding paths to --group-by keys. Only the input
// matching Mode is consulted; the others may be nil.
type Ownership struct {
	Mode       string // owner | directory | package | section
	CO         *CodeownersData
	Workspaces []Workspace
}

// Key resolves one finding path to its group key.
func (o *Ownership) Key(p string) string {
	rel := relForGroup(p)
	switch o.Mode {
	case "directory":
		return directoryGroup(rel)
	case "package":
		return o.packageKey(rel)
	case "owner":
		if o.CO == nil {
			return UnownedLabel
		}
		owner, ok := o.CO.OwnerOf(rel)
		if !ok {
			return UnownedLabel
		}
		return owner
	case "section":
		if o.CO == nil {
			return UnownedLabel
		}
		sec, ok := o.CO.SectionOf(rel)
		if !ok {
			return UnownedLabel
		}
		if sec == "" {
			return NoSectionLabel
		}
		return sec
	}
	return UnownedLabel
}

// Owners returns the section default owners for a path (section mode only),
// or nil outside section mode.
func (o *Ownership) Owners(p string) []string {
	if o.Mode != "section" || o.CO == nil {
		return nil
	}
	sec, ok := o.CO.SectionOf(relForGroup(p))
	if !ok {
		return nil
	}
	if sec == "" {
		return []string{}
	}
	owners := o.CO.SectionOwners[sec]
	if owners == nil {
		return []string{}
	}
	return owners
}

// relForGroup normalizes a project-relative finding path for matching.
func relForGroup(p string) string {
	p = strings.TrimPrefix(p, "./")
	if p == "" {
		return "."
	}
	return path.Clean(p)
}

// directoryGroup is the first path component; a root-level file names itself.
func directoryGroup(rel string) string {
	if i := strings.Index(rel, "/"); i >= 0 {
		return rel[:i]
	}
	return rel
}

// packageKey uses longest-prefix workspace matching; unmatched files are
// (root).
func (o *Ownership) packageKey(rel string) string {
	bestRoot, bestName := "", ""
	for _, w := range o.Workspaces {
		if w.RelRoot == "" {
			continue
		}
		if rel == w.RelRoot || strings.HasPrefix(rel, w.RelRoot+"/") {
			if len(w.RelRoot) > len(bestRoot) {
				bestRoot, bestName = w.RelRoot, w.Name
			}
		}
	}
	if bestName == "" {
		return RootPkgLabel
	}
	return bestName
}

// GroupEntry is one bucket of a grouped run. Sections holds the bucket's
// findings by plural section key; Extra carries surface-specific payloads
// (dupes clone_groups, health bodies).
type GroupEntry struct {
	Key      string
	Owners   []string
	Total    int
	Sections map[string][]*Finding
	Extra    map[string]any
}

// pinnedGroup reports whether a key sorts last regardless of size.
func pinnedGroup(k string) bool {
	switch k {
	case UnownedLabel, NoSectionLabel, RootPkgLabel:
		return true
	}
	return false
}

// sortGroupKeys orders buckets by descending size, then key, with the
// placeholder labels pinned last, like fallow's finalize_groups.
func sortGroupKeys(keys []string, totals map[string]int) {
	sort.SliceStable(keys, func(i, j int) bool {
		pi, pj := pinnedGroup(keys[i]), pinnedGroup(keys[j])
		if pi != pj {
			return !pi
		}
		if totals[keys[i]] != totals[keys[j]] {
			return totals[keys[i]] > totals[keys[j]]
		}
		return keys[i] < keys[j]
	})
}

// PartitionDoc groups the document's visible findings by the resolver.
func (d *Doc) PartitionDoc(o *Ownership) []*GroupEntry {
	if o == nil {
		return nil
	}
	byKey := map[string]*GroupEntry{}
	totals := map[string]int{}
	ownerSeed := map[string]bool{}
	keyOf := func(k string) *GroupEntry {
		g, ok := byKey[k]
		if !ok {
			g = &GroupEntry{Key: k, Sections: map[string][]*Finding{}}
			byKey[k] = g
		}
		return g
	}
	for _, f := range d.Visible() {
		k := o.Key(f.Path)
		g := keyOf(k)
		if o.Mode == "section" && !ownerSeed[k] {
			owners := o.Owners(f.Path)
			if owners == nil {
				owners = []string{}
			}
			g.Owners = owners
			ownerSeed[k] = true
		}
		sec := f.SectionName()
		g.Sections[sec] = append(g.Sections[sec], f)
		g.Total++
		totals[k] = g.Total
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sortGroupKeys(keys, totals)
	for _, k := range keys {
		for _, fs := range byKey[k].Sections {
			SortFindings(fs)
		}
	}
	out := make([]*GroupEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}

// GroupedJSON renders fallow's grouped envelope: kind suffixed "-grouped",
// grouped_by, total_issues, and groups[] with flattened section arrays plus
// any per-group Extra payloads (dupes passes pre-partitioned clone groups).
func (d *Doc) GroupedJSON(groups []*GroupEntry, ownership *Ownership, o Options) string {
	s, err := JSONString(d.groupedJSONBody(groups, ownership, o))
	if err != nil {
		return "{}"
	}
	return s
}

func (d *Doc) groupedJSONBody(groups []*GroupEntry, ownership *Ownership, o Options) map[string]any {
	raw := make([]any, 0, len(groups))
	for _, g := range groups {
		m := map[string]any{"key": g.Key}
		if ownership.Mode == "section" {
			owners := g.Owners
			if owners == nil {
				owners = []string{}
			}
			m["owners"] = owners
		}
		for k, v := range g.Extra {
			m[k] = v
		}
		m["total_issues"] = g.Total
		for secKey, fs := range g.Sections {
			items := make([]any, 0, len(fs))
			for _, f := range fs {
				items = append(items, findingJSONObject(f, o))
			}
			if o.Lean && len(items) == 0 {
				continue
			}
			m[secKey] = items
		}
		raw = append(raw, m)
	}
	root := map[string]any{}
	for k, v := range d.Envelope {
		if k == "kind" || k == "total_issues" {
			continue
		}
		root[k] = v
	}
	root["kind"] = d.Kind + "-grouped"
	root["grouped_by"] = ownership.Mode
	delete(root, "summary")
	total := 0
	for _, g := range groups {
		total += g.Total
	}
	root["total_issues"] = total
	root["groups"] = raw
	return root
}

// renderSections emits the flat body layout (per-kind sections without the
// banner) for reuse inside grouped human output.
func renderSections(d *Doc) string {
	var b strings.Builder
	for _, sec := range d.orderedSections() {
		title := SectionTitle(sec.Kind)
		marker := "●"
		if sec.Kind == "stale-suppression" || sec.Kind == "missing-suppression-reason" {
			marker = "○"
		}
		fmt.Fprintf(&b, "\n%s %s (%d)\n", marker, title, len(sec.Findings))
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
			if len(g.fs) > 1 {
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
				fmt.Fprintf(&b, "    :%d %s\n", f.Line, ident)
			}
		}
	}
	return b.String()
}

// GroupedHuman renders one block per bucket under a mode header.
func (d *Doc) GroupedHuman(groups []*GroupEntry, ownership *Ownership, colors bool) string {
	var b strings.Builder
	b.WriteString(headerFor(d, colors) + "\n")
	fmt.Fprintf(&b, "\nGrouped by %s\n", ownership.Mode)
	for _, g := range groups {
		fmt.Fprintf(&b, "\n◆ %s (%d issue%s)\n", g.Key, g.Total, pluralSuffix(g.Total))
		if len(g.Owners) > 0 {
			fmt.Fprintf(&b, "  owners: %s\n", strings.Join(g.Owners, ", "))
		}
		inner := &Doc{Kind: d.Kind}
		for _, sec := range sortedSectionKeys(g.Sections) {
			inner.Findings = append(inner.Findings, g.Sections[sec]...)
		}
		body := renderSections(inner)
		if body == "" {
			b.WriteString("  No issues in this group\n")
			continue
		}
		b.WriteString(body)
	}
	if d.TotalIssues() == 0 {
		fmt.Fprintf(&b, "\n No issues found\n")
	}
	fmt.Fprintf(&b, "\n%s %s (%.2fs)\n", d.HumanMark(colors), d.tailCounts(), float64(d.ElapsedMS)/1000.0)
	if line := d.GateSummaryLine(); line != "" {
		b.WriteString(line + "\n")
	}
	return b.String()
}

func pluralSuffix(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func sortedSectionKeys(m map[string][]*Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SortGroupKeys orders bucket keys by descending issue count, ties by key,
// with the placeholder labels ((unowned), (no section), (root)) pinned last.
func SortGroupKeys(keys []string, totals map[string]int) {
	sortGroupKeys(keys, totals)
}

// supportsGrouping reports whether a format carries grouped output. JSON and
// human render the groups themselves; SARIF and CodeClimate carry the key as
// a per-result property. Every other target renders one flat document.
func supportsGrouping(format string) bool {
	switch format {
	case "", "human", "json", "sarif", "codeclimate", "gitlab-codequality":
		return true
	}
	return false
}

// GroupingNote returns fallow's note for formats that cannot carry groups,
// or "" when the format supports grouping.
func GroupingNote(format, mode string) string {
	if mode == "" || supportsGrouping(format) {
		return ""
	}
	return fmt.Sprintf("note: --group-by %s is not supported for %s output, falling back to ungrouped output (use --format json for the full grouped envelope)", mode, format)
}

// PrintGroupingNote emits the fallback note on stderr.
func PrintGroupingNote(format, mode string) {
	if note := GroupingNote(format, mode); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
}

// GroupFilter applies --group selectors: exact keys, glob patterns, and
// `!`-prefixed negations, last match wins.
type GroupFilter struct {
	patterns []string
	matcher  *glob.Matcher
}

// NewGroupFilter compiles the selector list.
func NewGroupFilter(patterns []string) (*GroupFilter, error) {
	m, err := glob.NewMatcher(patterns, glob.Options{})
	if err != nil {
		return nil, err
	}
	return &GroupFilter{patterns: patterns, matcher: m}, nil
}

// Keep reports whether a group key survives the selector.
func (gf *GroupFilter) Keep(key string) bool {
	if gf == nil || len(gf.patterns) == 0 {
		return true
	}
	return gf.matcher.Match(key)
}

// Unmatched lists the positive patterns that matched no kept-or-seen key.
func (gf *GroupFilter) Unmatched(keys []string) []string {
	if gf == nil || len(gf.patterns) == 0 {
		return nil
	}
	var out []string
	for _, p := range gf.patterns {
		if strings.HasPrefix(p, "!") {
			continue
		}
		hit := false
		for _, k := range keys {
			m, err := glob.Compile(p, glob.Options{})
			if err == nil && m.Match(k) {
				hit = true
				break
			}
		}
		if !hit {
			out = append(out, p)
		}
	}
	return out
}

// GroupedRoot assembles the fallow grouped envelope: the flat document's
// identity fields, grouped_by, total_issues, and a groups array of
// caller-built group objects.
func GroupedRoot(kind string, schemaVersion int, ownership *Ownership, projectEnvelope map[string]any, groups []map[string]any, total int) map[string]any {
	root := map[string]any{}
	for k, v := range projectEnvelope {
		if k == "kind" || k == "groups" || k == "grouped_by" {
			continue
		}
		root[k] = v
	}
	root["kind"] = kind
	root["schema_version"] = schemaVersion
	root["grouped_by"] = ownership.Mode
	totalCopy := total
	groupsCopy := groups
	if groupsCopy == nil {
		groupsCopy = []map[string]any{}
	}
	root["total_issues"] = totalCopy
	root["groups"] = groupsCopy
	return root
}

// PartitionCloneGroups buckets dupes clone-group payloads by their largest
// owner: the key with the most instances wins, ties break alphabetically.
func PartitionCloneGroups(cloneGroups []any, ownership *Ownership) ([]*GroupEntry, int) {
	byKey := map[string][]any{}
	totals := map[string]int{}
	for _, item := range cloneGroups {
		g, _ := item.(map[string]any)
		if g == nil {
			continue
		}
		counts := map[string]int{}
		if insts, ok := g["instances"].([]any); ok {
			for _, it := range insts {
				im, _ := it.(map[string]any)
				if im == nil {
					continue
				}
				if p, ok2 := im["file"].(string); ok2 {
					counts[ownership.Key(p)]++
				}
			}
		}
		best, bestN := UnownedLabel, -1
		for k, n := range counts {
			if n > bestN || (n == bestN && k < best) {
				best, bestN = k, n
			}
		}
		byKey[best] = append(byKey[best], g)
		totals[best]++
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sortGroupKeys(keys, totals)
	out := make([]*GroupEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, &GroupEntry{Key: k, Total: totals[k], Extra: map[string]any{"clone_groups": byKey[k]}})
	}
	return out, len(cloneGroups)
}

// DupesGroupedJSON renders fallow's grouped duplication envelope: the flat
// document's identity fields minus the group arrays, plus grouped_by,
// total_issues (clone groups across all buckets), and groups[] where each
// bucket carries the clone groups attributed to its largest owner.
func (d *Doc) DupesGroupedJSON(ownership *Ownership, o Options) string {
	cg, _ := d.Envelope["clone_groups"].([]any)
	entries, _ := PartitionCloneGroups(cg, ownership)
	groups := make([]map[string]any, 0, len(entries))
	total := 0
	for _, e := range entries {
		m := map[string]any{"key": e.Key}
		if ownership.Mode == "section" {
			owners := e.Owners
			if owners == nil {
				owners = []string{}
			}
			m["owners"] = owners
		}
		m["total_issues"] = e.Total
		m["clone_groups"] = e.Extra["clone_groups"]
		if n, ok := e.Extra["files_with_duplication"]; ok {
			m["files_with_duplication"] = n
		}
		groups = append(groups, m)
		total += e.Total
	}
	envelope := map[string]any{}
	for k, v := range d.Envelope {
		switch k {
		case "clone_groups", "clone_groups_shown", "clone_groups_omitted", "kind", "total_issues":
			continue
		}
		envelope[k] = v
	}
	root := GroupedRoot("dupes-grouped", schemaVersionFor("dupes"), ownership, envelope, groups, total)
	if len(d.Gates) > 0 {
		gm := map[string]any{}
		for name, g := range d.Gates {
			gm[name] = g
		}
		root["gate_outcomes"] = gm
	}
	body, err := JSONString(root)
	if err != nil {
		return "{}"
	}
	if o.Pretty {
		if s, perr := MarshalIndent(root); perr == nil {
			return string(s)
		}
	}
	return body
}
