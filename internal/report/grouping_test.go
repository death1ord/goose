package report

import (
	"encoding/json"
	"strings"
	"testing"

	"goose/internal/config"
)

func TestNormalizeGroupByAliases(t *testing.T) {
	for in, want := range map[string]string{
		"owner": "owner", "team": "owner", "CodeOwner": "owner",
		"directory": "directory",
		"package":   "package", "workspace": "package", "pkg": "package",
		"section": "section", "gl-section": "section",
	} {
		got, ok := NormalizeGroupBy(in)
		if !ok || got != want {
			t.Fatalf("%q -> %q,%v want %q", in, got, ok, want)
		}
	}
	if _, ok := NormalizeGroupBy("bogus"); ok {
		t.Fatal("bogus must not normalize")
	}
}

func TestDirectoryGroupAndPackageKey(t *testing.T) {
	if got := directoryGroup("src/utils/index.go"); got != "src" {
		t.Fatalf("directory group: %s", got)
	}
	if got := directoryGroup("main.go"); got != "main.go" {
		t.Fatalf("root file names itself: %s", got)
	}
	o := &Ownership{Mode: "package", Workspaces: []Workspace{
		{RelRoot: "apps/api", Name: "example.com/apps/api"},
		{RelRoot: "apps", Name: "example.com/apps"},
	}}
	if got := o.Key("apps/api/routes/x.go"); got != "example.com/apps/api" {
		t.Fatalf("longest prefix must win: %s", got)
	}
	if got := o.Key("apps/web/x.go"); got != "example.com/apps" {
		t.Fatalf("shallower match: %s", got)
	}
	if got := o.Key("libs/x.go"); got != RootPkgLabel {
		t.Fatalf("unmatched must be (root): %s", got)
	}
}

func TestCodeownersLastMatchAndNegation(t *testing.T) {
	co := ParseCodeowners("# comment\n* @default\nsrc/ @web\n!src/generated/\n")
	if o, ok := co.OwnerOf("readme.md"); !ok || o != "@default" {
		t.Fatalf("root catch-all: %q %v", o, ok)
	}
	if o, ok := co.OwnerOf("src/app/x.go"); !ok || o != "@web" {
		t.Fatalf("later rule wins: %q %v", o, ok)
	}
	if _, ok := co.OwnerOf("src/generated/api.go"); ok {
		t.Fatal("negation must clear ownership")
	}
	// Unanchored single-segment patterns match at any depth.
	co2 := ParseCodeowners("apps/ @apps-team\n")
	if o, ok := co2.OwnerOf("libs/internal/apps/web/a.go"); !ok || o != "@apps-team" {
		t.Fatalf("any-depth match: %q %v", o, ok)
	}
}

func TestSectionGroupingWithOwners(t *testing.T) {
	co := ParseCodeowners("[Frontend] @ui @ux\n/src/ui/\n[Backend] @api\n/src/api @api-lead\n")
	if !co.Sections {
		t.Fatal("sections must be detected")
	}
	o := &Ownership{Mode: "section", CO: co}
	if got := o.Key("src/ui/button/a.go"); got != "Frontend" {
		t.Fatalf("section key: %s", got)
	}
	if owners := o.Owners("src/ui/a.go"); len(owners) != 2 || owners[0] != "@ui" {
		t.Fatalf("section owners: %v", owners)
	}
	// A rule owned by nothing else still lands in its section.
	if got := o.Key("src/api/users.go"); got != "Backend" {
		t.Fatalf("backend section: %s", got)
	}
	if got := o.Key("docs/x.md"); got != UnownedLabel {
		t.Fatalf("no match must be unowned: %s", got)
	}
}

func TestOwnerOfNoOwnerRuleAndSectionBeforeHeader(t *testing.T) {
	co := ParseCodeowners("[Docs] @docs\n/docs/ @d1 * @d2\n")
	o := &Ownership{Mode: "section", CO: co}
	if owners := co.SectionOwners["Docs"]; len(owners) != 1 || owners[0] != "@docs" {
		t.Fatalf("section default owners: %v", owners)
	}
	// Only the first owner of a rule wins, so "@d1" heads the file rule.
	if owner, ok := co.OwnerOf("docs/guide.md"); !ok || owner != "@d1" {
		t.Fatalf("first owner wins: %q %v", owner, ok)
	}
	if got := o.Key("docs/guide.md"); got != "Docs" {
		t.Fatalf("section from rule: %s", got)
	}
	// No [Section] headers means no section mode.
	flat := ParseCodeowners("/src/ @x\n")
	if flat.Sections {
		t.Fatal("flat CODEOWNERS must report no sections")
	}
}

func mkFinding(kind, path string) *Finding {
	return &Finding{Kind: kind, Path: path, Severity: config.Warn, Message: "m"}
}

func TestPartitionOrderDescThenKeyWithPinnedLast(t *testing.T) {
	d := NewDoc("dead-code")
	d.Findings = []*Finding{
		mkFinding("unused-export", "src/a.go"),
		mkFinding("unused-export", "src/b.go"),
		mkFinding("unused-export", "docs/x.go"),
	}
	groups := d.PartitionDoc(&Ownership{Mode: "directory"})
	if len(groups) != 2 {
		t.Fatalf("groups: %d", len(groups))
	}
	if groups[0].Key != "src" || groups[0].Total != 2 {
		t.Fatalf("bigger bucket first: %+v", groups[0])
	}
	if groups[1].Key != "docs" {
		t.Fatalf("second: %s", groups[1].Key)
	}
	// (unowned) sorts last even when it is the biggest bucket.
	d2 := NewDoc("dead-code")
	d2.Findings = []*Finding{
		mkFinding("unused-export", "z/a.go"), mkFinding("unused-export", "z/b.go"), mkFinding("unused-export", "z/c.go"),
		mkFinding("unused-export", "top.go"),
	}
	g := d2.PartitionDoc(&Ownership{Mode: "owner"}) // no CODEOWNERS -> all unowned
	if len(g) != 1 || g[0].Key != UnownedLabel || g[0].Total != 4 {
		t.Fatalf("unowned bucket: %+v", g)
	}
}

func TestGroupedJSONBodyShape(t *testing.T) {
	d := NewDoc("dead-code")
	d.Findings = []*Finding{
		mkFinding("unused-export", "src/a.go"),
		mkFinding("unused-export", "lib/b.go"),
	}
	o := &Ownership{Mode: "directory"}
	out := d.GroupedJSON(d.PartitionDoc(o), o, Options{})
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["kind"] != "dead-code-grouped" || doc["grouped_by"] != "directory" {
		t.Fatalf("root: %v", doc["kind"])
	}
	if doc["total_issues"].(float64) != 2 {
		t.Fatalf("total: %v", doc["total_issues"])
	}
	groups, _ := doc["groups"].([]any)
	if len(groups) != 2 {
		t.Fatalf("groups: %d", len(groups))
	}
	g0 := groups[0].(map[string]any)
	if g0["key"].(string) == "" || g0["section"] != nil {
		t.Fatalf("group shape: %v", g0)
	}
	if _, ok := g0[Plural("unused-export")]; !ok {
		t.Fatalf("flattened section key missing: %v", g0)
	}
}

func TestGroupFilterGlobNegationAndUnmatched(t *testing.T) {
	gf, err := NewGroupFilter([]string{"@team/*", "!@team/b"})
	if err != nil {
		t.Fatal(err)
	}
	if !gf.Keep("@team/a") {
		t.Fatal("positive glob must match")
	}
	if gf.Keep("@team/b") {
		t.Fatal("negation must exclude")
	}
	if gf.Keep("other") {
		t.Fatal("non-matching key excluded")
	}
	// "@team/*" matched a seen key, and negations are never reported, so
	// nothing is unmatched here.
	if un := gf.Unmatched([]string{"@team/a", "@team/b"}); len(un) != 0 {
		t.Fatalf("unmatched: %v", un)
	}
	gf2, _ := NewGroupFilter([]string{"nomatch*", "@team/a"})
	un := gf2.Unmatched([]string{"@team/a"})
	if len(un) != 1 || un[0] != "nomatch*" {
		t.Fatalf("unmatched positive pattern: %v", un)
	}
}

func TestGroupingNoteUnsupportedFormats(t *testing.T) {
	if GroupingNote("json", "directory") != "" || GroupingNote("human", "owner") != "" {
		t.Fatal("supported formats must not note")
	}
	n := GroupingNote("compact", "directory")
	if !strings.Contains(n, "--group-by directory") || !strings.Contains(n, "compact") {
		t.Fatalf("note: %q", n)
	}
	if !supportsGrouping("sarif") || !supportsGrouping("codeclimate") {
		t.Fatal("machine formats annotate rather than fall back")
	}
}

func TestCloneGroupAttributionLargestOwnerTie(t *testing.T) {
	cloneGroups := []any{
		map[string]any{"instances": []any{
			map[string]any{"file": "a/x.go"}, map[string]any{"file": "a/y.go"},
			map[string]any{"file": "b/z.go"},
		}},
		map[string]any{"instances": []any{
			map[string]any{"file": "p/one.go"}, map[string]any{"file": "q/two.go"},
		}},
	}
	entries, total := PartitionCloneGroups(cloneGroups, &Ownership{Mode: "directory"})
	if total != 2 {
		t.Fatalf("total: %d", total)
	}
	if entries[0].Key != "a" || entries[0].Total != 1 {
		t.Fatalf("majority owner bucket: %+v", entries[0])
	}
	// Tie between p and q resolves alphabetically to p.
	if entries[1].Key != "p" {
		t.Fatalf("tie-break: %s", entries[1].Key)
	}
}
