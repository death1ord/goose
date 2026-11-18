package cli

import (
	"strings"
	"testing"

	"goose/internal/config"
	"goose/internal/report"
)

func wantUsage(t *testing.T, args []string, substr string) {
	t.Helper()
	_, err := Parse(args)
	if err == nil {
		t.Fatalf("%v: want usage error containing %q, got nil", args, substr)
	}
	e, ok := err.(ErrUsage)
	if !ok {
		t.Fatalf("%v: want ErrUsage, got %T(%v)", args, err, err)
	}
	if !strings.Contains(e.Error(), substr) {
		t.Fatalf("%v: want %q in %q", args, substr, e.Error())
	}
}

func TestParseBaselineGateValidation(t *testing.T) {
	wantUsage(t, []string{"--fail-on-baseline-growth"}, "needs a baseline")
	wantUsage(t, []string{"--baseline", "b.json", "--baseline-base", "main"}, "needs --fail-on-baseline-growth")
	// Valid shape: growth + baseline + base is accepted.
	f, err := Parse([]string{"--baseline", "b.json", "--fail-on-baseline-growth", "--baseline-base", "main"})
	if err != nil {
		t.Fatalf("valid combo rejected: %v", err)
	}
	if !f.FailOnBaselineGrowth || f.BaselineBase != "main" {
		t.Fatalf("flags not set: %+v", f)
	}
}

func TestParsePresentationFlagValidation(t *testing.T) {
	wantUsage(t, []string{"--lean"}, "--lean requires JSON output")
	wantUsage(t, []string{"--lean", "--format", "human"}, "--lean requires JSON output")
	wantUsage(t, []string{"--full-tables", "--format", "json"}, "needs --lean")
	wantUsage(t, []string{"--production", "--no-production"}, "cannot be combined")
	wantUsage(t, []string{"--type-aware", "--no-type-aware"}, "cannot be combined")
	wantUsage(t, []string{"--group", "x"}, "needs --group-by")
	wantUsage(t, []string{"--group-by", "bogus"}, "must be one of")
	if _, err := Parse([]string{"--format", "json", "--lean"}); err != nil {
		t.Fatalf("json+lean must parse: %v", err)
	}
	if _, err := Parse([]string{"--format", "json", "--lean", "--full-tables"}); err != nil {
		t.Fatalf("lean+full-tables must parse: %v", err)
	}
}

func TestValidateRunFlagsCommandScope(t *testing.T) {
	// --lean belongs only to the lean-profile envelopes.
	f := &Flags{Global: Global{Lean: true}}
	if err := validateRunFlags("dupes", f); err == nil {
		t.Fatal("dupes must reject --lean")
	}
	for _, cmd := range []string{"", "combined", "dead-code", "health"} {
		if err := validateRunFlags(cmd, f); err != nil {
			t.Fatalf("%s must accept --lean: %v", cmd, err)
		}
	}
	// --full-tables plus a --top cap is a contradiction on health.
	f2 := &Flags{Global: Global{Lean: true, FullTables: true}, Extra: map[string]string{"--top": "3"}}
	if err := validateRunFlags("health", f2); err == nil {
		t.Fatal("health must reject --top with --full-tables")
	}
	f3 := &Flags{Global: Global{Lean: true, FullTables: true}, Extra: map[string]string{"--top": ""}}
	if err := validateRunFlags("health", f3); err != nil {
		t.Fatalf("health without --top: %v", err)
	}
}

func TestParseSaveSnapshotOptionalValue(t *testing.T) {
	// Bare --save-snapshot takes the default path; the next flag must not be
	// swallowed.
	f, err := Parse([]string{"--save-snapshot", "--quiet"})
	if err != nil {
		t.Fatal(err)
	}
	if !f.SnapshotSet || f.SaveSnapshot != "" || !f.Quiet {
		t.Fatalf("bare form wrong: %+v", f)
	}
	f, err = Parse([]string{"--save-snapshot", "snap.json", "health"})
	if err != nil {
		t.Fatal(err)
	}
	if f.SaveSnapshot != "snap.json" || !f.Score {
		t.Fatalf("valued form wrong: %+v", f)
	}
	if len(f.Args) != 1 || f.Args[0] != "health" {
		t.Fatalf("positional lost: %v", f.Args)
	}
}

func TestParseTrendFlagsImplyScore(t *testing.T) {
	f, err := Parse([]string{"--trend"})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Trend || !f.Score {
		t.Fatalf("--trend must imply --score: %+v", f)
	}
	f, err = Parse([]string{"--trend-from", "base.json"})
	if err != nil {
		t.Fatal(err)
	}
	if f.TrendFrom != "base.json" || !f.Trend || !f.Score {
		t.Fatalf("--trend-from must imply trend+score: %+v", f)
	}
}

func TestOptionalValueDoesNotSwallowPositional(t *testing.T) {
	f, err := Parse([]string{"--save-snapshot", "snap.json"})
	if err != nil {
		t.Fatal(err)
	}
	if f.SaveSnapshot != "snap.json" {
		t.Fatalf("value: %q", f.SaveSnapshot)
	}
	if len(f.Args) != 0 {
		t.Fatalf("value misread as positional: %v", f.Args)
	}
}

func TestBaselineStaleInertRules(t *testing.T) {
	f := &Flags{Global: Global{Baseline: "b.json"}}
	if baselineStaleInert(f, ".") != "" {
		t.Fatal("unscoped run must not be inert")
	}
	f.BaselineScoped = true
	if why := baselineStaleInert(f, t.TempDir()); why == "" {
		t.Fatal("scoped run must stand the stale gate down")
	}
	f = &Flags{Global: Global{Baseline: "b.json", SaveBaseline: "outdir/../b.json"}}
	root := t.TempDir()
	if why := baselineStaleInert(f, root); why == "" {
		t.Fatal("same-file save+load must stand the stale gate down")
	}
	f = &Flags{Global: Global{Baseline: "b.json", SaveBaseline: "other.json"}}
	if why := baselineStaleInert(f, root); why != "" {
		t.Fatalf("different files must judge normally: %q", why)
	}
}

func TestDiffPathsPlainList(t *testing.T) {
	input := `
cmd/main.go
./internal/cli/cli.go
pkg/foo/bar.go
`
	paths := diffPaths(input)
	if len(paths) != 3 {
		t.Fatalf("diffPaths plain list len = %d, want 3: %v", len(paths), paths)
	}
	if !paths["cmd/main.go"] || !paths["internal/cli/cli.go"] || !paths["pkg/foo/bar.go"] {
		t.Errorf("missing expected paths: %v", paths)
	}
}

func TestDiffPathsUnifiedDiff(t *testing.T) {
	diff := `diff --git a/pkg/a.go b/pkg/a.go
index 1234567..89abcdef 100644
--- a/pkg/a.go
+++ b/pkg/a.go
@@ -10,6 +10,7 @@
 func A() {
+    // added line
 }
diff --git a/pkg/b.go b/pkg/b.go
new file mode 100644
--- /dev/null
+++ b/pkg/b.go
@@ -0,0 +1,5 @@
+package pkg
`
	paths := diffPaths(diff)
	if len(paths) != 2 {
		t.Fatalf("diffPaths unified diff len = %d, want 2: %v", len(paths), paths)
	}
	if !paths["pkg/a.go"] || !paths["pkg/b.go"] {
		t.Errorf("missing expected diff paths: %v", paths)
	}
}

func TestCompactDupes(t *testing.T) {
	doc := report.NewDoc("dupes")
	doc.Findings = []*report.Finding{
		{
			Kind: "clone-group",
			Path: "pkg/a.go",
			Line: 10,
			Col:  1,
			Extra: map[string]any{
				"instances": 3,
				"tokens":    45,
			},
		},
	}
	out := doc.Compact()
	want := "clone-group:pkg/a.go:10:1 (3 instances, 45 tokens)\n"
	if out != want {
		t.Errorf("Compact() = %q, want %q", out, want)
	}
}

func TestReportDocMethods(t *testing.T) {
	errJSON := report.ErrorJSON("E_TEST", "test error")
	if !strings.Contains(errJSON, "E_TEST") {
		t.Errorf("ErrorJSON missing code: %s", errJSON)
	}

	doc := report.NewDoc("dead-code")
	doc.Findings = []*report.Finding{
		{
			Kind:     "unused-export",
			Path:     "pkg/a.go",
			Line:     10,
			Severity: config.Error,
		},
		{
			Kind:     "unused-export",
			Path:     "pkg/b.go",
			Line:     20,
			Severity: config.Warn,
		},
	}
	if doc.ErrorCount() != 1 {
		t.Errorf("ErrorCount = %d, want 1", doc.ErrorCount())
	}
	sections := doc.BySection()
	if len(sections) == 0 {
		t.Errorf("BySection returned empty map")
	}
}

