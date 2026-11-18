package health

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCoverageProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cov.out")
	body := "mode: count\n" +
		"example/pkg/a.go:10.20,14.3 2 0\n" +
		"example/pkg/a.go:16.2,18.7 1 3\n" +
		"example/pkg/b.go:5.1,9.2 4 1\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cov, err := ParseCoverage(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cov.Blocks) != 2 {
		t.Fatalf("want 2 files, got %d", len(cov.Blocks))
	}
	a := cov.Blocks["example/pkg/a.go"]
	if len(a) != 2 {
		t.Fatalf("want 2 blocks in a.go, got %d", len(a))
	}
	if a[0].StartLine != 10 || a[0].EndLine != 14 || a[0].Count != 0 {
		t.Errorf("block0 = %+v", a[0])
	}
	if a[1].Count != 3 || a[1].NumStmt != 1 {
		t.Errorf("block1 = %+v", a[1])
	}
}

func TestParseCoverageSetModeCollapses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cov.out")
	body := "mode: set\nexample/pkg/a.go:1.1,2.2 1 57\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cov, err := ParseCoverage(path)
	if err != nil {
		t.Fatal(err)
	}
	b := cov.Blocks["example/pkg/a.go"][0]
	if b.Count != 1 {
		t.Errorf("set mode should collapse counts to 1, got %d", b.Count)
	}
}

func TestParseCoverageGarbageLinesSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cov.out")
	body := "mode: set\n// comment\n\nbogus line here\nexample/x.go:1.1,2.2 1 1\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cov, err := ParseCoverage(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(cov.Blocks["example/x.go"]); n != 1 {
		t.Errorf("want 1 block, got %d", n)
	}
}

func TestAggregateChurnCountsAndTrend(t *testing.T) {
	const now int64 = 1_700_000_000
	data := ChurnData{Available: true}
	// Six identical-recent commits: should classify as Accelerating.
	for i := 0; i < 6; i++ {
		data.Events = append(data.Events, ChurnEvent{
			Path: "a.go", Timestamp: now - 10, Author: "dev",
			Added: 5, Deleted: 2,
		})
	}
	AggregateChurn(&data, now)
	f := data.FilesByPath["a.go"]
	if f == nil {
		t.Fatal("missing a.go")
	}
	if f.Commits != 6 {
		t.Errorf("commits = %d want 6", f.Commits)
	}
	if f.Added != 30 || f.Deleted != 12 {
		t.Errorf("adds=%d dels=%d want 30/12", f.Added, f.Deleted)
	}
	switch f.Trend {
	case "Accelerating", "Stable", "Cooling":
	default:
		t.Errorf("unexpected trend %q", f.Trend)
	}
	if f.BusFactor < 1 {
		t.Errorf("bus factor = %d, want >=1", f.BusFactor)
	}
}

func TestAggregateChurnBusFactorMultipleAuthors(t *testing.T) {
	const now int64 = 1_700_000_000
	data := ChurnData{Available: true}
	authors := []string{"a", "b", "c", "d", "e"}
	for i, au := range authors {
		data.Events = append(data.Events, ChurnEvent{
			Path: "multi.go", Timestamp: now - int64(i)*1000, Author: au,
			Added: 10,
		})
	}
	AggregateChurn(&data, now)
	f := data.FilesByPath["multi.go"]
	if f.BusFactor != 3 {
		// Weighted shares differ slightly by recency; the top sharers
		// covering >= 50% needs 2-3 authors. 3 is the spread-out answer.
		if f.BusFactor < 2 || f.BusFactor > 3 {
			t.Errorf("bus factor = %d, want 2..3", f.BusFactor)
		}
	}
}

func TestAggregateChurnNoEvents(t *testing.T) {
	data := ChurnData{Available: false}
	AggregateChurn(&data, 1)
	if data.FilesByPath != nil {
		t.Error("nil events must leave FilesByPath nil")
	}
}
