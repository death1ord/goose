package health

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func scoredResult(score float64, grade string) *Result {
	s := score
	r := &Result{
		FilesAnalyzed: 100,
		FuncsAnalyzed: 500,
		Vital: VitalSigns{
			DeadFilePercent:       5.0,
			DeadExportPercent:     8.0,
			AvgCyclomatic:         2.0,
			CriticalComplexityPct: 1.0,
			HotspotCount:          2,
			MaintainabilityAvg:    75.0,
		},
		Score: Score{FormulaVersion: 3, Score: score, Grade: grade},
		Model: "static_estimated",
	}
	_ = s
	return r
}

func TestSnapshotSaveLoadRoundTrip(t *testing.T) {
	root := t.TempDir()
	res := scoredResult(80.0, "B")
	snap := BuildSnapshot(res, "1.0.0", "abc1234", "main", false)
	path, err := SaveSnapshot(snap, root, "")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != filepath.Join(root, DefaultSnapshotDir) {
		t.Fatalf("snapshot written outside the default dir: %s", path)
	}
	bl, err := LoadTrendBaseline(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if bl.Snapshot == nil || bl.SnapshotsLoaded != 1 {
		t.Fatalf("baseline not loaded: %+v", bl)
	}
	if bl.Snapshot.ScoreFormulaVersion != 3 {
		t.Fatalf("formula version lost: %d", bl.Snapshot.ScoreFormulaVersion)
	}
}

func TestTrendScoreRequiresMatchingFormula(t *testing.T) {
	prev := BuildSnapshot(scoredResult(72.0, "B"), "1.0.0", "", "", false)
	cur := scoredResult(78.0, "B")
	tr := BuildTrend(prev, 1, cur)
	var hasScore bool
	for _, m := range tr.Metrics {
		if m.Name == "score" {
			hasScore = true
			if m.Delta != 6.0 || m.Direction != "improving" {
				t.Fatalf("score delta wrong: %+v", m)
			}
		}
	}
	if !hasScore {
		t.Fatal("matching formulas should emit a score delta")
	}
	// A mismatched stored formula drops only the score metric.
	prev.ScoreFormulaVersion = 2
	tr = BuildTrend(prev, 1, cur)
	hasRaw := false
	for _, m := range tr.Metrics {
		if m.Name == "score" {
			t.Fatal("mismatched formula must not emit a score delta")
		}
		if m.Name == "avg_cyclomatic" {
			hasRaw = true
		}
	}
	if !hasRaw {
		t.Fatal("raw metrics must still compare: avg_cyclomatic missing")
	}
}

func TestTrendDirectionAndTolerance(t *testing.T) {
	prev := BuildSnapshot(scoredResult(78.0, "B"), "1.0.0", "", "", false)
	cur := scoredResult(78.3, "B") // +0.3 < tolerance
	tr := BuildTrend(prev, 1, cur)
	for _, m := range tr.Metrics {
		if m.Name == "score" && m.Direction != "stable" {
			t.Fatalf("0.3 pts must stay within tolerance: %+v", m)
		}
	}
	// Declining: more dead files.
	prev2 := BuildSnapshot(scoredResult(78.0, "B"), "1.0.0", "", "", false)
	cur2 := scoredResult(70.0, "C")
	cur2.Vital.DeadFilePercent = 20.0
	tr = BuildTrend(prev2, 1, cur2)
	for _, m := range tr.Metrics {
		switch m.Name {
		case "dead_file_pct":
			if m.Direction != "declining" {
				t.Fatalf("dead files rising must decline: %+v", m)
			}
		case "score":
			if m.Direction != "declining" {
				t.Fatalf("score falling must decline: %+v", m)
			}
		}
	}
}

func TestTrendFromExplicitErrors(t *testing.T) {
	root := t.TempDir()
	if _, err := LoadTrendBaseline(root, "absent.json"); err == nil {
		t.Fatal("missing explicit snapshot must error")
	}
	bad := filepath.Join(root, "invalid.json")
	if err := os.WriteFile(bad, []byte(`{"not":"a snapshot"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrendBaseline(root, "invalid.json"); err == nil {
		t.Fatal("invalid snapshot content must error")
	}
}

func TestDefaultDirSkipsCorruptSnapshots(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, DefaultSnapshotDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	good := BuildSnapshot(scoredResult(81.0, "B"), "1.0.0", "", "", false)
	data, _ := json.Marshal(good)
	if err := os.WriteFile(filepath.Join(dir, "good.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	bl, err := LoadTrendBaseline(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if bl.Snapshot == nil || bl.SnapshotsLoaded != 1 {
		t.Fatalf("good snapshot must load: %+v", bl)
	}
	if len(bl.Unreadable) != 1 || bl.Unreadable[0] != filepath.ToSlash(filepath.Join(DefaultSnapshotDir, "broken.json")) {
		t.Fatalf("unreadable list wrong: %+v", bl.Unreadable)
	}
}

func TestGroupTrendComparesStoredGroup(t *testing.T) {
	base := BuildSnapshot(scoredResult(70.0, "B"), "1.0.0", "", "", false)
	groupScore := 80.0
	base.Groups = &SnapshotGrouping{GroupedBy: "directory", Groups: []GroupSnapshot{
		{Key: "src", VitalSigns: base.VitalSigns, Counts: base.Counts, Score: &groupScore, Grade: "B", ScoreFormulaVersion: 3},
	}}
	body := scoredResult(84.0, "B")
	tr := BuildGroupTrend(base, 1, "src", body)
	if tr == nil {
		t.Fatal("group trend missing")
	}
	var scoreMetric *TrendMetric
	for i := range tr.Metrics {
		if tr.Metrics[i].Name == "score" {
			scoreMetric = &tr.Metrics[i]
		}
	}
	if scoreMetric == nil || math.Abs(scoreMetric.Delta-4.0) > 0.001 || scoreMetric.Direction != "improving" {
		t.Fatalf("group score delta wrong: %+v", scoreMetric)
	}
	if BuildGroupTrend(base, 1, "other", body) != nil {
		t.Fatal("a group missing from the baseline must report no trend")
	}
}
