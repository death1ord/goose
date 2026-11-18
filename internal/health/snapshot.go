package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"goose/internal/version"
)

// SnapshotSchemaVersion is the on-disk format version of a vital signs
// snapshot. It is independent of the report schema versions.
const SnapshotSchemaVersion = version.SnapshotSchemaVersion

// ScoreFormulaVersion identifies the health score formula.
const ScoreFormulaVersion = version.ScoreFormulaVersion

// DefaultSnapshotDir is the project-relative directory that --save-snapshot
// writes to and --trend reads from when no path is given.
const DefaultSnapshotDir = ".goose/snapshots"

// SnapshotCounts are the raw counts behind the vital signs, stored so a
// trend can explain a percentage move as numerator or denominator drift.
type SnapshotCounts struct {
	TotalFiles     int `json:"total_files"`
	TotalFunctions int `json:"total_functions"`
	AboveThreshold int `json:"functions_above_threshold"`
	FilesScored    int `json:"files_scored"`
	HotspotFiles   int `json:"hotspot_files"`
}

// GroupSnapshot is one bucket of a grouped run's snapshot.
type GroupSnapshot struct {
	Key                 string         `json:"key"`
	VitalSigns          VitalSigns     `json:"vital_signs"`
	Counts              SnapshotCounts `json:"counts"`
	Score               *float64       `json:"score,omitempty"`
	Grade               string         `json:"grade,omitempty"`
	ScoreFormulaVersion int            `json:"score_formula_version,omitempty"`
}

// SnapshotGrouping carries the --group-by partition of a snapshot.
type SnapshotGrouping struct {
	GroupedBy string          `json:"grouped_by"`
	Groups    []GroupSnapshot `json:"groups"`
}

// Snapshot is a point-in-time vital signs record persisted by
// --save-snapshot and compared by --trend/--trend-from.
type Snapshot struct {
	SnapshotSchemaVersion int               `json:"snapshot_schema_version"`
	Version               string            `json:"version"`
	Timestamp             string            `json:"timestamp"`
	GitSHA                string            `json:"git_sha,omitempty"`
	GitBranch             string            `json:"git_branch,omitempty"`
	ShallowClone          bool              `json:"shallow_clone"`
	VitalSigns            VitalSigns        `json:"vital_signs"`
	Counts                SnapshotCounts    `json:"counts"`
	Score                 *float64          `json:"score,omitempty"`
	Grade                 string            `json:"grade,omitempty"`
	ScoreFormulaVersion   int               `json:"score_formula_version,omitempty"`
	CoverageModel         string            `json:"coverage_model,omitempty"`
	Groups                *SnapshotGrouping `json:"groups,omitempty"`
}

// BuildSnapshot freezes one run's result into a snapshot record.
func BuildSnapshot(res *Result, toolVersion string, sha, branch string, shallow bool) *Snapshot {
	s := &Snapshot{
		SnapshotSchemaVersion: SnapshotSchemaVersion,
		Version:               toolVersion,
		Timestamp:             time.Now().UTC().Format(time.RFC3339),
		GitSHA:                sha,
		GitBranch:             branch,
		ShallowClone:          shallow,
		VitalSigns:            res.Vital,
		Counts: SnapshotCounts{
			TotalFiles:     res.FilesAnalyzed,
			TotalFunctions: res.FuncsAnalyzed,
			AboveThreshold: res.AboveCeiling,
			FilesScored:    res.FilesScored,
			HotspotFiles:   len(res.Hotspots),
		},
		CoverageModel: res.Model,
	}
	if res.Score.FormulaVersion != 0 {
		score := res.Score.Score
		s.Score = &score
		s.Grade = res.Score.Grade
		s.ScoreFormulaVersion = res.Score.FormulaVersion
	}
	return s
}

// GroupSnapshotOf builds the per-bucket record of a grouped run.
func GroupSnapshotOf(key string, body *Result) GroupSnapshot {
	g := GroupSnapshot{Key: key, VitalSigns: body.Vital, Counts: SnapshotCounts{
		TotalFiles:     body.FilesAnalyzed,
		TotalFunctions: body.FuncsAnalyzed,
		AboveThreshold: body.AboveCeiling,
		FilesScored:    body.FilesScored,
		HotspotFiles:   len(body.Hotspots),
	}}
	if body.Score.FormulaVersion != 0 {
		score := body.Score.Score
		g.Score = &score
		g.Grade = body.Score.Grade
		g.ScoreFormulaVersion = body.Score.FormulaVersion
	}
	return g
}

// SaveSnapshot writes the record. explicit="" uses
// <root>/.goose/snapshots/<timestamp>.json; a named path is used verbatim
// (relative to the working directory, like fallow) with directories created.
// Returns the path written.
func SaveSnapshot(s *Snapshot, root, explicit string) (string, error) {
	path := explicit
	if path == "" {
		name := strings.ReplaceAll(s.Timestamp, ":", "-")
		name = strings.TrimSuffix(name, "Z") + "Z.json"
		path = filepath.Join(root, DefaultSnapshotDir, name)
	} else {
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("cannot create the snapshot directory %s: %v", dir, err)
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return "", fmt.Errorf("cannot write the snapshot %s: %v", path, err)
	}
	return path, nil
}

// TrendBaseline is the snapshot the trend compares against plus how many
// snapshots were available.
type TrendBaseline struct {
	Snapshot        *Snapshot
	SnapshotsLoaded int
	// Unreadable lists default-directory files skipped as corrupt,
	// project-relative.
	Unreadable []string
	// AbsentDir reports the snapshot directory itself was missing.
	AbsentDir bool
}

// LoadTrendBaseline resolves the trend baseline: an explicit file (named by
// --trend-from, so a missing or invalid file is an error) or the newest valid
// snapshot of the default directory. Corrupt files in the directory are
// skipped and recorded, matching fallow.
func LoadTrendBaseline(root, explicit string) (*TrendBaseline, error) {
	if explicit != "" {
		path := explicit
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read --trend-from snapshot %s: %v", explicit, err)
		}
		s, perr := parseSnapshot(data)
		if perr != nil {
			return nil, fmt.Errorf("--trend-from file %s is not a goose health snapshot: %v", explicit, perr)
		}
		return &TrendBaseline{Snapshot: s, SnapshotsLoaded: 1}, nil
	}
	dir := filepath.Join(root, DefaultSnapshotDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return &TrendBaseline{AbsentDir: true}, nil
	}
	var found []*Snapshot
	var unreadable []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			unreadable = append(unreadable, filepath.ToSlash(filepath.Join(DefaultSnapshotDir, e.Name())))
			continue
		}
		s, perr := parseSnapshot(data)
		if perr != nil {
			unreadable = append(unreadable, filepath.ToSlash(filepath.Join(DefaultSnapshotDir, e.Name())))
			continue
		}
		found = append(found, s)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Timestamp < found[j].Timestamp })
	if len(found) == 0 {
		return &TrendBaseline{Unreadable: unreadable}, nil
	}
	return &TrendBaseline{Snapshot: found[len(found)-1], SnapshotsLoaded: len(found), Unreadable: unreadable}, nil
}

func parseSnapshot(data []byte) (*Snapshot, error) {
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	if _, ok := probe["snapshot_schema_version"]; !ok {
		return nil, errors.New("missing snapshot_schema_version")
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ---------------------------------------------------------------------------
// Trend computation (fallow health_trends contract)
// ---------------------------------------------------------------------------

// Trend tolerance under which a delta is reported stable.
const trendTolerance = 0.5

// TrendMetric is one metric's movement between snapshots.
type TrendMetric struct {
	Name     string  `json:"name"`
	Label    string  `json:"label"`
	Previous float64 `json:"previous"`
	Current  float64 `json:"current"`
	Delta    float64 `json:"delta"`
	// Direction is improving | declining | stable.
	Direction string `json:"direction"`
	Unit      string `json:"unit"`
}

// TrendPoint names the snapshot compared against.
type TrendPoint struct {
	Timestamp           string   `json:"timestamp"`
	GitSHA              string   `json:"git_sha,omitempty"`
	Score               *float64 `json:"score,omitempty"`
	Grade               string   `json:"grade,omitempty"`
	ScoreFormulaVersion int      `json:"score_formula_version,omitempty"`
	CoverageModel       string   `json:"coverage_model,omitempty"`
}

// Trend is the health_trend object of the report.
type Trend struct {
	ComparedTo       TrendPoint    `json:"compared_to"`
	Metrics          []TrendMetric `json:"metrics"`
	SnapshotsLoaded  int           `json:"snapshots_loaded"`
	OverallDirection string        `json:"overall_direction"`
}

// ScoreComparable reports whether the trend's score metric was emitted. When
// false with a stored previous score, the formulas did not match and the
// delta was dropped.
func (t *Trend) ScoreComparable() bool {
	if t == nil {
		return false
	}
	for _, m := range t.Metrics {
		if m.Name == "score" {
			return true
		}
	}
	return false
}


// BuildTrend compares the current vital signs (and optionally score) against
// a baseline snapshot, following fallow's health_trend: per-metric deltas,
// direction with tolerance, stored score never re-derived, and a score delta
// only when both scores exist under the same formula version.
func BuildTrend(prev *Snapshot, snapshotsLoaded int, res *Result) *Trend {
	point := TrendPoint{
		Timestamp:           prev.Timestamp,
		GitSHA:              prev.GitSHA,
		Score:               prev.Score,
		Grade:               prev.Grade,
		ScoreFormulaVersion: prev.ScoreFormulaVersion,
		CoverageModel:       prev.CoverageModel,
	}
	cur := res.Vital
	t := &Trend{ComparedTo: point, SnapshotsLoaded: snapshotsLoaded}
	add := func(name, label string, previous, current float64, unit string, higherIsBetter bool) {
		t.Metrics = append(t.Metrics, makeTrendMetric(name, label, previous, current, unit, higherIsBetter))
	}
	// Score first, only when stored and current scores share one formula.
	if prev.Score != nil && res.Score.FormulaVersion != 0 &&
		prev.ScoreFormulaVersion == res.Score.FormulaVersion {
		add("score", "Health Score", *prev.Score, res.Score.Score, "", true)
	}
	add("dead_file_pct", "Dead Files", prev.VitalSigns.DeadFilePercent, cur.DeadFilePercent, "%", false)
	add("dead_export_pct", "Dead Exports", prev.VitalSigns.DeadExportPercent, cur.DeadExportPercent, "%", false)
	add("critical_complexity_pct", "Critical Complexity", prev.VitalSigns.CriticalComplexityPct, cur.CriticalComplexityPct, "%", false)
	add("hotspot_count", "Hotspots", float64(prev.VitalSigns.HotspotCount), float64(cur.HotspotCount), "", false)
	if prev.Counts.TotalFunctions > 0 && res.FuncsAnalyzed > 0 {
		add("functions_above_threshold", "Above Threshold", float64(prev.Counts.AboveThreshold), float64(res.AboveCeiling), "", false)
	}
	if prev.VitalSigns.AvgCyclomatic > 0 && cur.AvgCyclomatic > 0 {
		add("avg_cyclomatic", "Avg Cyclomatic", prev.VitalSigns.AvgCyclomatic, cur.AvgCyclomatic, "", false)
	}
	if prev.VitalSigns.MaintainabilityAvg > 0 && cur.MaintainabilityAvg > 0 {
		add("maintainability_avg", "Maintainability", prev.VitalSigns.MaintainabilityAvg, cur.MaintainabilityAvg, "", true)
	}
	t.OverallDirection = overallTrendDirection(t.Metrics)
	return t
}

func makeTrendMetric(name, label string, previous, current float64, unit string, higherIsBetter bool) TrendMetric {
	round := func(v float64) float64 { return math.Round(v*10) / 10 }
	delta := round(current - previous)
	direction := "stable"
	if math.Abs(delta) >= trendTolerance {
		if (higherIsBetter && delta > 0) || (!higherIsBetter && delta < 0) {
			direction = "improving"
		} else {
			direction = "declining"
		}
	}
	return TrendMetric{
		Name: name, Label: label,
		Previous: round(previous), Current: round(current),
		Delta: delta, Direction: direction, Unit: unit,
	}
}

func overallTrendDirection(metrics []TrendMetric) string {
	improving, declining := 0, 0
	for _, m := range metrics {
		switch m.Direction {
		case "improving":
			improving++
		case "declining":
			declining++
		}
	}
	switch {
	case improving > declining:
		return "improving"
	case declining > improving:
		return "declining"
	}
	return "stable"
}

// BuildGroupTrend compares one group's current result against the same
// group's stored record in the baseline.
func BuildGroupTrend(base *Snapshot, loaded int, key string, body *Result) *Trend {
	if base.Groups == nil {
		return nil
	}
	for i := range base.Groups.Groups {
		if base.Groups.Groups[i].Key != key {
			continue
		}
		g := base.Groups.Groups[i]
		synthetic := &Snapshot{
			Timestamp:           base.Timestamp,
			GitSHA:              base.GitSHA,
			VitalSigns:          g.VitalSigns,
			Counts:              g.Counts,
			Score:               g.Score,
			Grade:               g.Grade,
			ScoreFormulaVersion: g.ScoreFormulaVersion,
			CoverageModel:       base.CoverageModel,
		}
		return BuildTrend(synthetic, loaded, body)
	}
	return nil
}
