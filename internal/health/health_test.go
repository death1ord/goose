package health

import (
	"math"
	"testing"

	"goose/internal/config"
	"goose/internal/facts"
)

func TestCrapFormula(t *testing.T) {
	// Crap(cc, cov) = cc^2 * (1-cov)^3 + cc, exactly as documented.
	cases := []struct {
		cc   int
		cov  float64
		want float64
	}{
		{1, 1, 1},
		{1, 0, 2},
		{5, 1, 5},
		{5, 0, 30},
		{0, 0.5, 0},
		{10, 0.5, 22.5},
	}
	for _, c := range cases {
		if got := Crap(c.cc, c.cov); math.Abs(got-c.want) > 0.06 {
			t.Errorf("Crap(%d,%v)=%v want %v", c.cc, c.cov, got, c.want)
		}
	}
}

func TestCrapBoundsCoverage(t *testing.T) {
	// Coverage outside [0,1] is clamped, never producing a negative penalty.
	if lo := Crap(10, -1); lo <= 0 {
		t.Errorf("Crap(10,-1)=%v, want clamped positive", lo)
	}
	if hi := Crap(10, 2); hi > 10 || hi < 10 {
		t.Errorf("Crap(10,2)=%v, want 10 (fully covered)", hi)
	}
	// Uncovered cc grows with cc^2.
	if a, b := Crap(4, 0), Crap(2, 0); a <= b {
		t.Errorf("expected higher cc to have higher CRAP: cc4=%v cc2=%v", a, b)
	}
}

func TestGradeOf(t *testing.T) {
	cases := map[float64]string{
		95: "A", 90: "A", 85: "B", 80: "B", 75: "C", 70: "C",
		65: "D", 60: "D", 59: "F", 0: "F", 100: "A",
	}
	for score, want := range cases {
		if got := gradeOf(score); got != want {
			t.Errorf("gradeOf(%v)=%v want %v", score, got, want)
		}
	}
}

func TestClampPct(t *testing.T) {
	if clampPct(-5) != 0 {
		t.Errorf("clampPct(-5) want 0")
	}
	if clampPct(150) != 100 {
		t.Errorf("clampPct(150) want 100")
	}
	if clampPct(42) != 42 {
		t.Errorf("clampPct(42) want 42")
	}
}

func TestComputeVitalsDeadFiles(t *testing.T) {
	proj := &facts.Project{
		Files: map[string]*facts.FileFacts{
			"/repo/cmd/main.go": {
				Path:     "/repo/cmd/main.go",
				Rel:      "cmd/main.go",
				PkgName:  "main",
				PkgPath:  "example.com/cmd",
				Entities: []facts.Key{"cmd.main"},
			},
			"/repo/pkg/init.go": {
				Path:     "/repo/pkg/init.go",
				Rel:      "pkg/init.go",
				PkgName:  "pkg",
				PkgPath:  "example.com/pkg",
				Entities: []facts.Key{"pkg.init"},
			},
			"/repo/pkg/used.go": {
				Path:     "/repo/pkg/used.go",
				Rel:      "pkg/used.go",
				PkgName:  "pkg",
				PkgPath:  "example.com/pkg",
				Entities: []facts.Key{"pkg.Foo"},
			},
			"/repo/pkg/doc.go": {
				Path:     "/repo/pkg/doc.go",
				Rel:      "pkg/doc.go",
				PkgName:  "pkg",
				PkgPath:  "example.com/pkg",
				Entities: nil,
			},
			"/repo/pkg/dead.go": {
				Path:     "/repo/pkg/dead.go",
				Rel:      "pkg/dead.go",
				PkgName:  "pkg",
				PkgPath:  "example.com/pkg",
				Entities: []facts.Key{"pkg.Dead"},
			},
		},
		Entities: map[facts.Key]*facts.Entity{
			"cmd.main": {
				Key:  "cmd.main",
				Func: &facts.FuncInfo{IsMain: true},
			},
			"pkg.init": {
				Key:  "pkg.init",
				Func: &facts.FuncInfo{IsInit: true},
			},
			"pkg.Foo": {
				Key:      "pkg.Foo",
				Exported: true,
			},
			"pkg.Dead": {
				Key:      "pkg.Dead",
				Exported: true,
			},
		},
		Uses: map[facts.Key][]facts.UseSite{
			"pkg.Foo": {
				{Key: "pkg.Foo", PkgPath: "example.com/pkg"},
			},
		},
	}

	in := Input{
		Facts: proj,
		Cfg:   config.Defaults(),
	}
	r := &Result{}
	r.computeVitals(in, r)

	if r.Vital.DeadFilePercent != 20.0 {
		t.Errorf("DeadFilePercent = %v, want 20.0", r.Vital.DeadFilePercent)
	}
}

func TestTrendScoreComparable(t *testing.T) {
	var tr *Trend
	if tr.ScoreComparable() {
		t.Errorf("nil trend should not be comparable")
	}
	tr = &Trend{
		Metrics: []TrendMetric{{Name: "score"}},
	}
	if !tr.ScoreComparable() {
		t.Errorf("trend with score metric should be comparable")
	}
	tr = &Trend{
		Metrics: []TrendMetric{{Name: "other"}},
	}
	if tr.ScoreComparable() {
		t.Errorf("trend without score metric should not be comparable")
	}
}

func TestCoverageMatchFilesAndFilePercent(t *testing.T) {
	cov := &Coverage{
		Blocks: map[string][]Block{
			"example.com/foo/bar.go": {
				{StartLine: 1, EndLine: 10, NumStmt: 5, Count: 1},
				{StartLine: 11, EndLine: 20, NumStmt: 5, Count: 0},
			},
		},
	}
	matched := cov.MatchFiles(func(key string) (string, bool) {
		if key == "example.com/foo/bar.go" {
			return "bar.go", true
		}
		return "", false
	})
	if matched == nil || len(matched.Blocks["bar.go"]) != 2 {
		t.Fatalf("MatchFiles failed: %v", matched)
	}
	pct := matched.FilePercent("bar.go")
	if pct == nil || *pct != 0.5 {
		t.Errorf("FilePercent want 0.5, got %v", pct)
	}
	var nilCov *Coverage
	if nilCov.MatchFiles(nil) != nil {
		t.Errorf("MatchFiles on nil coverage should return nil")
	}
	if nilCov.FilePercent("bar.go") != nil {
		t.Errorf("FilePercent on nil coverage should return nil")
	}
}

