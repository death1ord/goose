package health

import (
	"testing"
)

func TestCoverageGapSummaryPercent(t *testing.T) {
	// Empty scope reports full coverage, mirroring fallow.
	s := buildGapSummary(0, 0, 0, 0)
	if s.FileCoveragePct != 100.0 {
		t.Fatalf("empty scope: %v", s.FileCoveragePct)
	}
	s = buildGapSummary(3, 1, 2, 5)
	if s.FileCoveragePct != 33.3 {
		t.Fatalf("one third: %v", s.FileCoveragePct)
	}
}
