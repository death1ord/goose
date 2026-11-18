package architecture

import (
	"testing"

	"goose/internal/config"
	"goose/internal/facts"
)

func TestClassifyFirstPatternWins(t *testing.T) {
	zones := []zone{
		{name: "domain", patterns: []string{"**/domain/**", "**/core/**"}},
		{name: "infra", patterns: []string{"**/storage/**"}},
	}
	if got := classify(zones, "internal/domain/user.go"); got != "domain" {
		t.Errorf("domain classify = %q", got)
	}
	if got := classify(zones, "internal/core/x.go"); got != "domain" {
		t.Errorf("core should join domain (pattern 2) = %q", got)
	}
	if got := classify(zones, "internal/storage/db.go"); got != "infra" {
		t.Errorf("storage classify = %q", got)
	}
	if got := classify(zones, "random/file.go"); got != "" {
		t.Errorf("unmatched should classify empty, got %q", got)
	}
}

func TestPresetZonesKnown(t *testing.T) {
	for _, p := range []string{"layered", "hexagonal", "feature-sliced", "bulletproof"} {
		zs, ok := presetZones(p)
		if !ok || len(zs) == 0 {
			t.Errorf("preset %q should resolve to zones", p)
		}
	}
	if _, ok := presetZones("nope"); ok {
		t.Error("unknown preset must not resolve")
	}
}

func allowedFor(t *testing.T, preset, from, to string) bool {
	t.Helper()
	a := &Analysis{Cfg: config.Defaults()}
	a.Cfg.Boundaries.Preset = preset
	rules := a.effectiveRules(nil)
	ok, _ := a.allowed(rules, from, to)
	return ok
}

func allowedUser(t *testing.T, rules []config.BoundaryRule, from, to string) bool {
	t.Helper()
	a := &Analysis{Cfg: config.Defaults()}
	ok, _ := a.allowed(rules, from, to)
	return ok
}

func TestAllowedMatrixDomainLeaf(t *testing.T) {
	// domain may import only domain in every preset's layered/hex shape.
	if allowedFor(t, "layered", "domain", "infrastructure") {
		t.Error("domain must not import infrastructure")
	}
	if allowedFor(t, "layered", "domain", "application") {
		t.Error("domain must not import application")
	}
	if !allowedFor(t, "layered", "infrastructure", "domain") {
		t.Error("infrastructure may import domain")
	}
}

func TestAllowedSameZoneAlwaysOK(t *testing.T) {
	if !allowedFor(t, "layered", "domain", "domain") {
		t.Error("self imports are always allowed")
	}
}

func TestAllowedNoRuleDefaultsOpen(t *testing.T) {
	// A from-zone with no rule at all is unconstrained.
	if !allowedUser(t, nil, "mystery", "whatever") {
		t.Error("a zone without a rule should allow everything")
	}
	// interfaces is the outermost layered zone and imports every other.
	if !allowedFor(t, "layered", "interfaces", "infrastructure") {
		t.Error("interfaces may import infrastructure")
	}
}

func TestUserRuleOverridesPreset(t *testing.T) {
	a := &Analysis{Cfg: config.Defaults()}
	a.Cfg.Boundaries.Preset = "layered"
	// Tighten: now the interfaces layer may not import infrastructure.
	a.Cfg.Boundaries.Rules = []config.BoundaryRule{
		{From: "interfaces", Allow: []string{"domain"}},
	}
	rules := a.effectiveRules(nil)
	ok, _ := a.allowed(rules, "interfaces", "infrastructure")
	if ok {
		t.Error("user rule should override preset and deny interfaces→infrastructure")
	}
	ok2, _ := a.allowed(rules, "interfaces", "domain")
	if !ok2 {
		t.Error("user rule allows interfaces→domain")
	}
}

func TestDeepImportDetection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules["deep-import"] = string(config.Warn)
	cfg.PublicPackages = []string{"testmod/pkg/api"}

	proj := &facts.Project{
		Module: facts.ModuleInfo{Path: "testmod"},
		Files: map[string]*facts.FileFacts{
			"/repo/main.go": {
				Path:    "/repo/main.go",
				Rel:     "main.go",
				PkgPath: "testmod",
				Imports: []facts.ImportInfo{
					{Path: "testmod/pkg/api", Line: 3},
					{Path: "testmod/pkg/api/internal_sub", Line: 4},
					{Path: "testmod/feature/sub/deep", Line: 5},
				},
			},
		},
	}
	a := &Analysis{Proj: proj, Cfg: cfg}
	res, err := a.Run(Options{Boundaries: true, SelectorsSet: true})
	if err != nil {
		t.Fatal(err)
	}
	gotSpecs := map[string]bool{}
	for _, f := range res.Findings {
		if f.Kind == "deep-import" {
			spec, _ := f.Extra["specifier"].(string)
			gotSpecs[spec] = true
		}
	}
	if gotSpecs["testmod/pkg/api"] {
		t.Errorf("root public package testmod/pkg/api should not be flagged as deep-import")
	}
	if !gotSpecs["testmod/pkg/api/internal_sub"] {
		t.Errorf("expected testmod/pkg/api/internal_sub to be flagged as deep-import")
	}
	if !gotSpecs["testmod/feature/sub/deep"] {
		t.Errorf("expected testmod/feature/sub/deep to be flagged as deep-import")
	}
}
