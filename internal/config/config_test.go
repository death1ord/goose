package config

import (
	"os"
	"testing"
)

func TestRuleSeverityDefaults(t *testing.T) {
	c := Defaults()
	c.applyDefaults()
	if got := c.RuleSeverity("unused-exports", ""); got != Error {
		t.Errorf("unused-exports default = %v, want error", got)
	}
	// duplicate-exports is intentionally off in Go.
	if got := c.RuleSeverity("duplicate-exports", ""); got != Off {
		t.Errorf("duplicate-exports default = %v, want off", got)
	}
	if got := c.RuleSeverity("stale-suppressions", ""); got != Warn {
		t.Errorf("stale-suppressions default = %v, want warn", got)
	}
	if got := c.RuleSeverity("not-a-real-rule", ""); got != Warn {
		t.Errorf("unknown rule default = %v, want warn", got)
	}
}

func TestRuleSeverityAlias(t *testing.T) {
	c := Defaults()
	c.Rules = map[string]string{"unused-export": "warn"} // singular alias
	if got := c.RuleSeverity("unused-exports", ""); got != Warn {
		t.Errorf("alias-configured severity = %v, want warn", got)
	}
}

func TestRuleSeverityOverrideByPath(t *testing.T) {
	c := Defaults()
	c.Overrides = []Override{{
		Files: []string{"internal/generated/**"},
		Rules: map[string]string{"unused-exports": "off"},
	}}
	if got := c.RuleSeverity("unused-exports", "internal/generated/x.go"); got != Off {
		t.Errorf("override severity = %v, want off", got)
	}
	if got := c.RuleSeverity("unused-exports", "internal/cli/cli.go"); got != Error {
		t.Errorf("non-matching path = %v, want error", got)
	}
}

func TestRuleEnabled(t *testing.T) {
	c := Defaults()
	if !c.RuleEnabled("unused-files") {
		t.Error("unused-files should be enabled by default")
	}
	if c.RuleEnabled("duplicate-exports") {
		t.Error("duplicate-exports should be disabled by default")
	}
}

func TestProdFor(t *testing.T) {
	c := Defaults()
	if c.ProdFor("dead-code") {
		t.Error("no production set should yield prod")
	}
	c.Production = ProductionMode{Enabled: true}
	if !c.ProdFor("anything") {
		t.Error("global production should apply to every analysis")
	}
	c.Production = ProductionMode{PerKey: true, Health: true}
	if c.ProdFor("dead-code") {
		t.Error("per-key health should not enable dead-code")
	}
	if !c.ProdFor("health") {
		t.Error("per-key health should enable health")
	}
}

func TestExtendsParentChildThresholds(t *testing.T) {
	dir := t.TempDir()
	parentPath := dir + "/parent.json"
	childPath := dir + "/child.json"

	parentContent := `{
		"thresholds": {"maxCyclomatic": 42},
		"duplicates": {"minTokens": 100}
	}`
	childContent := `{
		"extends": "./parent.json",
		"thresholds": {"maxCognitive": 30}
	}`

	if err := os.WriteFile(parentPath, []byte(parentContent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(childPath, []byte(childContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, _, err := loadFile(childPath, LoadOptions{}, nil, 0)
	if err != nil {
		t.Fatalf("loadFile failed: %v", err)
	}
	if cfg.Thresholds.MaxCyclomatic != 42 {
		t.Errorf("cfg.Thresholds.MaxCyclomatic = %d, want 42", cfg.Thresholds.MaxCyclomatic)
	}
	if cfg.Thresholds.MaxCognitive != 30 {
		t.Errorf("cfg.Thresholds.MaxCognitive = %d, want 30", cfg.Thresholds.MaxCognitive)
	}
	if cfg.Duplicates.MinTokens != 100 {
		t.Errorf("cfg.Duplicates.MinTokens = %d, want 100", cfg.Duplicates.MinTokens)
	}
}

func TestExtendsMultipleParents(t *testing.T) {
	dir := t.TempDir()
	p1Path := dir + "/p1.json"
	p2Path := dir + "/p2.json"
	childPath := dir + "/child.json"

	p1Content := `{
		"thresholds": {"maxCyclomatic": 42, "maxCognitive": 20},
		"duplicates": {"minTokens": 100}
	}`
	p2Content := `{
		"thresholds": {"maxCognitive": 50},
		"duplicates": {"minTokens": 200, "minLines": 10}
	}`
	childContent := `{
		"extends": ["./p1.json", "./p2.json"],
		"thresholds": {"maxCognitive": 30}
	}`

	if err := os.WriteFile(p1Path, []byte(p1Content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2Path, []byte(p2Content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(childPath, []byte(childContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, _, err := loadFile(childPath, LoadOptions{}, nil, 0)
	if err != nil {
		t.Fatalf("loadFile failed: %v", err)
	}
	if cfg.Thresholds.MaxCyclomatic != 42 {
		t.Errorf("cfg.Thresholds.MaxCyclomatic = %d, want 42 (from p1)", cfg.Thresholds.MaxCyclomatic)
	}
	if cfg.Thresholds.MaxCognitive != 30 {
		t.Errorf("cfg.Thresholds.MaxCognitive = %d, want 30 (child overrides p2 and p1)", cfg.Thresholds.MaxCognitive)
	}
	if cfg.Duplicates.MinTokens != 200 {
		t.Errorf("cfg.Duplicates.MinTokens = %d, want 200 (p2 overrides p1)", cfg.Duplicates.MinTokens)
	}
	if cfg.Duplicates.MinLines != 10 {
		t.Errorf("cfg.Duplicates.MinLines = %d, want 10 (from p2)", cfg.Duplicates.MinLines)
	}
}

func TestRuleSeverityOverrideWildcard(t *testing.T) {
	c := Defaults()
	c.Overrides = []Override{{
		Files: []string{"internal/generated/**"},
		Rules: map[string]string{"*": "off"},
	}}
	if got := c.RuleSeverity("unused-exports", "internal/generated/x.go"); got != Off {
		t.Errorf("override severity for wildcard = %v, want off", got)
	}
	if got := c.RuleSeverity("unused-exports", "internal/cli/cli.go"); got != Error {
		t.Errorf("non-matching path severity = %v, want error", got)
	}
}

func TestMerge(t *testing.T) {
	p := Defaults()
	p.Duplicates.MinTokens = 100
	c := Defaults()
	c.Duplicates.MinTokens = 200
	merged := Merge(p, c)
	if merged.Duplicates.MinTokens != 200 {
		t.Errorf("Merge failed: got %d, want 200", merged.Duplicates.MinTokens)
	}
	if Merge(nil, c) != c {
		t.Errorf("Merge nil parent failed")
	}
	if Merge(p, nil) != p {
		t.Errorf("Merge nil child failed")
	}
}

func TestRuleNames(t *testing.T) {
	names := RuleNames()
	if len(names) == 0 {
		t.Fatalf("RuleNames returned empty slice")
	}
}

