package report

import (
	"strings"
	"testing"

	"goose/internal/config"
)

func finding(kind string, sev config.Severity) *Finding {
	return &Finding{Kind: kind, Rule: "x", Path: "a.go", Line: 1, Severity: sev}
}

func TestExitCodeHumanErrorFails(t *testing.T) {
	d := NewDoc("dead-code")
	d.Findings = []*Finding{finding("unused-export", config.Error)}
	if got := d.ExitCode(false, false); got != 1 {
		t.Errorf("human run with an error finding should exit 1, got %d", got)
	}
}

func TestExitCodeMachineCleanByDefault(t *testing.T) {
	d := NewDoc("dead-code")
	d.Findings = []*Finding{finding("unused-export", config.Error)}
	// A machine format exits 0 on findings unless --fail-on-issues.
	if got := d.ExitCode(false, true); got != 0 {
		t.Errorf("machine format without fail-on-issues should exit 0, got %d", got)
	}
}

func TestExitCodeFailOnIssuesWarns(t *testing.T) {
	d := NewDoc("dead-code")
	d.Findings = []*Finding{finding("unused-export", config.Warn)}
	if got := d.ExitCode(true, true); got != 1 {
		t.Errorf("--fail-on-issues with warn should exit 1, got %d", got)
	}
	if got := d.ExitCode(false, true); got != 0 {
		t.Errorf("no flag with warn should exit 0, got %d", got)
	}
}

func TestExitCodeEnforcedGateAlwaysFails(t *testing.T) {
	d := NewDoc("dupes")
	d.Gates["duplication-threshold"] = &Gate{Status: "failed", Enforced: true}
	if got := d.ExitCode(false, true); got != 1 {
		t.Errorf("enforced failed gate should exit 1 even in machine mode, got %d", got)
	}
}

func TestExitCodeOffSeverityIgnored(t *testing.T) {
	d := NewDoc("dead-code")
	d.Findings = []*Finding{finding("x", config.Off)}
	if got := d.ExitCode(true, false); got != 0 {
		t.Errorf("off-severity findings should be ignored, got %d", got)
	}
}

func TestFingerprintStableAndLineFree(t *testing.T) {
	a := Fingerprint("unused-export", "a.go", "Foo")
	// Line numbers are never part of the id: only kind, path, identity.
	b := Fingerprint("unused-export", "a.go", "Foo")
	if a != b {
		t.Error("fingerprint must be stable")
	}
	if c := Fingerprint("unused-export", "a.go", "Bar"); c == a {
		t.Error("different symbol must change the id")
	}
	if !strings.HasPrefix(a, "dc1:unused-export:") {
		t.Errorf("id shape wrong: %s", a)
	}
}

func TestPluralAndSingular(t *testing.T) {
	cases := map[string]string{
		"unused-export":       "unused-exports",
		"package-cycle":       "package-cycles",
		"circular-dependency": "circular-dependencies",
		"boundary-violation":  "boundary-violations",
	}
	for in, want := range cases {
		if got := Plural(in); got != want {
			t.Errorf("Plural(%q)=%q want %q", in, got, want)
		}
	}
	if got := Singular("circular-dependencies"); got != "circular-dependency" {
		t.Errorf("Singular = %q", got)
	}
	if got := Singular("unused-exports"); got != "unused-export" {
		t.Errorf("Singular exports = %q", got)
	}
}

func TestRuleForKind(t *testing.T) {
	if got := RuleForKind("unused-export"); got != "unused-exports" {
		t.Errorf("RuleForKind unused-export = %q", got)
	}
	if got := RuleForKind("boundary-violation"); got != "boundary-violation" {
		t.Errorf("RuleForKind boundary-violation = %q", got)
	}
	if got := RuleForKind("complexity-finding"); got != "complexity-cyclomatic" {
		t.Errorf("RuleForKind complexity-finding = %q", got)
	}
}
