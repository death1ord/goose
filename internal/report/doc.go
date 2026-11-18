package report

import (
	"fmt"
	"strings"

	"goose/internal/config"
	"goose/internal/version"
)

// Diag is one workspace_diagnostics entry.
type Diag struct {
	Path     string         `json:"path"`
	Kind     string         `json:"kind"`
	Message  string         `json:"message,omitempty"`
	Pattern  string         `json:"pattern,omitempty"`
	Rule     string         `json:"rule,omitempty"`
	Flag     string         `json:"flag,omitempty"`
	Cause    string         `json:"cause,omitempty"`
	Reason   string         `json:"reason,omitempty"`
	Degrades bool           `json:"degrades_analysis,omitempty"`
	Count    int            `json:"count,omitempty"`
	Extra    map[string]any `json:"-"`
}

// MarshalJSON merges Extra.
func (d Diag) MarshalJSON() ([]byte, error) {
	m := map[string]any{"path": d.Path, "kind": d.Kind}
	str := map[string]string{"message": d.Message, "pattern": d.Pattern, "rule": d.Rule, "flag": d.Flag, "cause": d.Cause, "reason": d.Reason}
	for k, v := range str {
		if v != "" {
			m[k] = v
		}
	}
	if d.Degrades {
		m["degrades_analysis"] = true
	}
	if d.Count != 0 {
		m["count"] = d.Count
	}
	for k, v := range d.Extra {
		m[k] = v
	}
	return marshalMap(m)
}

// Gate is one gate_outcomes entry.
type Gate struct {
	Status    string     `json:"status"` // passed | failed
	Enforced  bool       `json:"enforced"`
	Observed  any        `json:"observed"`
	Threshold any        `json:"threshold"`
	Detail    string     `json:"detail,omitempty"`
	Files     []GateFile `json:"files,omitempty"`
}

// GateFile names one offending file in a gate outcome.
type GateFile struct {
	Path   string `json:"path"`
	Count  int    `json:"count"`
	Reason string `json:"reason,omitempty"`
}

// Request is one request_outcomes entry.
type Request struct {
	Status    string `json:"status"` // applied | not-applied
	Affects   string `json:"affects"`
	Requested string `json:"requested"`
	ScopeSize *int   `json:"scope_size,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Message   string `json:"message,omitempty"`
	Path      string `json:"path,omitempty"`
}

// NextStep is one next_steps entry.
type NextStep struct {
	Command     string `json:"command"`
	Description string `json:"description,omitempty"`
}

// Doc is one analysis result document. The JSON form is assembled from these
// fields; each format renders them its own way.
type Doc struct {
	Kind          string
	Envelope      map[string]any // extra root fields, kind-specific
	Findings      []*Finding
	Summary       map[string]any
	Diagnostics   []Diag
	Gates         map[string]*Gate
	Requests      map[string]*Request
	NextSteps     []NextStep
	CascadeHidden int
	ElapsedMS     int64
	// ScoreFields holds health/vital-score root fields when set.
	ScoreFields map[string]any
	// Lean trims JSON output like fallow --lean.
	Lean bool
}

// NewDoc returns an envelope with the standard root fields.
func NewDoc(kind string) *Doc {
	return &Doc{
		Kind: kind,
		Envelope: map[string]any{
			"kind":           kind,
			"schema_version": schemaVersionFor(kind),
			"version":        version.Version,
		},
		Gates:    map[string]*Gate{},
		Requests: map[string]*Request{},
	}
}

func schemaVersionFor(kind string) int {
	switch kind {
	case "health":
		return version.HealthSchemaVersion
	case "architecture":
		return version.ArchitectureSchemaVersion
	default:
		return version.SchemaVersion
	}
}

// ErrorDocument is the exit-2 error envelope.
type ErrorDocument struct {
	Kind     string `json:"kind"`
	Message  string `json:"message"`
	Code     string `json:"code,omitempty"`
	ExitCode int    `json:"exit_code"`
}

// ErrorJSON renders the JSON error document.
// ErrorJSONWith renders an error envelope with extra fields merged in.
func ErrorJSONWith(fields map[string]any) string {
	s, _ := JSONString(fields)
	return s
}

func ErrorJSON(code, message string) string {
	s, _ := JSONString(ErrorDocument{Kind: "error", Message: message, Code: code, ExitCode: 2})
	return s
}

// BySection groups findings by their JSON section key, sorted.
func (d *Doc) BySection() map[string][]*Finding {
	out := map[string][]*Finding{}
	for _, f := range d.Findings {
		if f.Hidden {
			continue
		}
		out[f.SectionName()] = append(out[f.SectionName()], f)
	}
	for k := range out {
		SortFindings(out[k])
	}
	return out
}

// Visible returns findings that survive cascade hiding.
func (d *Doc) Visible() []*Finding {
	var out []*Finding
	for _, f := range d.Findings {
		if !f.Hidden && f.Kind != "stale-suppression" || f.Kind == "stale-suppression" {
			out = append(out, f)
		}
	}
	return out
}

// TotalIssues counts visible findings.
func (d *Doc) TotalIssues() int { return len(d.Visible()) }

// HasErrorSeverity reports whether any visible finding has severity error.
func (d *Doc) HasErrorSeverity() bool {
	return d.ErrorCount() > 0
}

// WarnCount counts warn-severity findings.
func (d *Doc) WarnCount() int {
	n := 0
	for _, f := range d.Visible() {
		if f.Severity == config.Warn {
			n++
		}
	}
	return n
}

// ErrorCount counts error-severity findings.
func (d *Doc) ErrorCount() int {
	n := 0
	for _, f := range d.Visible() {
		if f.Severity == config.Error {
			n++
		}
	}
	return n
}

// ExitCode applies the documented gate rules: the caller passes whether
// error findings fail (machine formats exit 0 without --fail-on-issues on the
// bare and dead-code runs).
func (d *Doc) ExitCode(failOnIssues, machineFormat bool) int {
	if d.gateFailedLocked() {
		return 1
	}
	enforcedError := failOnIssues || !machineFormat
	if enforcedError && d.HasErrorSeverity() {
		return 1
	}
	if failOnIssues && d.WarnCount() > 0 && d.Kind != "audit" {
		return 1
	}
	return 0
}

func (d *Doc) gateFailedLocked() bool {
	for _, g := range d.Gates {
		if g.Enforced && g.Status == "failed" {
			return true
		}
	}
	return false
}

// FailedGateNames lists the gates that failed while enforced.
func (d *Doc) FailedGateNames() []string {
	var out []string
	for name, g := range d.Gates {
		if g.Enforced && g.Status == "failed" {
			out = append(out, name)
		}
	}
	stringsOut := out
	sortNames(stringsOut)
	return stringsOut
}

func sortNames(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// GateSummaryLine is the stderr line printed when a gate fails the run.
func (d *Doc) GateSummaryLine() string {
	names := d.FailedGateNames()
	if len(names) == 0 {
		return ""
	}
	for name, g := range d.Gates {
		if name == names[0] {
			return fmt.Sprintf("[X] Exit code 1: gate %s (%v at or above error) failed.", name, g.Observed)
		}
	}
	return ""
}

// humanCountLine renders the final summary line with the run mark.
func (d *Doc) Mark() string {
	if d.failingAny() {
		return "✗"
	}
	if d.TotalIssues() > 0 {
		return "⚠"
	}
	return "✓"
}

func (d *Doc) failingAny() bool {
	if d.gateFailedLocked() {
		return true
	}
	return d.HasErrorSeverity()
}

// SectionTitle maps a finding kind to its human section title.
func SectionTitle(kind string) string {
	switch kind {
	case "unused-file":
		return "Unused files"
	case "unused-export":
		return "Unused exports"
	case "unused-unexported":
		return "Unused unexported symbols"
	case "unused-type":
		return "Unused types"
	case "unused-field":
		return "Unused struct fields"
	case "unused-method":
		return "Unused methods"
	case "unused-constant":
		return "Unused constants"
	case "unused-variable":
		return "Unused variables"
	case "unused-dependency":
		return "Unused dependencies"
	case "unused-test-dependency":
		return "Unused test dependencies"
	case "unlisted-dependency":
		return "Unlisted dependencies"
	case "unresolved-import":
		return "Unresolved imports"
	case "duplicate-export":
		return "Duplicate exports"
	case "circular-dependency":
		return "Circular dependencies"
	case "package-cycle":
		return "Package cycles"
	case "boundary-violation":
		return "Boundary violations"
	case "policy-violation":
		return "Policy violations"
	case "stale-suppression":
		return "Stale suppressions"
	case "complexity-finding":
		return "High complexity functions"
	case "large-function":
		return "Large functions"
	case "large-file":
		return "Large files"
	case "clone-group":
		return "Duplicates"
	case "coverage-gap":
		return "Coverage gaps"
	case "feature-flag":
		return "Feature flags"
	case "stale-feature-flag":
		return "Stale feature flags"
	case "security-candidate":
		return "Security candidates"
	case "secret-in-code":
		return "Secrets in code"
	case "write-only-field":
		return "Write-only struct fields"
	case "write-only-variable":
		return "Write-only variables"
	case "can-be-unexported":
		return "Over-exported symbols"
	case "unused-interface-method":
		return "Unused interface methods"
	case "unused-parameter":
		return "Unused parameters"
	case "unused-receiver":
		return "Unused method receivers"
	case "struct-padding":
		return "Suboptimal struct padding"
	case "nil-error-interface":
		return "Typed-nil interface returns"
	case "context-leak":
		return "Context cancellation leaks"
	case "defer-in-loop":
		return "Defer statements inside loops"
	case "unclosed-body":
		return "Unclosed resources"
	case "copylocks":
		return "Locks passed by value"
	case "deep-import":
		return "Deep imports"
	case "diverged-clone-sibling":
		return "Diverged clone siblings"
	case "missing-suppression-reason":
		return "Suppressions without a reason"
	}
	title := strings.ReplaceAll(kind, "-", " ")
	return strings.ToUpper(title[:1]) + title[1:]
}

// SectionDescription is the Description: line in human output with --explain.
func SectionDescription(kind string) string {
	switch kind {
	case "unused-file":
		return "Packages not reachable from any entry point"
	case "unused-export":
		return "Exported symbols with no reference from another package"
	case "unused-unexported":
		return "Unexported symbols with no reference inside their package"
	case "unused-type":
		return "Declared types nothing references"
	case "unused-field":
		return "Struct fields never read or written"
	case "unused-method":
		return "Methods never called and not implied by a used interface"
	case "unused-dependency":
		return "Modules required in go.mod but never imported"
	case "unlisted-dependency":
		return "Imports that no go.mod require declares"
	case "unresolved-import":
		return "Import paths that go list cannot resolve"
	case "circular-dependency":
		return "Imports that form a cycle between files"
	case "package-cycle":
		return "Packages that import each other in a loop"
	case "boundary-violation":
		return "Imports that cross defined architecture zone boundaries"
	case "complexity-finding":
		return "Functions exceeding cyclomatic, cognitive, or CRAP thresholds"
	case "coverage-gap":
		return "Runtime files and exports that no test reaches"
	}
	return ""
}

// SuppressHint names the inline suppression comment for a finding kind.
func SuppressHint(kind string) string {
	return "// goose-ignore-next-line " + kind
}
