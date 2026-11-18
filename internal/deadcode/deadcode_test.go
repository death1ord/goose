package deadcode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"goose/internal/config"
	"goose/internal/facts"
	"goose/internal/graph"
	"goose/internal/loader"
	"goose/internal/report"
)

// writeModule lays down a small Go module for analyzer integration tests.
func writeModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module fixture\n\ngo 1.24\n",
		"main.go": `package main

import "fixture/lib"

func main() { lib.Run() }
`,
		"main_test.go": `package main

import "testing"

func TestMainProtected(t *testing.T) {}
`,
		"lib/used.go": `package lib

import (
	"encoding/json"

	"fixture/other"
)

type Config struct {
	Name    string ` + "`json:\"name\"`" + `
	Hidden  string
}

func (c Config) MarshalJSON() ([]byte, error) { return nil, nil }

func Run() {
	other.Helper()
	_, _ = json.Marshal(Config{})
}
`,
		"lib/deadcode.go": `package lib

// NeverUsed is exported and referenced nowhere.
func NeverUsed() int { return 0 }

var neverTouched = 5

type Ghost struct{ A int }
`,
		"other/helper.go": `package other

func Helper() int { return 1 }
`,
		"orphan/orphan.go": `package faraway

func Only() int { return 1 }
`,
	}
	for name, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runAnalysis(t *testing.T, dir string) (*report.Doc, *Analysis) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Root = dir
	ld, err := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	if err != nil {
		t.Fatal(err)
	}
	proj := facts.Build(ld)
	g := graph.Build(proj)
	a := &Analysis{Proj: proj, Graph: g, Cfg: cfg}
	res := Run(a)
	doc := report.NewDoc("dead-code")
	doc.Findings = res.Findings
	return doc, a
}

func kindsBySymbol(doc *report.Doc) map[string]string {
	out := map[string]string{}
	for _, f := range doc.Visible() {
		if sym, ok := f.Extra["symbol"].(string); ok {
			out[f.Path+":"+sym] = f.Kind
		}
	}
	return out
}

func TestEndToEndDeadCodeFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test needs the go command")
	}
	dir := writeModule(t)
	doc, _ := runAnalysis(t, dir)
	kinds := kindsBySymbol(doc)

	// The never-used export, var, and type are found.
	for _, want := range []struct{ path, sym, kind string }{
		{"lib/deadcode.go", "NeverUsed", "unused-export"},
		{"lib/deadcode.go", "neverTouched", "unused-variable"},
		{"lib/deadcode.go", "Ghost", "unused-type"},
	} {
		if got := kinds[want.path+":"+want.sym]; got != want.kind {
			t.Errorf("%s.%s = %q, want %q. All: %v", want.path, want.sym, got, want.kind, kinds)
		}
	}

	// The unreached package is an unused file.
	var orphanReported bool
	for _, f := range doc.Visible() {
		if f.Kind == "unused-file" && f.Path == "orphan/orphan.go" {
			orphanReported = true
		}
	}
	if !orphanReported {
		t.Error("orphan/orphan.go should be reported as an unused file")
	}

	// False-positive guards.
	for _, keep := range []string{
		"lib/used.go:Config",      // marshalled via json.Marshal
		"lib/used.go:Name",        // json tag credit (fields of reflected type)
		"lib/used.go:MarshalJSON", // stdlib interface satisfaction
		"lib/used.go:Run",         // entry-reachable
		"other/helper.go:Helper",  // used by lib
		"main.go:main",            // entry point
	} {
		if _, bad := kinds[keep]; bad {
			t.Errorf("false positive: %s reported as dead (%s)", keep, kinds[keep])
		}
	}
	t.Logf("total issues: %d", doc.TotalIssues())

	// Baseline round trip: everything current becomes exempt next run.
	data, _ := json.MarshalIndent(Baseline{Kind: "dead-code", Entries: map[string]int{}}, "", " ")
	_ = data
	blPath := filepath.Join(dir, "bl.json")
	if err := SaveBaseline(blPath, doc.Findings, "test"); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBaseline(blPath)
	if err != nil {
		t.Fatal(err)
	}
	kept, st := ApplyBaseline(doc.Findings, b)
	if len(kept) != 0 {
		t.Errorf("baseline should cover every current finding, %d remain", len(kept))
	}
	if st.MatchedEntries == 0 {
		t.Error("baseline should match entries")
	}
}

func TestUnusedFileSuppressedByGooseIgnoreFile(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test needs the go command")
	}
	dir := writeModule(t)
	// Add a file-level suppression to the orphan package.
	target := filepath.Join(dir, "orphan", "orphan.go")
	body, _ := os.ReadFile(target)
	os.WriteFile(target, []byte("// goose-ignore-file unused-file\n"+string(body)), 0o644)
	doc, _ := runAnalysis(t, dir)
	for _, f := range doc.Visible() {
		if f.Kind == "unused-file" && f.Path == "orphan/orphan.go" {
			t.Error("goose-ignore-file should suppress the unused-file finding")
		}
	}
	// Every suppression must be marked used: no stale-suppression findings
	// for it.
	for _, f := range doc.Visible() {
		if f.Kind == "stale-suppression" && f.Path == "orphan/orphan.go" {
			t.Error("the used suppression must not be stale")
		}
	}
}

func TestDeprecatedExportsInUse(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test needs the go command")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n",
		"main.go": `package main

import "testmod/pkg"

func main() {
	pkg.OldFunc()
}
`,
		"pkg/old.go": `package pkg

// OldFunc is deprecated.
// Deprecated: use NewFunc instead.
func OldFunc() {}

func NewFunc() {}
`,
	}
	for name, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(body), 0o644)
	}

	cfg := config.Defaults()
	cfg.Root = dir
	cfg.Rules["deprecated-exports-in-use"] = string(config.Warn)
	ld, err := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	if err != nil {
		t.Fatal(err)
	}
	proj := facts.Build(ld)
	g := graph.Build(proj)
	a := &Analysis{Proj: proj, Graph: g, Cfg: cfg}
	res := Run(a)

	var found bool
	for _, f := range res.Findings {
		if f.Kind == "deprecated-export-in-use" && f.Rule == "deprecated-exports-in-use" {
			if sym, _ := f.Extra["symbol"].(string); sym == "OldFunc" {
				found = true
				if f.Severity != config.Warn {
					t.Errorf("got severity %s, want %s", f.Severity, config.Warn)
				}
			}
		}
	}
	if !found {
		t.Errorf("expected deprecated-export-in-use finding for OldFunc, got findings: %+v", res.Findings)
	}
}

func TestPrivateTypeLeaks(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test needs the go command")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n",
		"main.go": `package main

type secretType struct{ val int }

func PublicLeak() secretType {
	return secretType{val: 42}
}

func main() {
	PublicLeak()
}
`,
	}
	for name, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(body), 0o644)
	}

	cfg := config.Defaults()
	cfg.Root = dir
	cfg.Rules["private-type-leaks"] = string(config.Error)
	ld, err := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	if err != nil {
		t.Fatal(err)
	}
	proj := facts.Build(ld)
	g := graph.Build(proj)
	a := &Analysis{Proj: proj, Graph: g, Cfg: cfg}
	res := Run(a)

	var found bool
	for _, f := range res.Findings {
		if f.Kind == "private-type-leak" && f.Rule == "private-type-leaks" {
			if sym, _ := f.Extra["symbol"].(string); sym == "PublicLeak" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected private-type-leak finding for PublicLeak, got findings: %+v", res.Findings)
	}
}

func TestUnusedTestDependencyInProductionMode(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test needs the go command")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": `module testmod

go 1.24

require github.com/direct/dep v1.0.0

replace github.com/direct/dep => ./dep
`,
		"main.go": `package main

func main() {}
`,
		"main_test.go": `package main

import (
	"testing"

	_ "github.com/direct/dep"
)

func TestSomething(t *testing.T) {}
`,
		"dep/dep.go": `package dep

func Helper() {}
`,
	}
	for name, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(body), 0o644)
	}

	cfg := config.Defaults()
	cfg.Root = dir
	ld, err := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	if err != nil {
		t.Fatal(err)
	}
	proj := facts.Build(ld)
	g := graph.Build(proj)

	// Non-production analysis should NOT report unused-test-dependency.
	aNonProd := &Analysis{Proj: proj, Graph: g, Cfg: cfg, Opts: Options{Production: false}}
	resNonProd := Run(aNonProd)
	for _, f := range resNonProd.Findings {
		if f.Kind == "unused-test-dependency" {
			t.Errorf("did not expect unused-test-dependency in non-production mode, got: %+v", f)
		}
	}

	// Production analysis MUST report unused-test-dependency.
	aProd := &Analysis{Proj: proj, Graph: g, Cfg: cfg, Opts: Options{Production: true}}
	resProd := Run(aProd)
	var found bool
	for _, f := range resProd.Findings {
		if f.Kind == "unused-test-dependency" && f.Rule == "unused-test-dependencies" {
			if pkg, _ := f.Extra["package_name"].(string); pkg == "github.com/direct/dep" {
				found = true
				if f.Severity != config.Warn {
					t.Errorf("got severity %s, want %s", f.Severity, config.Warn)
				}
			}
		}
	}
	if !found {
		t.Errorf("expected unused-test-dependency finding for github.com/direct/dep in production mode, got findings: %+v", resProd.Findings)
	}
}

func TestTransitiveCallGraphDeadCycles(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test needs the go command")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n",
		"main.go": `package main

func main() {
	liveCycleA(2)
}

func liveCycleA(n int) int {
	if n <= 0 {
		return 0
	}
	return liveCycleB(n - 1)
}

func liveCycleB(n int) int {
	return liveCycleA(n - 1)
}

func deadCycleA(n int) int {
	if n <= 0 {
		return 0
	}
	return deadCycleB(n - 1)
}

func deadCycleB(n int) int {
	return deadCycleA(n - 1)
}

func deadChainCaller() int {
	return deadChainCallee()
}

func deadChainCallee() int {
	return 42
}
`,
	}
	for name, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(body), 0o644)
	}

	doc, _ := runAnalysis(t, dir)
	kinds := kindsBySymbol(doc)

	for _, wantDead := range []string{"deadCycleA", "deadCycleB", "deadChainCaller", "deadChainCallee"} {
		if got := kinds["main.go:"+wantDead]; got != "unused-unexported" {
			t.Errorf("expected %s to be reported as unused-unexported, got %q (all: %v)", wantDead, got, kinds)
		}
	}
	for _, wantLive := range []string{"main", "liveCycleA", "liveCycleB"} {
		if got, bad := kinds["main.go:"+wantLive]; bad {
			t.Errorf("false positive: %s reported as %s", wantLive, got)
		}
	}
}

func TestCompilerDirectivesAndBuildTags(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test needs the go command")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n",
		"main.go": `package main

func main() {}

//export cgoExportedHook
func cgoExportedHook() int {
	return 1
}

//go:linkname runtimeLinkedHelper testmod.runtimeLinkedHelper
func runtimeLinkedHelper() int {
	return 2
}

func platformSpecificHelper() int {
	return 3
}

func genuinelyUnusedHelper() int {
	return 4
}
`,
		"platform_other.go": `//go:build never_active_platform_tag

package main

func init() {
	_ = platformSpecificHelper()
}
`,
	}
	for name, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(body), 0o644)
	}

	doc, _ := runAnalysis(t, dir)
	kinds := kindsBySymbol(doc)

	for _, keep := range []string{"cgoExportedHook", "runtimeLinkedHelper", "platformSpecificHelper"} {
		if got, bad := kinds["main.go:"+keep]; bad {
			t.Errorf("expected %s to be credited and kept alive, got %q", keep, got)
		}
	}
	if got := kinds["main.go:genuinelyUnusedHelper"]; got != "unused-unexported" {
		t.Errorf("expected genuinelyUnusedHelper to be unused-unexported, got %q", got)
	}
}

func TestGoSpecificDeadCodeAndAPIRules(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test needs the go command")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n",
		"main.go": `package main

import "testmod/lib"

var writeOnlyGlobal int
var readAndWrittenGlobal int

type PaddedStruct struct {
	flagA bool
	big   int64
	flagB bool
}

type Store interface {
	Get() int
	UnusedIfaceMethod() error
}

type memStore struct {
	readField      int
	writeOnlyField int
}

func (m *memStore) Get() int                { return m.readField }
func (m *memStore) UnusedIfaceMethod() error { return nil }
func (m *memStore) UnusedRecvMethod() int    { return 99 }

func computeWithUnusedParam(used int, unusedParam string) int {
	return used + 1
}

func main() {
	writeOnlyGlobal = 10
	readAndWrittenGlobal = 20
	s := &memStore{readField: readAndWrittenGlobal, writeOnlyField: 5}
	s.writeOnlyField = 6
	var st Store = s
	_ = st.Get()
	_ = s.UnusedRecvMethod()
	_ = computeWithUnusedParam(1, "ignored")
	p := PaddedStruct{flagA: true, big: 100, flagB: false}
	if p.flagA && p.flagB && p.big > 0 {
		lib.PublicEntry()
	}
}
`,
		"lib/lib.go": `package lib

func PublicEntry() int {
	return OnlySamePkgExport()
}

func OnlySamePkgExport() int {
	return 7
}
`,
	}
	for name, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(body), 0o644)
	}

	cfg := config.Defaults()
	cfg.Root = dir
	for _, r := range []string{
		"write-only-fields",
		"write-only-variables",
		"can-be-unexported",
		"unused-interface-methods",
		"unused-parameters",
		"unused-receivers",
		"struct-padding",
	} {
		cfg.Rules[r] = string(config.Warn)
	}

	ld, err := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	if err != nil {
		t.Fatal(err)
	}
	proj := facts.Build(ld)
	g := graph.Build(proj)
	a := &Analysis{Proj: proj, Graph: g, Cfg: cfg}
	res := Run(a)

	gotByKindSym := map[string]bool{}
	for _, f := range res.Findings {
		sym, _ := f.Extra["symbol"].(string)
		gotByKindSym[f.Kind+":"+sym] = true
	}

	for _, want := range []string{
		"write-only-field:writeOnlyField",
		"write-only-variable:writeOnlyGlobal",
		"can-be-unexported:OnlySamePkgExport",
		"unused-interface-method:UnusedIfaceMethod",
		"unused-parameter:unusedParam",
		"unused-receiver:m",
		"struct-padding:PaddedStruct",
	} {
		if !gotByKindSym[want] {
			t.Errorf("missing expected finding %s; got: %v", want, gotByKindSym)
		}
	}

	for _, notWant := range []string{
		"write-only-field:readField",
		"write-only-variable:readAndWrittenGlobal",
		"can-be-unexported:PublicEntry",
		"unused-interface-method:Get",
		"unused-parameter:used",
	} {
		if gotByKindSym[notWant] {
			t.Errorf("unexpected false positive %s", notWant)
		}
	}
}

func TestGoRuntimeHazardAndSecurityRules(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test needs the go command")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n",
		"main.go": `package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"os/exec"
	"sync"
)

const hardcodedToken = "ghp_1234567890abcdefghijklmnopqrstuv"

type myCustomErr struct{}

func (*myCustomErr) Error() string { return "boom" }

func returnsTypedNilError() error {
	var p *myCustomErr
	return p
}

func leaksContext(parent context.Context) {
	ctx, _ := context.WithCancel(parent)
	_ = ctx
}

func defersInLoop(items []string) {
	for _, it := range items {
		f, err := os.Open(it)
		if err == nil {
			defer f.Close()
		}
	}
}

func leaksHTTPBody(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	_ = resp.StatusCode
	return nil
}

type lockBox struct {
	mu sync.Mutex
}

func (b lockBox) copyReceiver() {}

func dangerousExec(userArg string) {
	_ = exec.Command("sh", "-c", userArg)
	_ = &tls.Config{InsecureSkipVerify: true}
}

func checkFlag() bool {
	return os.Getenv("FEATURE_BETA_MODE") == "1"
}

func main() {
	_ = hardcodedToken
	_ = returnsTypedNilError()
	leaksContext(context.Background())
	defersInLoop(nil)
	_ = leaksHTTPBody("http://example.com")
	var lb lockBox
	lb.copyReceiver()
	dangerousExec("echo hi")
	_ = checkFlag()
}
`,
	}
	for name, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(body), 0o644)
	}

	cfg := config.Defaults()
	cfg.Root = dir
	cfg.Rules["security-sink"] = string(config.Warn)
	cfg.Rules["secrets-in-code"] = string(config.Warn)
	cfg.Rules["feature-flags"] = string(config.Warn)

	ld, err := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	if err != nil {
		t.Fatal(err)
	}
	proj := facts.Build(ld)
	g := graph.Build(proj)
	a := &Analysis{Proj: proj, Graph: g, Cfg: cfg}
	res := Run(a)

	gotKinds := map[string]int{}
	for _, f := range res.Findings {
		gotKinds[f.Kind]++
	}

	for _, wantKind := range []string{
		"nil-error-interface",
		"context-leak",
		"defer-in-loop",
		"unclosed-body",
		"copylocks",
		"security-sink",
		"secret-in-code",
		"feature-flag",
	} {
		if gotKinds[wantKind] == 0 {
			t.Errorf("expected finding of kind %q, got counts: %v", wantKind, gotKinds)
		}
	}
}
