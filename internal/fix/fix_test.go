package fix

import (
	"os"
	"path/filepath"
	"testing"

	"goose/internal/report"
)

func TestBuildClassifiesTargets(t *testing.T) {
	findings := []*report.Finding{
		{Kind: "unused-export", Path: "a.go", Line: 3, Severity: "error",
			Extra:   map[string]any{"symbol": "Foo"},
			Actions: []report.Action{{Type: "remove-dead-code", AutoFixable: true}}},
		{Kind: "unused-file", Path: "b.go", Severity: "error",
			Actions: []report.Action{{Type: "remove-file", AutoFixable: true}}},
		{Kind: "stale-suppression", Path: "a.go", Line: 9,
			Extra:   map[string]any{"comment": "// goose-ignore-next-line unused-export"},
			Actions: []report.Action{{Type: "remove-suppression", AutoFixable: true}}},
		// Not auto-fixable: skipped.
		{Kind: "unused-dependency", Path: "go.mod",
			Extra:   map[string]any{"package_name": "example.com/nope"},
			Actions: []report.Action{{Type: "remove-dependency", AutoFixable: false}}},
		// Hidden: never planned.
		{Kind: "unused-export", Path: "c.go", Hidden: true, Line: 1,
			Extra:   map[string]any{"symbol": "Hid"},
			Actions: []report.Action{{Type: "remove-dead-code", AutoFixable: true}}},
	}
	p := Build("/root", findings)
	if p.AutoFixes != 3 {
		t.Errorf("auto-fixes = %d, want 3", p.AutoFixes)
	}
	if p.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", p.Skipped)
	}
	if len(p.Files) != 1 || filepath.Base(p.Files[0]) != "b.go" {
		t.Errorf("files = %v, want [b.go]", p.Files)
	}
	if p.Edits != 1 { // a.go gets symbol + suppression edits
		t.Errorf("edits = %d, want 1", p.Edits)
	}
	if len(p.Targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(p.Targets))
	}
	var hasSym, hasSupp bool
	for _, tg := range p.Targets {
		if tg.Symbol == "Foo" && tg.Line == 3 {
			hasSym = true
		}
		if tg.Kind == "stale-suppression" && tg.Line == 9 {
			hasSupp = true
		}
	}
	if !hasSym || !hasSupp {
		t.Errorf("targets missing: %+v", p.Targets)
	}
}

func TestDropLinesAndCollapse(t *testing.T) {
	src := "package a\n\nfunc Keep() {}\n\nfunc Drop() {}\n\nfunc Keep2() {}\n"
	out := string(dropLines([]byte(src), map[int]bool{5: true}))
	if want := "package a\n\nfunc Keep() {}\n\nfunc Keep2() {}\n"; out != want {
		t.Errorf("dropLines = %q want %q", out, want)
	}
}

func TestApplyRemovesSymbolAndKeepsBuild(t *testing.T) {
	dir := t.TempDir()
	main := `package main

func main() { keep() }

func keep() {}

func drop() {}
`
	file := filepath.Join(dir, "main.go")
	if err := os.WriteFile(file, []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	gomod := filepath.Join(dir, "go.mod")
	os.WriteFile(gomod, []byte("module fixt\n\ngo 1.24\n"), 0o644)

	plan := Build(dir, []*report.Finding{{
		Kind: "unused-unexported", Path: "main.go", Line: 7,
		Extra:   map[string]any{"symbol": "drop"},
		Actions: []report.Action{{Type: "remove-dead-code", AutoFixable: true}},
	}})
	res := plan.Apply(dir)
	if !res.BuildOK {
		t.Fatalf("build after fix failed: %s", res.BuildErr)
	}
	after, _ := os.ReadFile(file)
	s := string(after)
	if containsStr(s, "drop") {
		t.Errorf("drop() should be gone, file:\n%s", s)
	}
	if !containsStr(s, "keep") || !containsStr(s, "main") {
		t.Errorf("live code damaged:\n%s", s)
	}
}

func TestApplyRollsBackOnBrokenEdit(t *testing.T) {
	dir := t.TempDir()
	// main uses helper; a plan that removes "keep" (actually referenced
	// indirectly via the line we target on purpose to break build).
	main := `package main

func main() { println(keep()) }

func keep() int { return 1 }
`
	file := filepath.Join(dir, "main.go")
	os.WriteFile(file, []byte(main), 0o644)
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixb\n\ngo 1.24\n"), 0o644)

	// Force a target that deletes the line keep() is declared on (line 5),
	// which breaks the build — the rollback contract's whole point.
	plan := &Plan{Root: dir, AutoFixes: 1, Targets: []Target{{
		File: file, Kind: "unused-unexported", Symbol: "keep", Line: 5,
	}}}
	res := plan.Apply(dir)
	if res.BuildOK {
		t.Fatal("expected the build to fail after removing keep()")
	}
	if !res.RolledBack {
		t.Error("expected rollback")
	}
	after, _ := os.ReadFile(file)
	if string(after) != main {
		t.Errorf("file not restored:\n%s", after)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestApplyRemovesUnusedField(t *testing.T) {
	dir := t.TempDir()
	main := `package main

type MyStruct struct {
	KeepA int
	DropMe string
	KeepB bool
}

func main() {
	s := MyStruct{KeepA: 1, KeepB: true}
	println(s.KeepA, s.KeepB)
}
`
	file := filepath.Join(dir, "main.go")
	if err := os.WriteFile(file, []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixfield\n\ngo 1.24\n"), 0o644)

	plan := Build(dir, []*report.Finding{{
		Kind: "unused-field", Path: "main.go", Line: 5,
		Extra:   map[string]any{"symbol": "DropMe", "struct": "MyStruct"},
		Actions: []report.Action{{Type: "remove-dead-code", AutoFixable: true}},
	}})
	res := plan.Apply(dir)
	if !res.BuildOK {
		t.Fatalf("build after field fix failed: %s", res.BuildErr)
	}
	after, _ := os.ReadFile(file)
	s := string(after)
	if containsStr(s, "DropMe") {
		t.Errorf("DropMe should be gone, file:\n%s", s)
	}
	if !containsStr(s, "KeepA") || !containsStr(s, "KeepB") {
		t.Errorf("sibling fields damaged:\n%s", s)
	}
}

func TestApplySkipsMultiNameField(t *testing.T) {
	dir := t.TempDir()
	main := `package main

type MyStruct struct {
	KeepA, DropB int
}

func main() {
	s := MyStruct{KeepA: 1}
	println(s.KeepA)
}
`
	file := filepath.Join(dir, "main.go")
	os.WriteFile(file, []byte(main), 0o644)
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixmultifield\n\ngo 1.24\n"), 0o644)

	plan := Build(dir, []*report.Finding{{
		Kind: "unused-field", Path: "main.go", Line: 4,
		Extra:   map[string]any{"symbol": "DropB", "struct": "MyStruct"},
		Actions: []report.Action{{Type: "remove-dead-code", AutoFixable: true}},
	}})
	res := plan.Apply(dir)
	if !res.BuildOK {
		t.Fatalf("build failed: %s", res.BuildErr)
	}
	after, _ := os.ReadFile(file)
	s := string(after)
	if !containsStr(s, "KeepA, DropB int") {
		t.Errorf("multi-name field declaration should not have been deleted:\n%s", s)
	}
}

func TestAbsorbCommentsDoesNotCrossBlankLines(t *testing.T) {
	dir := t.TempDir()
	main := `package main

// Unrelated header comment that must remain.

// DropFuncDoc comment for DropFunc.
func DropFunc() {}

func main() {}
`
	file := filepath.Join(dir, "main.go")
	os.WriteFile(file, []byte(main), 0o644)
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixcomment\n\ngo 1.24\n"), 0o644)

	plan := Build(dir, []*report.Finding{{
		Kind: "unused-unexported", Path: "main.go", Line: 6,
		Extra:   map[string]any{"symbol": "DropFunc"},
		Actions: []report.Action{{Type: "remove-dead-code", AutoFixable: true}},
	}})
	res := plan.Apply(dir)
	if !res.BuildOK {
		t.Fatalf("build failed: %s", res.BuildErr)
	}
	after, _ := os.ReadFile(file)
	s := string(after)
	if containsStr(s, "DropFuncDoc") {
		t.Errorf("direct doc comment should have been absorbed:\n%s", s)
	}
	if !containsStr(s, "Unrelated header comment that must remain.") {
		t.Errorf("unrelated comment across blank line was deleted:\n%s", s)
	}
}

func TestApplySkipsMultiIdentifierVar(t *testing.T) {
	dir := t.TempDir()
	main := `package main

var used, unused = 1, 2

func main() {
	println(used)
}
`
	file := filepath.Join(dir, "main.go")
	os.WriteFile(file, []byte(main), 0o644)
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixmultivar\n\ngo 1.24\n"), 0o644)

	plan := Build(dir, []*report.Finding{{
		Kind: "unused-variable", Path: "main.go", Line: 3,
		Extra:   map[string]any{"symbol": "unused"},
		Actions: []report.Action{{Type: "remove-dead-code", AutoFixable: true}},
	}})
	res := plan.Apply(dir)
	if !res.BuildOK {
		t.Fatalf("build failed: %s", res.BuildErr)
	}
	after, _ := os.ReadFile(file)
	s := string(after)
	if !containsStr(s, "var used, unused = 1, 2") {
		t.Errorf("multi-identifier var should be skipped and preserved intact:\n%s", s)
	}
}
