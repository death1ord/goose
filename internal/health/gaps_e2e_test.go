package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"goose/internal/config"
	"goose/internal/facts"
	"goose/internal/loader"
)

func writeGapsModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module gaps\n\ngo 1.24\n",
		"main.go": `package main

import "gaps/covered"

func main() { covered.Do() }
`,
		"covered/do.go": `package covered

func Do() int { return raw() }
`,
		"covered/do_test.go": `package covered

import "testing"

func TestDo(t *testing.T) { if Do() != 5 { t.Fail() } }
`,
		"orphan/orphan.go": `package orphan

func Orphaned() int { return 42 }

func AlsoOrphaned() string { return "x" }
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

func TestCoverageGapsEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test needs the go command")
	}
	dir := writeGapsModule(t)
	cfg := config.Defaults()
	cfg.Root = dir
	ld, err := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	if err != nil {
		t.Fatal(err)
	}
	proj := facts.Build(ld)
	gaps := computeCoverageGaps(proj, cfg)

	if gaps == nil || gaps.Summary.RuntimeFiles == 0 {
		t.Fatalf("no coverage gaps computed on the fixture")
	}
	// orphan/orphan.go declares code that no test reaches.
	var gapFiles []string
	for _, uf := range gaps.Files {
		gapFiles = append(gapFiles, uf.Path)
	}
	found := false
	for _, p := range gapFiles {
		if p == "orphan/orphan.go" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("orphan/orphan.go must be an untested gap; files=%v", gapFiles)
	}
	// covered/do.go IS test-reachable (via its own _test.go), so it must NOT
	// appear in the files list.
	for _, p := range gapFiles {
		if p == "covered/do.go" {
			t.Fatalf("covered/do.go is test-reachable; must not be a gap: %v", gapFiles)
		}
	}
	var gapExports []string
	for _, ue := range gaps.Exports {
		gapExports = append(gapExports, ue.Path+":"+ue.ExportName)
	}
	found = false
	for _, x := range gapExports {
		if x == "orphan/orphan.go:Orphaned" || x == "orphan/orphan.go:AlsoOrphaned" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("orphan exports must be gaps; exports=%v", gapExports)
	}
}

func TestCoverageGapsHonorsSeverityOff(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test needs the go command")
	}
	dir := writeGapsModule(t)
	cfg := config.Defaults()
	cfg.Root = dir
	cfg.Rules["coverage-gaps"] = "off"
	ld, _ := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	proj := facts.Build(ld)
	gaps := computeCoverageGaps(proj, cfg)
	if gaps == nil {
		t.Fatal("gaps nil when off")
	}
	if len(gaps.Files) != 0 || len(gaps.Exports) != 0 {
		t.Fatalf("off rule must exclude every file: files=%d exports=%d",
			len(gaps.Files), len(gaps.Exports))
	}
}
