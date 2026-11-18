package loader_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"goose/internal/loader"
)

func TestLoaderProjectMethods(t *testing.T) {
	dir := t.TempDir()
	mod := "module testmod\n\ngo 1.24\n\nrequire (\n\tgithub.com/direct/dep v1.0.0\n\tgithub.com/indirect/dep v1.0.0 // indirect\n)\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	src := "package main\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	m, err := loader.FindModule(dir)
	if err != nil {
		t.Fatalf("FindModule failed: %v", err)
	}
	if m.Path != "testmod" {
		t.Errorf("module path = %q, want testmod", m.Path)
	}
	if len(m.Requires) != 1 || m.Requires[0] != "github.com/direct/dep" {
		t.Errorf("expected only direct dependencies, got %v", m.Requires)
	}

	ld, err := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	if err != nil {
		t.Fatalf("loader.Load failed: %v", err)
	}

	pkgs := ld.ProjectPackages()
	if len(pkgs) == 0 {
		t.Errorf("expected at least 1 project package, got 0")
	}

	files := ld.ProjectFiles()
	if len(files) == 0 {
		t.Errorf("expected at least 1 project file, got 0")
	}
}

func TestGoWorkWithoutRootModAndFlags(t *testing.T) {
	ws := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(ws, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.work", "go 1.24\n\nuse (\n\t./a\n\t./b\n)\n")
	write("a/go.mod", "module example.com/a\n\ngo 1.24\n")
	write("a/a.go", "package a\n\nfunc A() int { return 1 }\n")
	write("a/tag.go", "//go:build customtag\n\npackage a\n\nfunc Tagged() int { return 2 }\n")
	write("b/go.mod", "module example.com/b\n\ngo 1.24\n")
	write("b/b.go", "package b\n\nfunc B() int { return 3 }\n")
	write("extra/go.mod", "module example.com/extra\n\ngo 1.24\n")
	write("extra/extra.go", "package extra\n\nfunc E() int { return 4 }\n")

	m, err := loader.FindModule(ws)
	if err != nil {
		t.Fatalf("FindModule(ws) failed: %v", err)
	}
	if m.WorkFile == "" || len(m.Workspaces) != 2 {
		t.Fatalf("expected WorkFile and 2 Workspaces, got WorkFile=%q Workspaces=%v", m.WorkFile, m.Workspaces)
	}
	if m.Dir == "" {
		t.Fatalf("expected non-empty Dir fallback for go.work root")
	}

	t.Setenv("GOFLAGS", "-tags=customtag")
	ld, err := loader.LoadSyntax(context.Background(), loader.Options{Dir: ws, Tests: false})
	if err != nil {
		t.Fatalf("LoadSyntax failed: %v", err)
	}
	var seenA, seenTag, seenB, seenExtra bool
	for path := range ld.Files {
		base := filepath.Base(path)
		switch base {
		case "a.go":
			seenA = true
		case "tag.go":
			seenTag = true
		case "b.go":
			seenB = true
		case "extra.go":
			seenExtra = true
		}
	}
	if !seenA || !seenTag || !seenB {
		t.Errorf("missing expected workspace/tag files: a=%v tag=%v b=%v", seenA, seenTag, seenB)
	}
	if seenExtra {
		t.Errorf("expected unrelated module extra.go to be skipped outside go.work")
	}

	t.Setenv("GOWORK", "off")
	mOff, err := loader.FindModule(filepath.Join(ws, "a"))
	if err != nil {
		t.Fatalf("FindModule with GOWORK=off failed: %v", err)
	}
	if mOff.WorkFile != "" || len(mOff.Workspaces) != 0 {
		t.Errorf("expected GOWORK=off to disable workspace detection, got WorkFile=%q Workspaces=%v", mOff.WorkFile, mOff.Workspaces)
	}
}
