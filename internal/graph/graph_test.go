package graph

import (
	"testing"

	"goose/internal/config"
	"goose/internal/facts"
)

// project builds a facts.Project from a map of package path -> imported
// project package paths, so the graph can be tested without the loader.
func project(pkgImports map[string][]string) *facts.Project {
	p := &facts.Project{
		Files:     map[string]*facts.FileFacts{},
		EntryPkgs: map[string]bool{},
	}
	for pkg, imps := range pkgImports {
		var ii []facts.ImportInfo
		for _, in := range imps {
			ii = append(ii, facts.ImportInfo{Path: in})
		}
		key := "/abs/" + pkg + "/x.go"
		p.Files[key] = &facts.FileFacts{
			Path: key, Rel: pkg + "/x.go", PkgPath: pkg, Imports: ii,
		}
	}
	return p
}

func TestCyclesDetectsLoop(t *testing.T) {
	g := Build(project(map[string][]string{
		"a": {"b"},
		"b": {"a"},
	}))
	cycles := g.Cycles()
	if len(cycles) != 1 {
		t.Fatalf("want 1 cycle, got %d: %v", len(cycles), cycles)
	}
	got := map[string]bool{}
	for _, p := range cycles[0] {
		got[p] = true
	}
	if !got["a"] || !got["b"] || len(cycles[0]) != 2 {
		t.Errorf("cycle members = %v, want {a,b}", cycles[0])
	}
}

func TestCyclesLongRing(t *testing.T) {
	g := Build(project(map[string][]string{
		"a": {"b"},
		"b": {"c"},
		"c": {"a"},
	}))
	cycles := g.Cycles()
	if len(cycles) != 1 || len(cycles[0]) != 3 {
		t.Fatalf("want one 3-cycle, got %v", cycles)
	}
}

func TestNoCyclesInDAG(t *testing.T) {
	g := Build(project(map[string][]string{
		"a": {"b", "c"},
		"b": {"d"},
		"c": {"d"},
		"d": {},
	}))
	if cycles := g.Cycles(); len(cycles) != 0 {
		t.Fatalf("DAG must have no cycles, got %v", cycles)
	}
}

func TestReachableFromEntry(t *testing.T) {
	p := project(map[string][]string{
		"main":  {"api"},
		"api":   {"store"},
		"store": {},
		"dead":  {},
	})
	p.EntryPkgs["main"] = true
	cfg := config.Defaults()
	g := Build(p)
	got := g.ReachablePackages(cfg)
	if !got["main"] || !got["api"] || !got["store"] {
		t.Errorf("reachable missing nodes: %v", got)
	}
	if got["dead"] {
		t.Error("dead must not be reachable")
	}
}

func TestEntryPackagesIncludesConfigGlobs(t *testing.T) {
	p := project(map[string][]string{"lib": {}})
	cfg := config.Defaults()
	cfg.Entry = []string{"lib"}
	g := Build(p)
	entries := g.EntryPackages(cfg)
	found := false
	for _, e := range entries {
		if e == "lib" {
			found = true
		}
	}
	if !found {
		t.Errorf("config entry glob should add lib, got %v", entries)
	}
}

func TestEntryPackagesMatchesFileRelPath(t *testing.T) {
	p := project(map[string][]string{"cmd/app": {}})
	cfg := config.Defaults()
	cfg.Entry = []string{"cmd/app/x.go"}
	g := Build(p)
	entries := g.EntryPackages(cfg)
	found := false
	for _, e := range entries {
		if e == "cmd/app" {
			found = true
		}
	}
	if !found {
		t.Errorf("config entry file rel path should add cmd/app, got %v", entries)
	}
}
