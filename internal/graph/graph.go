// Package graph models package-level import relationships: reachability from
// entry packages (used for unused-file analysis) and import cycles (used by
// the architecture analysis).
package graph

import (
	"sort"

	"goose/internal/config"
	"goose/internal/facts"
)

// Graph is the project's package import graph.
type Graph struct {
	Pkg *facts.Project
	// Imports maps a package path to the project paths it imports.
	Imports map[string][]string
	// ImportedBy maps a package path to the project paths that import it.
	ImportedBy map[string][]string
	// Packages lists every project package path.
	Packages []string
	// External lists import paths outside the module.
	External map[string]bool
}

// Build constructs the package import graph.
func Build(p *facts.Project) *Graph {
	g := &Graph{Pkg: p, Imports: map[string][]string{}, ImportedBy: map[string][]string{}, External: map[string]bool{}}
	present := map[string]bool{}
	for _, ff := range p.Files {
		if !present[ff.PkgPath] {
			present[ff.PkgPath] = true
			g.Packages = append(g.Packages, ff.PkgPath)
		}
	}
	sort.Strings(g.Packages)
	seenEdge := map[[2]string]bool{}
	for _, ff := range p.Files {
		for _, imp := range ff.Imports {
			if !present[imp.Path] {
				g.External[imp.Path] = true
				continue
			}
			if imp.Path == ff.PkgPath {
				continue
			}
			edge := [2]string{ff.PkgPath, imp.Path}
			if seenEdge[edge] {
				continue
			}
			seenEdge[edge] = true
			g.Imports[ff.PkgPath] = append(g.Imports[ff.PkgPath], imp.Path)
			g.ImportedBy[imp.Path] = append(g.ImportedBy[imp.Path], ff.PkgPath)
		}
	}
	return g
}

// EntryPackages returns root packages: those with a main function, plus any
// matching a config entry glob.
func (g *Graph) EntryPackages(cfg *config.Config) []string {
	roots := map[string]bool{}
	for pkg := range g.Pkg.EntryPkgs {
		roots[pkg] = true
	}
	for _, pattern := range cfg.Entry {
		for _, pkg := range g.Packages {
			if config.MatchPath(pattern, pkg) {
				roots[pkg] = true
			}
		}
		if g.Pkg != nil {
			for _, ff := range g.Pkg.Files {
				if !ff.InTest && config.MatchPath(pattern, ff.Rel) {
					roots[ff.PkgPath] = true
				}
			}
		}
	}
	var out []string
	for pkg := range roots {
		out = append(out, pkg)
	}
	sort.Strings(out)
	return out
}

// ReachablePackages returns the transitive import closure from the roots.
func (g *Graph) ReachablePackages(cfg *config.Config) map[string]bool {
	reached := map[string]bool{}
	var stack []string
	for _, pkg := range g.EntryPackages(cfg) {
		if !reached[pkg] {
			reached[pkg] = true
			stack = append(stack, pkg)
		}
	}
	for len(stack) > 0 {
		pkg := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, dep := range g.Imports[pkg] {
			if !reached[dep] {
				reached[dep] = true
				stack = append(stack, dep)
			}
		}
	}
	return reached
}

// IsTestPkg reports whether every file of a package is a test file.
func (g *Graph) IsTestPkg(pkg string) bool {
	sawFile := false
	for _, ff := range g.Pkg.Files {
		if ff.PkgPath != pkg {
			continue
		}
		sawFile = true
		if !ff.InTest {
			return false
		}
	}
	return sawFile
}

// Cycles returns every import cycle among project packages, each as a sorted
// list of package paths forming the loop.
func (g *Graph) Cycles() [][]string {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var stack []string
	index := map[string]int{}
	var found [][]string
	seenRoot := map[string]bool{}

	var visit func(pkg string)
	visit = func(pkg string) {
		color[pkg] = gray
		index[pkg] = len(stack)
		stack = append(stack, pkg)
		for _, dep := range g.Imports[pkg] {
			switch color[dep] {
			case white:
				visit(dep)
			case gray:
				cycle := append([]string{}, stack[index[dep]:]...)
				key := cycleKey(cycle)
				if !seenRoot[key] {
					seenRoot[key] = true
					found = append(found, cycle)
				}
			}
		}
		stack = stack[:len(stack)-1]
		delete(index, pkg)
		color[pkg] = black
	}
	for _, pkg := range g.Packages {
		if color[pkg] == white {
			visit(pkg)
		}
	}
	sortCycles(found)
	return found
}

func cycleKey(cycle []string) string {
	c := append([]string{}, cycle...)
	sort.Strings(c)
	key := ""
	for _, x := range c {
		key += x + "\x1f"
	}
	return key
}

func sortCycles(all [][]string) {
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		for k := range a {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return false
	})
}
