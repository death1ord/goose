package health

import (
	"math"
	"sort"

	"goose/internal/config"
	"goose/internal/facts"
)

// Coverage gaps answer "which runtime code does no test reach?" In Go every
// loaded file compiles, so the module graph is the reachability substrate:
// _test.go files are test roots, an import pulls in every file of the
// imported module package, and an entity use pulls in the declaring file. A
// runtime file outside the closure has no dependency path from any test; its
// exported symbols are untested-export findings.

// CoverageGapSummary aggregates the gap scan over the current scope.
type CoverageGapSummary struct {
	RuntimeFiles    int     `json:"runtime_files"`
	CoveredFiles    int     `json:"covered_files"`
	FileCoveragePct float64 `json:"file_coverage_pct"`
	UntestedFiles   int     `json:"untested_files"`
	UntestedExports int     `json:"untested_exports"`
}

// UntestedFile names a runtime file with no test dependency path.
type UntestedFile struct {
	Path             string `json:"path"`
	ValueExportCount int    `json:"value_export_count"`
}

// UntestedExport names a runtime export no test-reachable file references.
type UntestedExport struct {
	Path       string `json:"path"`
	ExportName string `json:"export_name"`
	Line       int    `json:"line"`
	Col        int    `json:"col"`
}

// CoverageGaps is the coverage_gaps block of the health report.
type CoverageGaps struct {
	Summary CoverageGapSummary `json:"summary"`
	Files   []UntestedFile     `json:"files,omitempty"`
	Exports []UntestedExport   `json:"exports,omitempty"`
}

// computeCoverageGaps runs the gap scan and drops entries whose
// coverage-gaps rule is off for their file.
func computeCoverageGaps(p *facts.Project, cfg *config.Config) *CoverageGaps {
	// relOf maps absolute file paths to project-relative ones.
	relOf := map[string]string{}
	for path, ff := range p.Files {
		relOf[path] = ff.Rel
	}
	// filesByPkg groups file paths by package path for import expansion.
	filesByPkg := map[string][]string{}
	for path, ff := range p.Files {
		filesByPkg[ff.PkgPath] = append(filesByPkg[ff.PkgPath], path)
	}
	// reach closure over imports and declared-entity uses, seeded with test
	// files. A reached file depends on: every file of each package it
	// imports, and every file declaring an entity it references.
	usesInFile := map[string][]facts.Key{}
	for key, sites := range p.Uses {
		for _, u := range sites {
			if u.File != "" {
				usesInFile[u.File] = append(usesInFile[u.File], key)
			}
		}
	}
	reach := map[string]bool{}
	queue := []string{}
	for path, ff := range p.Files {
		if ff.InTest {
			reach[path] = true
			queue = append(queue, path)
		}
	}
	sort.Strings(queue)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		ff := p.Files[cur]
		if ff == nil {
			continue
		}
		add := func(x string) {
			if x != "" && !reach[x] {
				reach[x] = true
				queue = append(queue, x)
			}
		}
		for _, imp := range ff.Imports {
			for _, f2 := range filesByPkg[imp.Path] {
				add(f2)
			}
		}
		for _, key := range usesInFile[cur] {
			if e := p.Entities[key]; e != nil {
				add(e.File)
			}
		}
	}
	// Scan non-test files that declare code.
	var files []UntestedFile
	var exports []UntestedExport
	runtimeFiles, covered := 0, 0
	for _, ff := range sortedProjectFiles(p) {
		if ff.InTest || len(ff.Entities) == 0 {
			continue
		}
		if cfg.RuleSeverity("coverage-gaps", ff.Rel) == config.Off {
			continue
		}
		runtimeFiles++
		if reach[ff.Path] {
			covered++
			continue
		}
		valueExports := 0
		for _, key := range ff.Entities {
			e := p.Entities[key]
			if e == nil || !e.Exported || e.Local || e.InterfaceMethod {
				continue
			}
			switch e.Kind {
			case facts.KindFunc, facts.KindMethod, facts.KindVar, facts.KindConst:
				valueExports++
			}
			if !referencedFromReachable(p, reach, key) {
				exports = append(exports, UntestedExport{
					Path: ff.Rel, ExportName: e.Name, Line: e.Line, Col: e.Col,
				})
			}
		}
		files = append(files, UntestedFile{Path: ff.Rel, ValueExportCount: valueExports})
	}
	pct := buildGapSummary(runtimeFiles, covered, 0, 0).FileCoveragePct
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(exports, func(i, j int) bool {
		if exports[i].Path != exports[j].Path {
			return exports[i].Path < exports[j].Path
		}
		if exports[i].ExportName != exports[j].ExportName {
			return exports[i].ExportName < exports[j].ExportName
		}
		return exports[i].Line < exports[j].Line
	})
	return &CoverageGaps{
		Summary: CoverageGapSummary{
			RuntimeFiles: runtimeFiles, CoveredFiles: covered, FileCoveragePct: pct,
			UntestedFiles: len(files), UntestedExports: len(exports),
		},
		Files: files, Exports: exports,
	}
}

// buildGapSummary aggregates the counters, rounding file coverage to one
// decimal and reporting 100% for an empty scope, like fallow.
func buildGapSummary(runtimeFiles, covered, untestedFiles, untestedExports int) CoverageGapSummary {
	pct := 100.0
	if runtimeFiles > 0 {
		pct = math.Round(float64(covered)/float64(runtimeFiles)*1000) / 10
	}
	return CoverageGapSummary{
		RuntimeFiles: runtimeFiles, CoveredFiles: covered, FileCoveragePct: pct,
		UntestedFiles: untestedFiles, UntestedExports: untestedExports,
	}
}

// referencedFromReachable reports whether any test-reachable file uses the
// entity.
func referencedFromReachable(p *facts.Project, reach map[string]bool, key facts.Key) bool {
	for _, u := range p.Uses[key] {
		if u.File != "" && reach[u.File] {
			return true
		}
	}
	return false
}

// sortedProjectFiles lists file facts deterministically by relative path.
func sortedProjectFiles(p *facts.Project) []*facts.FileFacts {
	out := make([]*facts.FileFacts, 0, len(p.Files))
	for _, path := range keysOf(p.Files) {
		out = append(out, p.Files[path])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
