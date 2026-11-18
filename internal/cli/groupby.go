package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"

	"goose/internal/config"
	"goose/internal/engine"
	"goose/internal/report"
)

// buildOwnership resolves --group-by the way fallow does: directory always
// works; owner and section need a CODEOWNERS file; package needs a Go
// workspace. A mode the format cannot carry is not an error here — the
// renderer prints the fallback note — but a missing CODEOWNERS or workspace
// is a usage error (exit 2) before any analysis runs.
func buildOwnership(f *Flags, ec *engine.Context, cfg *config.Config) (*report.Ownership, error) {
	if f.GroupBy == "" {
		return nil, nil
	}
	mode, ok := report.NormalizeGroupBy(f.GroupBy)
	if !ok {
		return nil, ErrUsage{"--group-by must be one of: owner, directory, package, section"}
	}
	switch mode {
	case "directory":
		return &report.Ownership{Mode: mode}, nil
	case "owner", "section":
		text, err := readCodeowners(cfg)
		if err != nil {
			return nil, err
		}
		co := report.ParseCodeowners(text)
		if mode == "section" && !co.Sections {
			return nil, ErrUsage{"--group-by section requires a GitLab-style CODEOWNERS file with [Section] headers. This CODEOWNERS has no sections; use --group-by owner instead"}
		}
		return &report.Ownership{Mode: mode, CO: co}, nil
	case "package":
		ws, err := goWorkspaces(cfg, ec)
		if err != nil {
			return nil, err
		}
		if len(ws) == 0 {
			return nil, ErrUsage{"--group-by package requires a Go workspace with use directories (go.work). For single-module projects use --group-by directory instead"}
		}
		return &report.Ownership{Mode: mode, Workspaces: ws}, nil
	}
	return nil, ErrUsage{"--group-by must be one of: owner, directory, package, section"}
}

// readCodeowners loads the configured path, then the standard probe order:
// CODEOWNERS, .github/CODEOWNERS, .gitlab/CODEOWNERS, docs/CODEOWNERS.
func readCodeowners(cfg *config.Config) (string, error) {
	if cfg.Codeowners != "" {
		p := cfg.Codeowners
		if !filepath.IsAbs(p) {
			p = filepath.Join(cfg.Root, p)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return "", ErrUsage{fmt.Sprintf("--group-by owner could not read the configured codeowners file %s: %v", cfg.Codeowners, err)}
		}
		return string(data), nil
	}
	for _, rel := range []string{"CODEOWNERS", ".github/CODEOWNERS", ".gitlab/CODEOWNERS", "docs/CODEOWNERS"} {
		data, err := os.ReadFile(filepath.Join(cfg.Root, rel))
		if err == nil {
			return string(data), nil
		}
	}
	return "", ErrUsage{"--group-by owner found no CODEOWNERS file. Looked for CODEOWNERS, .github/CODEOWNERS, .gitlab/CODEOWNERS, and docs/CODEOWNERS. Add one, set the config codeowners path, or use --group-by directory instead"}
}

// goWorkspaces turns go.work use directories into package buckets rooted
// under cfg.Root, named by the module path in each directory (basename
// fallback).
func goWorkspaces(cfg *config.Config, ec *engine.Context) ([]report.Workspace, error) {
	var out []report.Workspace
	seen := map[string]bool{}
	for _, abs := range ec.Loaded.Module.Workspaces {
		rel, err := filepath.Rel(cfg.Root, abs)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue // outside the analyzed root: cannot contain its findings
		}
		rel = filepath.ToSlash(rel)
		if rel == "." || seen[rel] {
			continue
		}
		seen[rel] = true
		name := filepath.Base(abs)
		if data, err := os.ReadFile(filepath.Join(abs, "go.mod")); err == nil {
			if mf, perr := modfile.Parse(filepath.Join(abs, "go.mod"), data, nil); perr == nil && mf.Module != nil && mf.Module.Mod.Path != "" {
				name = mf.Module.Mod.Path
			}
		}
		out = append(out, report.Workspace{RelRoot: rel, Name: name})
	}
	return out, nil
}
