package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"goose/internal/architecture"
	"goose/internal/report"
	"goose/internal/version"
)

// runList implements goose list: a read-only project inventory (files,
// entry points, architecture zones, suppression markers). It never fails a
// run; every error is a diagnostic and the exit code stays 0.
func runList(ctx context.Context, f *Flags) int {
	ec, cfg, err := runSyntaxContext(ctx, f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	want := func(name string) bool {
		// No selection asks for everything.
		if !f.BoolExtra["--files"] && !f.BoolExtra["--entry-points"] &&
			!f.BoolExtra["--boundaries"] && !f.BoolExtra["--suppressions"] {
			return true
		}
		return f.BoolExtra["--"+name]
	}

	// files
	var files []map[string]any
	if want("files") {
		var rels []string
		byRel := map[string]string{}
		byTest := map[string]bool{}
		loc := map[string]int{}
		for _, ff := range ec.Proj.Files {
			rels = append(rels, ff.Rel)
			byRel[ff.Rel] = ff.PkgPath
			byTest[ff.Rel] = ff.InTest
			loc[ff.Rel] = ff.Loc
		}
		sort.Strings(rels)
		for _, r := range rels {
			m := map[string]any{"path": r, "package": byRel[r], "lines": loc[r]}
			if byTest[r] {
				m["test"] = true
			}
			files = append(files, m)
		}
	}

	// entry points
	var entries []map[string]any
	if want("entry-points") {
		for _, pkg := range ec.Graph.EntryPackages(cfg) {
			m := map[string]any{"package": pkg}
			if ec.Proj.EntryPkgs[pkg] {
				m["kind"] = "main"
			} else {
				m["kind"] = "config"
			}
			var fs []string
			for _, ff := range ec.Proj.Files {
				if ff.PkgPath == pkg {
					fs = append(fs, ff.Rel)
				}
			}
			sort.Strings(fs)
			m["files"] = fs
			entries = append(entries, m)
		}
	}

	// boundaries
	var boundaries *architecture.BoundarySummary
	if want("boundaries") {
		summary, err := ec.Boundaries()
		if err != nil {
			fmt.Fprintln(os.Stderr, "goose:", err)
			boundaries = &architecture.BoundarySummary{}
		} else {
			boundaries = summary
		}
	}

	// suppressions
	var suppressions []map[string]any
	if want("suppressions") {
		var rels []string
		byRel := map[string][]map[string]any{}
		for _, ff := range ec.Proj.Files {
			for _, s := range ff.Suppressions {
				entry := map[string]any{
					"line": s.Line, "kind": s.Kind,
				}
				if len(s.Types) > 0 {
					entry["types"] = s.Types
				}
				if s.Reason != "" {
					entry["reason"] = s.Reason
				}
				if s.Used {
					entry["used"] = true
				}
				byRel[ff.Rel] = append(byRel[ff.Rel], entry)
			}
		}
		for r := range byRel {
			rels = append(rels, r)
		}
		sort.Strings(rels)
		for _, r := range rels {
			suppressions = append(suppressions, map[string]any{"path": r, "markers": byRel[r], "count": len(byRel[r])})
		}
	}

	if f.Format == "json" {
		root := map[string]any{
			"kind": "list", "schema_version": version.SchemaVersion,
			"version": version.Version,
		}
		if want("files") {
			root["files"] = files
			root["file_count"] = len(files)
		}
		if want("entry-points") {
			root["entry_points"] = entries
		}
		if want("boundaries") {
			root["boundaries"] = boundaries
		}
		if want("suppressions") {
			root["suppressions"] = suppressions
		}
		txt, _ := report.JSONStringIndent(root)
		writeOutput(f, txt)
		return 0
	}

	var b strings.Builder
	if want("files") {
		fmt.Fprintf(&b, "\n● Files (%d)\n", len(files))
		for _, m := range files {
			tag := ""
			if m["test"] == true {
				tag = " [test]"
			}
			fmt.Fprintf(&b, "  %-40s %s%s\n", m["path"], m["package"], tag)
		}
	}
	if want("entry-points") {
		fmt.Fprintf(&b, "\n● Entry points (%d)\n", len(entries))
		for _, m := range entries {
			fmt.Fprintf(&b, "  %-28s %s (%d files)\n", m["package"], m["kind"], len(m["files"].([]string)))
		}
		if len(entries) == 0 {
			b.WriteString("  none: no main packages and no config entries\n")
		}
	}
	if want("boundaries") && boundaries != nil {
		if !boundaries.Configured {
			b.WriteString("\n● Boundaries\n  not configured\n")
		} else {
			fmt.Fprintf(&b, "\n● Boundaries (%d zones%s)\n", len(boundaries.Zones), presetSuffix(boundaries.Preset))
			for _, z := range boundaries.Zones {
				fmt.Fprintf(&b, "  %-16s %2d files  %s\n", z.Name, z.Files, strings.Join(z.Patterns, ", "))
			}
			for _, r := range boundaries.Rules {
				rel := "allow: " + strings.Join(r.Allow, ", ")
				if len(r.Deny) > 0 {
					rel = "deny: " + strings.Join(r.Deny, ", ")
				}
				fmt.Fprintf(&b, "  rule %-14s → %s\n", r.From, rel)
			}
		}
	}
	if want("suppressions") {
		total := 0
		for _, m := range suppressions {
			total += m["count"].(int)
		}
		fmt.Fprintf(&b, "\n● Suppressions (%d markers in %d files)\n", total, len(suppressions))
		for _, m := range suppressions {
			fmt.Fprintf(&b, "  %s (%d)\n", m["path"], m["count"])
		}
	}
	if b.Len() == 0 {
		b.WriteString("nothing to list\n")
	}
	writeOutput(f, b.String())
	return 0
}

// presetSuffix labels the source preset when one is set.
func presetSuffix(preset string) string {
	if preset == "" {
		return ""
	}
	return ", preset " + preset
}
