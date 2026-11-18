package architecture

import (
	"fmt"
	"sort"
	"strings"

	"goose/internal/config"
	"goose/internal/facts"
	"goose/internal/report"
)

// zone is a resolved architecture boundary zone.
type zone struct {
	name     string
	patterns []string
}

// resolveZones expands the preset and the user zones into an ordered list.
// A preset provides base zones; user zones then override or add to them by
// name, matching fallow's preset + custom merge.
func (a *Analysis) resolveZones() ([]zone, error) {
	var out []zone
	seen := map[string]int{}
	add := func(z zone) {
		if i, ok := seen[z.name]; ok {
			out[i] = z
			return
		}
		seen[z.name] = len(out)
		out = append(out, z)
	}
	if a.Cfg.Boundaries.Preset != "" {
		ps, ok := presetZones(a.Cfg.Boundaries.Preset)
		if !ok {
			return nil, fmt.Errorf("goose: unknown boundaries.preset %q (want layered, hexagonal, feature-sliced, or bulletproof)", a.Cfg.Boundaries.Preset)
		}
		for _, z := range ps {
			add(z)
		}
	}
	for _, z := range a.Cfg.Boundaries.Zones {
		add(zone{name: z.Name, patterns: z.Patterns})
	}
	return out, nil
}

// presetZones returns the documented zone sets, adapted to Go layouts. Every
// zone lists the glob patterns that classify a file into it.
func presetZones(name string) ([]zone, bool) {
	switch name {
	case "layered":
		return []zone{
			{name: "domain", patterns: []string{"**/domain/**", "**/core/**"}},
			{name: "application", patterns: []string{"**/application/**", "**/service/**", "**/services/**", "**/usecase/**", "**/usecases/**"}},
			{name: "infrastructure", patterns: []string{"**/infrastructure/**", "**/repository/**", "**/repositories/**", "**/storage/**", "**/db/**", "**/persistence/**"}},
			{name: "interfaces", patterns: []string{"**/interfaces/**", "**/api/**", "**/handler/**", "**/handlers/**", "**/controller/**", "**/controllers/**", "**/transport/**", "**/delivery/**", "**/ui/**", "**/web/**"}},
		}, true
	case "hexagonal":
		return []zone{
			{name: "domain", patterns: []string{"**/domain/**", "**/core/**"}},
			{name: "ports", patterns: []string{"**/port/**", "**/ports/**", "**/gateway/**", "**/gateways/**"}},
			{name: "adapters", patterns: []string{"**/adapter/**", "**/adapters/**", "**/driver/**", "**/drivers/**", "**/infrastructure/**"}},
		}, true
	case "feature-sliced":
		return []zone{
			{name: "app", patterns: []string{"**/app/**"}},
			{name: "features", patterns: []string{"**/features/**"}},
			{name: "entities", patterns: []string{"**/entities/**"}},
			{name: "shared", patterns: []string{"**/shared/**", "**/common/**", "**/pkg/**", "**/internal/util/**"}},
		}, true
	case "bulletproof":
		return []zone{
			{name: "app", patterns: []string{"**/app/**"}},
			{name: "pages", patterns: []string{"**/pages/**", "**/routes/**", "**/cmd/**"}},
			{name: "widgets", patterns: []string{"**/widgets/**"}},
			{name: "features", patterns: []string{"**/features/**"}},
			{name: "entities", patterns: []string{"**/entities/**", "**/domain/**"}},
			{name: "shared", patterns: []string{"**/shared/**", "**/pkg/**", "**/internal/**"}},
		}, true
	}
	return nil, false
}

// presetRules returns the default from→allow matrix for a preset. User rules
// (boundaries.rules) take precedence when they name the same from-zone.
func presetRules(preset string) []config.BoundaryRule {
	switch preset {
	case "layered":
		return []config.BoundaryRule{
			{From: "domain", Allow: []string{"domain"}},
			{From: "application", Allow: []string{"domain", "application", "ports"}},
			{From: "infrastructure", Allow: []string{"domain", "application", "ports", "infrastructure"}},
			{From: "interfaces", Allow: []string{"domain", "application", "infrastructure", "interfaces"}},
		}
	case "hexagonal":
		return []config.BoundaryRule{
			{From: "domain", Allow: []string{"domain"}},
			{From: "ports", Allow: []string{"domain", "ports"}},
			{From: "adapters", Allow: []string{"domain", "ports", "adapters"}},
		}
	case "feature-sliced", "bulletproof":
		return []config.BoundaryRule{
			{From: "app", Allow: []string{"*"}},
			{From: "pages", Allow: []string{"*"}},
			{From: "widgets", Allow: []string{"features", "entities", "shared"}},
			{From: "features", Allow: []string{"entities", "shared"}},
			{From: "entities", Allow: []string{"shared"}},
			{From: "shared", Allow: []string{}},
		}
	}
	return nil
}

// classify returns the zone whose patterns match a module-relative path,
// scanning zones in declaration order (first match wins).
func classify(zones []zone, rel string) string {
	for _, z := range zones {
		for _, p := range z.patterns {
			if config.MatchPath(p, rel) {
				return z.name
			}
		}
	}
	return ""
}

// effectiveRules merges user rules over preset rules by from-zone.
func (a *Analysis) effectiveRules(zones []zone) []config.BoundaryRule {
	base := presetRules(a.Cfg.Boundaries.Preset)
	byFrom := map[string]config.BoundaryRule{}
	var order []string
	put := func(r config.BoundaryRule) {
		if _, ok := byFrom[r.From]; !ok {
			order = append(order, r.From)
		}
		byFrom[r.From] = r
	}
	for _, r := range base {
		put(r)
	}
	for _, r := range a.Cfg.Boundaries.Rules {
		put(r)
	}
	sort.Strings(order)
	out := make([]config.BoundaryRule, 0, len(order))
	for _, f := range order {
		out = append(out, byFrom[f])
	}
	return out
}

// allowed reports whether a→b import is permitted by the rule matrix. A zone
// with no rule defaults to allowing everything; a rule with an empty allow
// list (only a "shared"-style leaf) allows nothing but its own deny set.
func (a *Analysis) allowed(rules []config.BoundaryRule, from, to string) (bool, string) {
	if from == "" || to == "" || from == to {
		return true, ""
	}
	var matched *config.BoundaryRule
	for i := range rules {
		if rules[i].From == from {
			matched = &rules[i]
			break
		}
	}
	if matched == nil {
		return true, ""
	}
	for _, d := range matched.Deny {
		if d == "*" || d == to {
			return false, "denied"
		}
	}
	for _, al := range matched.Allow {
		if al == "*" || al == to {
			return true, ""
		}
	}
	return false, "not allowed"
}

// boundaryViolations reports zone-crossing imports. Zone membership is
// per-file; a package's zone for an import edge is the zone of any zoned
// production file in the target package (packages rarely span zones).
func (a *Analysis) boundaryViolations(classified map[string]string) []*report.Finding {
	sev := a.Cfg.RuleSeverity("boundary-violation", "")
	if sev == config.Off {
		return nil
	}
	rules := a.effectiveRules(nil)
	// pkgZones collects the zones each package appears in, in file order.
	pkgZones := map[string][]string{}
	for _, ff := range a.sortedFiles() {
		if ff.InTest {
			continue
		}
		z := classified[ff.Rel]
		if z == "" {
			continue
		}
		list := pkgZones[ff.PkgPath]
		found := false
		for _, x := range list {
			if x == z {
				found = true
				break
			}
		}
		if !found {
			pkgZones[ff.PkgPath] = append(list, z)
		}
	}
	// zoneFile picks a representative file of a package in a zone.
	zoneFile := func(pkg, wantZone string) string {
		for _, ff := range a.sortedFiles() {
			if ff.PkgPath == pkg && !ff.InTest && classified[ff.Rel] == wantZone {
				return ff.Rel
			}
		}
		return ""
	}
	var out []*report.Finding
	for _, ff := range a.sortedFiles() {
		if ff.InTest {
			continue
		}
		fromZone := classified[ff.Rel]
		if fromZone == "" {
			continue // only zoned files are checked
		}
		for _, imp := range ff.Imports {
			for _, toZone := range pkgZones[imp.Path] {
				if toZone == fromZone {
					continue
				}
				if ok2, _ := a.allowed(rules, fromZone, toZone); ok2 {
					continue
				}
				id := report.Fingerprint("boundary-violation", ff.Rel, imp.Path, fromZone, toZone)
				out = append(out, &report.Finding{
					Kind: "boundary-violation", Rule: "boundary-violation",
					Path: ff.Rel, Line: imp.Line, Col: imp.Col,
					Message:  fmt.Sprintf("Zone %q must not import %q (%s).", fromZone, toZone, imp.Path),
					Severity: sev,
					ID:       id,
					Extra: map[string]any{
						"from_path": ff.Rel, "from_zone": fromZone,
						"to_zone": toZone, "to_path": zoneFile(imp.Path, toZone),
						"package": imp.Path,
					},
					Actions: []report.Action{{
						Type: "remove-import", AutoFixable: false,
						Description: "Move shared code to a package both zones may import.",
					}},
				})
			}
		}
	}
	return out
}

// boundaryCoverage reports production files that match no zone.
func (a *Analysis) boundaryCoverage(classified map[string]string, production bool) []*report.Finding {
	sev := a.Cfg.RuleSeverity("boundary-violation", "")
	if sev == config.Off {
		return nil
	}
	allow := a.Cfg.Boundaries.Coverage.AllowUnmatched
	var out []*report.Finding
	for _, ff := range a.sortedFiles() {
		if ff.InTest && production {
			continue
		}
		if _, zoned := classified[ff.Rel]; zoned {
			continue
		}
		exempt := false
		for _, p := range allow {
			if config.MatchPath(p, ff.Rel) {
				exempt = true
				break
			}
		}
		if exempt {
			continue
		}
		out = append(out, &report.Finding{
			Kind: "boundary-coverage", Rule: "boundary-violation",
			Path:     ff.Rel,
			Message:  "This file matches no architecture boundary zone.",
			Severity: sev,
			ID:       report.Fingerprint("boundary-coverage", ff.Rel),
		})
	}
	return out
}

// deepImports reports imports that bypass a package root to reach deep into
// another subtree (either a non-root subpackage of a configured public package
// or a module subpackage >= 3 levels deep outside the importer's subtree).
func (a *Analysis) deepImports(production bool) []*report.Finding {
	if !a.Cfg.RuleEnabled("deep-import") {
		return nil
	}
	mod := a.Proj.Module.Path
	var out []*report.Finding
	for _, ff := range a.sortedFiles() {
		if ff.InTest && production {
			continue
		}
		sev := a.Cfg.RuleSeverity("deep-import", ff.Rel)
		if sev == config.Off {
			continue
		}
		fromSub := topSubtree(mod, ff.PkgPath)
		for _, imp := range ff.Imports {
			if imp.Path == ff.PkgPath {
				continue
			}
			isDeep := false
			for _, pub := range a.Cfg.PublicPackages {
				pubPkg := pub
				if mod != "" && !strings.HasPrefix(pub, mod) {
					pubPkg = mod + "/" + strings.TrimPrefix(pub, "./")
				}
				if strings.HasPrefix(imp.Path, pubPkg+"/") && !strings.HasPrefix(ff.PkgPath, pubPkg) {
					isDeep = true
					break
				}
			}
			if !isDeep && mod != "" && strings.HasPrefix(imp.Path, mod+"/") {
				toSub := topSubtree(mod, imp.Path)
				if toSub != "" && toSub != fromSub && subtreeDepth(mod, imp.Path) >= 3 {
					isDeep = true
				}
			}
			if !isDeep {
				continue
			}
			out = append(out, &report.Finding{
				Kind: "deep-import", Rule: "deep-import",
				Path: ff.Rel, Line: imp.Line, Col: imp.Col,
				Message:  fmt.Sprintf("Deep import %q bypasses top-level package boundary", imp.Path),
				Severity: sev,
				ID:       report.Fingerprint("deep-import", ff.Rel, imp.Path),
				Extra: map[string]any{
					"specifier": imp.Path,
					"package":   imp.Path,
				},
			})
		}
	}
	return out
}

func topSubtree(mod, pkgPath string) string {
	rel := strings.TrimPrefix(pkgPath, mod+"/")
	if rel == pkgPath || rel == "" {
		return ""
	}
	parts := strings.Split(rel, "/")
	if parts[0] == "internal" || parts[0] == "pkg" {
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
	}
	return parts[0]
}

func subtreeDepth(mod, pkgPath string) int {
	rel := strings.TrimPrefix(pkgPath, mod+"/")
	if rel == pkgPath || rel == "" {
		return 0
	}
	parts := strings.Split(rel, "/")
	if parts[0] == "internal" && len(parts) > 1 {
		return len(parts) - 1
	}
	return len(parts)
}

// sortedFiles lists production+test file facts in a stable order.
func (a *Analysis) sortedFiles() []*facts.FileFacts {
	out := make([]*facts.FileFacts, 0, len(a.Proj.Files))
	for _, ff := range a.Proj.Files {
		out = append(out, ff)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out
}

// absOf maps a module-relative path back to the absolute key used in files.
func (a *Analysis) absOf(rel string) string {
	for abs, ff := range a.Proj.Files {
		if ff.Rel == rel {
			return abs
		}
	}
	if i := strings.LastIndex(rel, "/"); i >= 0 && strings.HasPrefix(rel, "/") {
		return rel
	}
	return a.Cfg.Root + "/" + rel
}
