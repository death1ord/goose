package architecture

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"goose/internal/config"
	"goose/internal/facts"
	"goose/internal/report"
)

// RulePack is a declarative policy pack listed in the rulePacks config key.
// Packs are pure data: loading one never executes project code.
type RulePack struct {
	Version     int        `json:"version"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Rules       []PackRule `json:"rules"`

	// source records where the pack was loaded from, for diagnostics.
	source string `json:"-"`
}

// PackRule is one declarative policy rule.
type PackRule struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Message  string   `json:"message"`
	Severity string   `json:"severity"`
	Zones    []string `json:"zones"`
	// banned-call
	Callees []string `json:"callees"`
	// banned-import
	Specifiers []string `json:"specifiers"`
	AllowNames []string `json:"allowNames"`
	// banned-export
	Exports []string `json:"exports"`

	// compiled matcher state
	compiled bool            `json:"-"`
	callSet  map[string]bool `json:"-"`
	importM  []namePattern   `json:"-"`
	exportM  []namePattern   `json:"-"`
}

// namePattern matches an import specifier or exported name: an exact path, a
// module prefix (a specifier that is a path prefix), or a glob.
type namePattern struct {
	raw  string
	glob bool
}

func (p namePattern) match(v string) bool {
	if p.glob {
		return config.MatchName(p.raw, v)
	}
	if v == p.raw {
		return true
	}
	// Module-prefix match: "gopkg.in/yaml" matches "gopkg.in/yaml.v3".
	if len(v) > len(p.raw) && strings.HasPrefix(v, p.raw) {
		if p.raw[len(p.raw)-1] == '/' || v[len(p.raw)] == '.' || isModuleSep(v[len(p.raw):]) {
			return true
		}
	}
	return false
}

func isModuleSep(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".v")
}

// validate checks the fields against the kind, like fallow's fail-loud rule
// pack loading.
func (r *PackRule) validate(pack string) error {
	switch r.Kind {
	case "banned-call":
		unused := firstNonEmpty(r.Specifiers, r.Exports)
		if unused != "" || len(r.AllowNames) > 0 {
			return fmt.Errorf("rule %s/%s: %q fields do not apply to banned-call", pack, r.ID, r.Kind)
		}
		if len(r.Callees) == 0 {
			return fmt.Errorf("rule %s/%s: banned-call needs callees", pack, r.ID)
		}
	case "banned-import":
		if len(r.Specifiers) == 0 {
			return fmt.Errorf("rule %s/%s: banned-import needs specifiers", pack, r.ID)
		}
		if len(r.Callees) > 0 || len(r.Exports) > 0 {
			return fmt.Errorf("rule %s/%s: callees/exports do not apply to banned-import", pack, r.ID)
		}
	case "banned-export":
		if len(r.Exports) == 0 {
			return fmt.Errorf("rule %s/%s: banned-export needs exports", pack, r.ID)
		}
		if len(r.Callees) > 0 || len(r.Specifiers) > 0 {
			return fmt.Errorf("rule %s/%s: callees/specifiers do not apply to banned-export", pack, r.ID)
		}
	case "banned-effect":
		return fmt.Errorf("rule %s/%s: banned-effect needs a JavaScript dependency catalogue and is not supported for Go", pack, r.ID)
	default:
		return fmt.Errorf("rule %s/%s: unknown kind %q", pack, r.ID, r.Kind)
	}
	if r.Severity != "" {
		if _, ok := config.ParseSeverity(r.Severity); !ok {
			return fmt.Errorf("rule %s/%s: invalid severity %q", pack, r.ID, r.Severity)
		}
	}
	return nil
}

func firstNonEmpty(lists ...[]string) string {
	for _, l := range lists {
		if len(l) > 0 {
			return l[0]
		}
	}
	return ""
}

func (r *PackRule) compile() {
	if r.compiled {
		return
	}
	r.compiled = true
	r.callSet = map[string]bool{}
	for _, c := range r.Callees {
		r.callSet[c] = true
	}
	r.importM = compilePatterns(r.Specifiers)
	r.exportM = compilePatterns(r.Exports)
}

func compilePatterns(list []string) []namePattern {
	out := make([]namePattern, 0, len(list))
	for _, p := range list {
		out = append(out, namePattern{raw: p, glob: strings.ContainsAny(p, "*?[{")})
	}
	return out
}

// LoadRulePacks reads every pack named in the config, relative to the config
// directory (then the project root). A missing or invalid pack is a load
// error: config validity gates the run with exit 2.
func LoadRulePacks(cfg *config.Config) ([]*RulePack, error) {
	base := cfg.Root
	if cfg.LoadedFrom != "" {
		base = filepath.Dir(cfg.LoadedFrom)
	}
	var out []*RulePack
	for _, src := range cfg.RulePacks {
		candidates := []string{src}
		if !filepath.IsAbs(src) {
			candidates = []string{filepath.Join(base, src), filepath.Join(cfg.Root, src)}
		}
		var found string
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				found = c
				break
			}
		}
		if found == "" {
			return nil, fmt.Errorf("goose: rule pack %q not found", src)
		}
		data, err := os.ReadFile(found)
		if err != nil {
			return nil, fmt.Errorf("goose: cannot read rule pack %s: %w", found, err)
		}
		raw, err := config.ParseJSONC(string(data))
		if err != nil {
			return nil, fmt.Errorf("goose: invalid rule pack %s: %w", found, err)
		}
		delete(raw, "$schema")
		delete(raw, "documentation")
		merged, err := json.Marshal(raw)
		if err != nil {
			return nil, err
		}
		pack := &RulePack{}
		decErr := json.Unmarshal(merged, pack)
		if decErr != nil {
			return nil, fmt.Errorf("goose: invalid rule pack %s: %w", found, decErr)
		}
		pack.source = found
		// Unknown fields fail the run: decode strictly by comparing keys.
		if bad := unknownPackKeys(raw); bad != "" {
			return nil, fmt.Errorf("goose: invalid rule pack %s: unknown field %q", found, bad)
		}
		if pack.Name == "" {
			pack.Name = strings.TrimSuffix(filepath.Base(found), filepath.Ext(found))
		}
		for i := range pack.Rules {
			rl := &pack.Rules[i]
			if rl.ID == "" {
				return nil, fmt.Errorf("goose: rule pack %s: rule %d has no id", found, i)
			}
			if err := rl.validate(pack.Name); err != nil {
				return nil, fmt.Errorf("goose: %w", err)
			}
			rl.compile()
		}
		out = append(out, pack)
	}
	return out, nil
}

var packTopKeys = map[string]bool{
	"$schema": true, "documentation": true, "version": true,
	"name": true, "description": true, "rules": true,
}

var packRuleKeys = map[string]bool{
	"id": true, "kind": true, "message": true, "severity": true, "zones": true,
	"callees": true, "specifiers": true, "allowNames": true, "exports": true,
}

func unknownPackKeys(raw map[string]any) string {
	for k := range raw {
		if !packTopKeys[k] {
			return k
		}
	}
	rules, _ := raw["rules"].([]any)
	for _, r := range rules {
		rm, _ := r.(map[string]any)
		for k := range rm {
			if !packRuleKeys[k] {
				return k
			}
		}
	}
	return ""
}

// policyViolations evaluates every loaded pack rule over the project.
func (a *Analysis) policyViolations(classified map[string]string, production bool) ([]*report.Finding, []report.Diag, error) {
	packs, err := LoadRulePacks(a.Cfg)
	if err != nil {
		return nil, nil, err
	}
	if len(packs) == 0 {
		return nil, nil, nil
	}
	master := a.Cfg.RuleSeverity("policy-violation", "")
	if master == config.Off {
		return nil, nil, nil
	}
	// exportedByPkg lists exported entity names per package for banned-export.
	exportedByPkg := map[string][]*facts.Entity{}
	for _, e := range a.Proj.Entities {
		if e.Exported && !e.Local && !e.TestFile {
			exportedByPkg[e.PkgPath] = append(exportedByPkg[e.PkgPath], e)
		}
	}
	var out []*report.Finding
	var diags []report.Diag
	for _, pack := range packs {
		for i := range pack.Rules {
			rl := &pack.Rules[i]
			sev := master
			if rl.Severity != "" {
				if s, ok := config.ParseSeverity(rl.Severity); ok {
					sev = s
				}
			}
			if sev == config.Off {
				continue
			}
			inZone := func(rel string) bool {
				if len(rl.Zones) == 0 {
					return true
				}
				z := classified[rel]
				for _, want := range rl.Zones {
					if z == want {
						return true
					}
				}
				return false
			}
			switch rl.Kind {
			case "banned-call":
				out = append(out, a.bannedCalls(pack, rl, sev, inZone, production)...)
			case "banned-import":
				out = append(out, a.bannedImports(pack, rl, sev, inZone, production)...)
			case "banned-export":
				out = append(out, a.bannedExports(pack, rl, sev, exportedByPkg, inZone)...)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Line < out[j].Line
	})
	return out, diags, nil
}

func (a *Analysis) bannedCalls(pack *RulePack, rl *PackRule, sev config.Severity, inZone func(string) bool, production bool) []*report.Finding {
	var out []*report.Finding
	for _, ff := range a.sortedFiles() {
		if ff.InTest && production {
			continue
		}

		if !inZone(ff.Rel) {
			continue
		}
		a.walkCalls(ff, func(name string, line, col int) {
			match := rl.callSet[name]
			if !match {
				// wildcard like "os.*"
				if i := strings.Index(name, "."); i > 0 {
					match = rl.callSet[name[:i]+".*"]
				}
			}
			if !match {
				return
			}
			rel := ff.Rel
			out = append(out, &report.Finding{
				Kind: "policy-violation", Rule: "policy-violation",
				Path: rel, Line: line, Col: col,
				Message:  policyMessage(rl, fmt.Sprintf("call %s", name)),
				Severity: sev,
				ID:       report.Fingerprint("policy-violation", rel, pack.Name+"/"+rl.ID, fmt.Sprint(line)),
				Extra: map[string]any{
					"pack": pack.Name, "rule_id": rl.ID, "matched": name,
					"rule": "policy-violation:" + pack.Name + "/" + rl.ID,
				},
			})
		})
	}
	return out
}

// walkCalls visits every call expression in a file, resolving the callee to a
// selector name like "os.Exit" or a bare name like "eval".
func (a *Analysis) walkCalls(ff *facts.FileFacts, fn func(name string, line, col int)) {
	fset := a.Proj.Fset
	if fset == nil {
		fset = token.NewFileSet()
		a.Proj.Fset = fset
	}
	tree := a.Syntax[ff.Path]
	if tree == nil && ff.Src != "" {
		if parsed, err := parser.ParseFile(fset, ff.Path, ff.Src, 0); err == nil {
			tree = parsed
			if a.Syntax != nil {
				a.Syntax[ff.Path] = tree
			}
		}
	}
	if tree == nil {
		return
	}
	ast.Inspect(tree, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch callee := ce.Fun.(type) {
		case *ast.SelectorExpr:
			if id, ok := callee.X.(*ast.Ident); ok {
				name = id.Name + "." + callee.Sel.Name
			}
		case *ast.Ident:
			name = callee.Name
		}
		if name == "" {
			return true
		}
		pos := fset.Position(ce.Pos())
		fn(name, pos.Line, pos.Column-1)
		return true
	})
}

func (a *Analysis) bannedImports(pack *RulePack, rl *PackRule, sev config.Severity, inZone func(string) bool, production bool) []*report.Finding {
	var out []*report.Finding
	for _, ff := range a.sortedFiles() {
		if ff.InTest && production {
			continue
		}
		if !inZone(ff.Rel) {
			continue
		}
		for _, imp := range ff.Imports {
			matched := false
			for _, p := range rl.importM {
				if p.match(imp.Path) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			if len(rl.AllowNames) > 0 && imp.Name != "" && contains(rl.AllowNames, imp.Name) {
				continue
			}
			out = append(out, &report.Finding{
				Kind: "policy-violation", Rule: "policy-violation",
				Path: ff.Rel, Line: imp.Line, Col: imp.Col,
				Message:  policyMessage(rl, fmt.Sprintf("import %s", imp.Path)),
				Severity: sev,
				ID:       report.Fingerprint("policy-violation", ff.Rel, pack.Name+"/"+rl.ID, imp.Path),
				Extra: map[string]any{
					"pack": pack.Name, "rule_id": rl.ID, "matched": imp.Path,
					"rule": "policy-violation:" + pack.Name + "/" + rl.ID,
				},
			})
		}
	}
	return out
}

func (a *Analysis) bannedExports(pack *RulePack, rl *PackRule, sev config.Severity, exportedByPkg map[string][]*facts.Entity, inZone func(string) bool) []*report.Finding {
	var out []*report.Finding
	var pkgs []string
	for pkg := range exportedByPkg {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)
	for _, pkg := range pkgs {
		ents := exportedByPkg[pkg]
		sort.Slice(ents, func(i, j int) bool { return ents[i].Name < ents[j].Name })
		for _, e := range ents {
			matched := false
			for _, p := range rl.exportM {
				if p.match(e.Name) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			rel := ""
			if sp, ok := a.firstSpan(e); ok {
				rel = a.Proj.Files[sp.File].Rel
				if !inZone(rel) {
					continue
				}
				out = append(out, &report.Finding{
					Kind: "policy-violation", Rule: "policy-violation",
					Path: rel, Line: sp.StartLine,
					Message:  policyMessage(rl, fmt.Sprintf("export %s", e.Name)),
					Severity: sev,
					ID:       report.Fingerprint("policy-violation", rel, pack.Name+"/"+rl.ID, e.Name),
					Extra: map[string]any{
						"pack": pack.Name, "rule_id": rl.ID, "matched": e.Name,
						"symbol": e.Name,
						"rule":   "policy-violation:" + pack.Name + "/" + rl.ID,
					},
				})
			}
		}
	}
	return out
}

func (a *Analysis) firstSpan(e *facts.Entity) (facts.Span, bool) {
	spans := a.Proj.EntitySpans[e.Key]
	if len(spans) == 0 {
		return facts.Span{}, false
	}
	return spans[0], true
}

func policyMessage(rl *PackRule, what string) string {
	if rl.Message != "" {
		return what + ": " + rl.Message
	}
	return "Policy rule " + rl.ID + " forbids this: " + what
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
