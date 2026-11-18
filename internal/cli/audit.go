package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"goose/internal/config"
	"goose/internal/deadcode"
	"goose/internal/dupes"
	"goose/internal/engine"
	"goose/internal/gitx"
	"goose/internal/health"
	"goose/internal/report"
	"goose/internal/version"
)

// auditVerdict is the pass/warn/fail decision of one audit run.
type auditVerdict string

const (
	verdictPass auditVerdict = "pass"
	verdictWarn auditVerdict = "warn"
	verdictFail auditVerdict = "fail"
)

// runAudit implements goose audit: the changed-file quality gate combining
// dead-code, complexity, and duplication, mirroring fallow's audit contract.
func runAudit(ctx context.Context, f *Flags) int {
	if f.Baseline != "" || f.SaveBaseline != "" {
		fmt.Fprintln(os.Stderr, "goose: audit does not support --baseline/--save-baseline; use --dead-code-baseline, --health-baseline, or --dupes-baseline")
		return 2
	}
	if f.GroupBy != "" {
		fmt.Fprintln(os.Stderr, "goose: audit does not support --group-by")
		return 2
	}
	brief := f.BoolExtra["--brief"]
	start := time.Now()

	ec, cfg, err := runContext(ctx, f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}

	gate := ec.Cfg.Audit.Gate
	if f.Extra["--gate"] != "" {
		gate = f.Extra["--gate"]
	}
	if gate == "" {
		gate = "new-only"
	}
	if gate != "new-only" && gate != "all" {
		return usage(ErrUsage{"--gate must be new-only or all"})
	}
	worsened := ec.Cfg.Audit.Worsened
	if f.Extra["--worsened"] != "" {
		worsened = f.Extra["--worsened"]
	}
	if worsened == "" {
		worsened = "warn"
	}
	if worsened != "warn" && worsened != "error" && worsened != "off" {
		return usage(ErrUsage{"--worsened must be warn, error, or off"})
	}

	dcBaseline := ec.Cfg.Audit.DeadCodeBaseline
	if p := aPath(f, "--dead-code-baseline"); p != "" {
		dcBaseline = p
	}
	hBaseline := ec.Cfg.Audit.HealthBaseline
	if p := aPath(f, "--health-baseline"); p != "" {
		hBaseline = p
	}
	dupBaseline := ec.Cfg.Audit.DupesBaseline
	if p := aPath(f, "--dupes-baseline"); p != "" {
		dupBaseline = p
	}

	repo := gitx.Open(cfg.Root)
	if !repo.Inside || !gitx.Available() {
		fmt.Fprintln(os.Stderr, "goose: audit needs a git repository")
		return 2
	}
	baseRef := f.ChangedSince
	baseDesc := "--base"
	if baseRef == "" {
		baseRef = os.Getenv("GOOSE_AUDIT_BASE")
		baseDesc = "GOOSE_AUDIT_BASE"
	}
	if baseRef == "" {
		baseRef, err = repo.DefaultBase()
		baseDesc = "merge-base with default branch"
		if err != nil || baseRef == "" {
			fmt.Fprintln(os.Stderr, "goose: cannot resolve an audit base; pass --base")
			return 2
		}
	}
	if !repo.ResolveRef(baseRef) {
		fmt.Fprintf(os.Stderr, "goose: invalid base ref %q\n", baseRef)
		return 2
	}
	mergeBase, err := repo.MergeBase(baseRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "goose: merge-base with %s failed: %v\n", baseRef, err)
		return 2
	}
	changed, err := repo.ChangedFiles(baseRef)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		return 2
	}
	changedSet := map[string]bool{}
	for _, p := range changed {
		changedSet[p] = true
	}

	prodDC := f.Production || f.ProductionDC || f.BoolExtra["--production-dead-code"] || cfg.ProdFor("dead-code")
	prodH := f.Production || f.ProductionH || f.BoolExtra["--production-health"] || cfg.ProdFor("health")
	prodDup := f.Production || f.ProductionDupes || f.BoolExtra["--production-dupes"] || cfg.ProdFor("dupes")

	// --- dead-code over the whole tree, scoped to changed files. ---
	var dcFindings []*report.Finding
	dcSkipped := contains(f.Skip, "dead-code")
	if !dcSkipped && ec.Cfg.Audit.DeadCode != nil && !*ec.Cfg.Audit.DeadCode {
		dcSkipped = true
	}
	if !dcSkipped {
		doc := ec.DeadCode(deadcode.Options{
			Production:          prodDC,
			IncludeEntryExports: f.IncludeEntryExports || cfg.IncludeEntryExports,
		})
		if code := mergeArchitecture(f, ec, cfg, doc); code != 0 {
			return code
		}
		dcFindings = doc.Findings
		if dcBaseline != "" {
			b, err := deadcode.LoadBaseline(dcBaseline)
			if err != nil {
				fmt.Fprintln(os.Stderr, "goose:", err)
				return 2
			}
			dcFindings, _, _ = deadcode.SplitBaseline(dcFindings, b)
		}
	}
	var dcScoped []*report.Finding
	for _, x := range dcFindings {
		if !x.Hidden && changedSet[x.Path] {
			dcScoped = append(dcScoped, x)
		}
	}

	// --- complexity (health findings only), scoped to changed files. ---
	complexScoped := []*report.Finding(nil)
	healthSkipped := contains(f.Skip, "health")
	if !healthSkipped && ec.Cfg.Audit.Health != nil && !*ec.Cfg.Audit.Health {
		healthSkipped = true
	}
	var complexAll []health.Finding
	if !healthSkipped {
		res := ec.Health(engine.HealthInput{
			Options:  health.Options{Complexity: true, Production: prodH},
			Coverage: f.Extra["--coverage"],
		})
		complexAll = res.Findings
		for _, hf := range res.Findings {
			if len(hf.Exceeded) == 0 || !changedSet[hf.Path] {
				continue
			}
			sev := report.HealthFindingSeverity(cfg, hf)
			complexScoped = append(complexScoped, complexityFinding(hf, sev))
		}
		if hBaseline != "" {
			complexScoped = filterHealthBaseline(complexScoped, hBaseline)
		}
	}

	// --- dupes restricted to groups with a changed instance. ---
	dupRes := (*dupes.Result)(nil)
	dupesSkipped := contains(f.Skip, "dupes")
	if !dupesSkipped && ec.Cfg.Audit.Dupes != nil && !*ec.Cfg.Audit.Dupes {
		dupesSkipped = true
	}
	if !dupesSkipped {
		opts := dupes.FromConfig(cfg)
		if prodDup {
			opts.Ignore = prodDupIgnore(cfg)
		}
		dupRes = ec.Dupes(opts, changedSet)
		if dupBaseline != "" {
			b, err := dupes.LoadBaseline(dupBaseline)
			if err != nil {
				fmt.Fprintln(os.Stderr, "goose:", err)
				return 2
			}
			dupes.ApplyBaseline(dupRes, b)
		}
		if dupRes != nil && cfg.RuleEnabled("diverged-clone-sibling") {
			dcScoped = append(dcScoped, dupes.DivergedCloneSiblings(dupRes.Groups, changedSet, cfg)...)
		}
	}

	// --- attribution: which findings did the changeset introduce? ---
	attr := auditAttribution{Gate: gate, Worsened: worsened}
	dupIntroduced := map[string]bool{}
	baseSkipped := false
	if gate == "new-only" && (len(dcScoped) > 0 || len(complexScoped) > 0 || (dupRes != nil && len(dupRes.Groups) > 0)) {
		base, err := baseSnapshot(ctx, cfg, mergeBase)
		if err != nil {
			baseSkipped = true
			if !f.Quiet {
				fmt.Fprintf(os.Stderr, "Note: base snapshot unavailable (%v); every finding counts as introduced.\n", err)
			}
		} else {
			annotateIntroducedDC(dcScoped, &attr, base.dcKeys)
			annotateIntroducedComplex(complexScoped, &attr, base.complexKeys, base.complexCC, worsened)
			if dupRes != nil {
				for i := range dupRes.Groups {
					key := dupRes.Groups[i].Fingerprint + ":" + strconv.Itoa(len(dupRes.Groups[i].Instances))
					intro := !base.dupKeys[key]
					dupIntroduced[dupRes.Groups[i].Fingerprint] = intro
					if intro {
						attr.DupIntroduced++
					} else {
						attr.DupInherited++
					}
				}
			}
		}
	}

	summary, verdict := auditDecide(dcScoped, complexScoped, dupRes, gate, worsened, f.FailOnIssues)
	elapsed := time.Since(start).Milliseconds()

	cmd := "audit"
	if brief {
		cmd = "review"
	}
	out := auditOutput{
		Version:             version.Version,
		Command:             cmd,
		SchemaVersion:       7,
		Verdict:             string(verdict),
		ChangedFilesCount:   len(changed),
		BaseRef:             mergeBase,
		BaseDescription:     baseDesc + " " + baseRef,
		HeadSHA:             repo.CurrentSHA(),
		ElapsedMS:           elapsed,
		Summary:             summary,
		Attribution:         attr,
		ChangedFiles:        changed,
		BaseSnapshotSkipped: baseSkipped,
	}

	// Machine formats get the full envelope built from sub-sections.
	if f.Format == "json" {
		out.DeadCode = dcSub(dcScoped, dcSkipped)
		out.Complexity = complexSub(complexScoped, complexAll, healthSkipped)
		if dupRes != nil {
			out.Duplication = dupSub(dupRes, dupesSkipped)
		} else {
			out.Duplication = map[string]any{"skipped": true}
		}
		txt, _ := report.JSONStringIndent(out)
		writeOutput(f, txt)
	} else if f.Format == "human" || f.Format == "" {
		writeOutput(f, auditHuman(f, out, dcScoped, complexScoped, dupRes, dupIntroduced, elapsed))
	} else {
		// Everything else: aggregate findings into a normal doc and render it.
		doc := report.NewDoc("audit")
		doc.Envelope["kind"] = "audit"
		doc.Envelope["schema_version"] = 7
		doc.Envelope["verdict"] = string(verdict)
		doc.Envelope["command"] = "audit"
		doc.Envelope["changed_files_count"] = len(changed)
		doc.Envelope["base_ref"] = mergeBase
		doc.Envelope["head_sha"] = out.HeadSHA
		doc.Envelope["attribution"] = attr
		doc.ElapsedMS = elapsed
		doc.Findings = append(doc.Findings, dcScoped...)
		doc.Findings = append(doc.Findings, complexScoped...)
		doc.Summary = map[string]any{
			"total_issues": len(dcScoped) + len(complexScoped),
		}
		if dupRes != nil {
			doc.Findings = append(doc.Findings, dupRes.Doc(0, f.FailOnIssues, true, 0).Findings...)
			doc.Summary["duplication_clone_groups"] = dupRes.Stats.CloneGroups
		}
		doc.Gates["audit-verdict"] = &report.Gate{
			Status: verdictGate(verdict), Enforced: !brief,
			Observed: summary, Threshold: gate,
		}
		code := emit(f, doc, cfg.Root, false)
		if brief && code == 1 {
			return 0 // the review surface is advisory and never fails
		}
		return code
	}

	if !f.Quiet && f.Format != "json" {
		label := "audit"
		if brief {
			label = "review"
		}
		mark := "✓"
		if verdict == verdictFail {
			mark = "✗"
		} else if verdict == verdictWarn {
			mark = "⚠"
		}
		if brief && verdict == verdictFail {
			// Review is advisory: report the verdict but keep the run green.
			mark = "⚠"
		}
		fmt.Fprintf(os.Stderr, "%s %s %s · %d changed files (%.2fs)\n", mark, label, verdict, len(changed), float64(elapsed)/1000)
	}
	if verdict == verdictFail && !brief {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// Base snapshot via detached worktree.
// ---------------------------------------------------------------------------

type snapshot struct {
	dcKeys      map[string]bool
	complexKeys map[string]bool
	complexCC   map[string]int // path:name -> cyclomatic, for --worsened
	dupKeys     map[string]bool
}

// baseSnapshot analyzes the merge-base commit in a detached worktree.
func baseSnapshot(ctx context.Context, cfg *config.Config, mergeBase string) (*snapshot, error) {
	tmp, err := os.MkdirTemp("", "goose-base-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	repo := gitx.Open(cfg.Root)
	cleanup, err := repo.Worktree(tmp, mergeBase)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	baseCfg := *cfg
	baseCfg.Root = tmp
	ec, err := engine.LoadAndBuild(ctx, &baseCfg, false)
	if err != nil {
		return nil, err
	}
	s := &snapshot{
		dcKeys:      map[string]bool{},
		complexKeys: map[string]bool{},
		complexCC:   map[string]int{},
		dupKeys:     map[string]bool{},
	}
	doc := ec.DeadCode(deadcode.Options{})
	for _, x := range doc.Findings {
		if !x.Hidden {
			s.dcKeys[deadcode.BaselineKey(x)] = true
		}
	}
	res := ec.Health(engine.HealthInput{Options: health.Options{Complexity: true}})
	for _, hf := range res.Findings {
		if len(hf.Exceeded) == 0 {
			continue
		}
		s.complexKeys[hf.Path+"|"+hf.Name] = true
		s.complexCC[hf.Path+"|"+hf.Name] = hf.Cyclomatic
	}
	dres := ec.Dupes(dupes.FromConfig(cfg), nil)
	for _, g := range dres.Groups {
		s.dupKeys[g.Fingerprint+":"+strconv.Itoa(len(g.Instances))] = true
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// Attribution.
// ---------------------------------------------------------------------------

type auditAttribution struct {
	Gate          string `json:"gate"`
	Worsened      string `json:"worsened,omitempty"`
	DCIntroduced  int    `json:"dead_code_introduced"`
	DCInherited   int    `json:"dead_code_inherited"`
	CXIntroduced  int    `json:"complexity_introduced"`
	CXInherited   int    `json:"complexity_inherited"`
	CXWorsened    int    `json:"complexity_worsened,omitempty"`
	DupIntroduced int    `json:"duplication_introduced"`
	DupInherited  int    `json:"duplication_inherited"`
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// annotateIntroducedDC marks dead-code findings introduced when their
// baseline key is absent from the base snapshot and counts both buckets.
func annotateIntroducedDC(fs []*report.Finding, attr *auditAttribution, baseKeys map[string]bool) {
	for _, x := range fs {
		intro := !baseKeys[deadcode.BaselineKey(x)]
		x.Extra["introduced"] = intro
		if intro {
			attr.DCIntroduced++
		} else {
			attr.DCInherited++
		}
	}
}

// annotateIntroducedComplex does the same for complexity findings, applying
// the --worsened rule to inherited ones whose value grew.
func annotateIntroducedComplex(fs []*report.Finding, attr *auditAttribution, baseKeys map[string]bool, baseCC map[string]int, worsened string) {
	for _, x := range fs {
		key := x.Path + "|" + fmt.Sprint(x.Extra["name"])
		intro := !baseKeys[key]
		x.Extra["introduced"] = intro
		if intro {
			attr.CXIntroduced++
			continue
		}
		attr.CXInherited++
		if applyWorsened(x, baseCC, worsened) {
			attr.CXWorsened++
		}
	}
}

// applyWorsened upgrades an inherited complexity finding whose cyclomatic
// value grew since the base, per the --worsened mode. It reports whether the
// finding worsened.
func applyWorsened(x *report.Finding, baseCC map[string]int, worsened string) bool {
	key := x.Path + "|" + fmt.Sprint(x.Extra["name"])
	now, _ := x.Extra["cyclomatic"].(int)
	was, ok := baseCC[key]
	if !ok || now <= was {
		return false
	}
	x.Extra["worsened"] = true
	x.Extra["base_cyclomatic"] = was
	switch worsened {
	case "error":
		x.Extra["introduced"] = true
		x.Severity = config.Error
	case "warn":
		x.Severity = config.Warn
	}
	return true
}

// ---------------------------------------------------------------------------
// Decision.
// ---------------------------------------------------------------------------

func auditDecide(dc, cx []*report.Finding, dup *dupes.Result, gate, worsened string, failOnIssues bool) (map[string]any, auditVerdict) {
	introError := func(fs []*report.Finding) int {
		n := 0
		for _, x := range fs {
			enforce := gate == "all" || x.Extra["introduced"] == true
			enforce = enforce || (x.Extra["worsened"] == true && worsened == "error")
			if enforce && x.Severity == config.Error {
				n++
			}
		}
		return n
	}
	warnN := 0
	errN := introError(dc) + introError(cx)
	for _, x := range append(append([]*report.Finding{}, dc...), cx...) {
		if x.Severity == config.Warn && (gate == "all" || x.Extra["introduced"] == true || x.Extra["worsened"] == true) {
			warnN++
		}
	}
	groups, dupDup := 0, 0.0
	dupIntroErr := false
	if dup != nil {
		groups = dup.Stats.CloneGroups
		dupDup = dup.Stats.DuplicationPercentage
		if gate == "all" && groups > 0 {
			dupIntroErr = failOnIssues
		}
	}
	summary := map[string]any{
		"dead_code_issues":         visibleCount(dc),
		"dead_code_has_errors":     introError(dc) > 0,
		"complexity_findings":      len(cx),
		"duplication_clone_groups": groups,
		"duplication_percentage":   dupDup,
	}
	verdict := verdictPass
	if warnN > 0 {
		verdict = verdictWarn
	}
	if errN > 0 || dupIntroErr {
		verdict = verdictFail
	}
	return summary, verdict
}

func visibleCount(fs []*report.Finding) int {
	n := 0
	for _, x := range fs {
		if !x.Hidden {
			n++
		}
	}
	return n
}

func verdictGate(v auditVerdict) string {
	if v == verdictFail {
		return "failed"
	}
	return "passed"
}

// ---------------------------------------------------------------------------
// Output.
// ---------------------------------------------------------------------------

type auditOutput struct {
	Kind                string           `json:"kind"`
	Version             string           `json:"version"`
	SchemaVersion       int              `json:"schema_version"`
	Command             string           `json:"command"`
	Verdict             string           `json:"verdict"`
	ChangedFilesCount   int              `json:"changed_files_count"`
	BaseRef             string           `json:"base_ref"`
	BaseDescription     string           `json:"base_description"`
	HeadSHA             string           `json:"head_sha"`
	ElapsedMS           int64            `json:"elapsed_ms"`
	Summary             map[string]any   `json:"summary"`
	Attribution         auditAttribution `json:"attribution"`
	ChangedFiles        []string         `json:"changed_files"`
	BaseSnapshotSkipped bool             `json:"base_snapshot_skipped,omitempty"`
	DeadCode            map[string]any   `json:"dead_code,omitempty"`
	Complexity          map[string]any   `json:"complexity,omitempty"`
	Duplication         map[string]any   `json:"duplication,omitempty"`
}

func (o auditOutput) MarshalJSON() ([]byte, error) {
	type alias auditOutput
	m := map[string]any{}
	data, err := json.Marshal(alias(o))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	m["kind"] = "audit"
	if o.DeadCode == nil {
		m["dead_code"] = map[string]any{"skipped": true}
	}
	if o.Complexity == nil {
		m["complexity"] = map[string]any{"skipped": true}
	}
	return json.Marshal(m)
}

func dcSub(fs []*report.Finding, skipped bool) map[string]any {
	if skipped {
		return map[string]any{"skipped": true}
	}
	items := make([]any, 0, len(fs))
	for _, x := range fs {
		items = append(items, report.FindingJSON(x))
	}
	return map[string]any{"findings": items, "total": len(fs)}
}

func complexSub(fs []*report.Finding, all []health.Finding, skipped bool) map[string]any {
	if skipped {
		return map[string]any{"skipped": true}
	}
	items := make([]any, 0, len(fs))
	for _, x := range fs {
		items = append(items, report.FindingJSON(x))
	}
	maxCC := 0
	above := 0
	for _, hf := range all {
		if hf.Cyclomatic > maxCC {
			maxCC = hf.Cyclomatic
		}
		if len(hf.Exceeded) > 0 {
			above++
		}
	}
	return map[string]any{"findings": items, "total": len(fs), "max_cyclomatic": maxCC, "functions_above_threshold_full_tree": above}
}

func dupSub(res *dupes.Result, skipped bool) map[string]any {
	if skipped || res == nil {
		return map[string]any{"skipped": true}
	}
	return map[string]any{
		"clone_groups":           res.Stats.CloneGroups,
		"duplication_percentage": res.Stats.DuplicationPercentage,
		"files_with_duplication": res.Stats.FilesWithDuplication,
	}
}

// complexityFinding converts a health finding into a report finding for the
// audit envelope.
func complexityFinding(hf health.Finding, sev config.Severity) *report.Finding {
	return &report.Finding{
		Kind: "complexity-finding", Rule: "complexity-cyclomatic",
		Path: hf.Path, Line: hf.Line, Col: hf.Col,
		Message:  fmt.Sprintf("%s exceeds complexity ceilings (%v)", hf.Name, hf.Exceeded),
		Severity: sev,
		ID:       report.Fingerprint("complexity-finding", hf.Path, hf.Name),
		Extra: map[string]any{
			"name": hf.Name, "cyclomatic": hf.Cyclomatic, "cognitive": hf.Cognitive,
			"line_count": hf.Lines, "exceeded": hf.Exceeded,
		},
	}
}

// filterHealthBaseline drops findings whose path|name key is in a saved
// health baseline.
func filterHealthBaseline(fs []*report.Finding, path string) []*report.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "goose:", err)
		os.Exit(2)
	}
	var b struct {
		Entries map[string]int `json:"entries"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		fmt.Fprintln(os.Stderr, "goose: invalid health baseline:", err)
		os.Exit(2)
	}
	var out []*report.Finding
	for _, x := range fs {
		name := fmt.Sprint(x.Extra["name"])
		k1 := x.Path + ":" + name
		k2 := x.Path + "|" + name
		if b.Entries[k1] > 0 {
			b.Entries[k1]--
			continue
		}
		if b.Entries[k2] > 0 {
			b.Entries[k2]--
			continue
		}
		out = append(out, x)
	}
	return out
}

// aPath reads an audit sub-flag value from Extra.
func aPath(f *Flags, name string) string { return f.Extra[name] }

// auditHuman renders the terminal audit brief.
func auditHuman(f *Flags, out auditOutput, dc, cx []*report.Finding, dup *dupes.Result, dupIntroduced map[string]bool, elapsed int64) string {
	var b strings.Builder
	b.WriteString(header("Audit") + "\n\n")
	fmt.Fprintf(&b, "  base: %s\n  changed: %d files · head %s\n\n", out.BaseDescription, out.ChangedFilesCount, out.HeadSHA)
	row := func(label string, count any, intro, inher int, skipped bool) {
		if skipped {
			fmt.Fprintf(&b, "  %-13s skipped\n", label)
			return
		}
		fmt.Fprintf(&b, "  %-13s %v (%d introduced, %d inherited)\n", label, count, intro, inher)
	}
	row("Dead code", len(dc), out.Attribution.DCIntroduced, out.Attribution.DCInherited, len(dc) == 0 && out.Summary["dead_code_issues"] == nil)
	row("Complexity", len(cx), out.Attribution.CXIntroduced, out.Attribution.CXInherited, out.Complexity == nil && out.Summary["complexity_findings"] == nil)
	if dup != nil {
		fmt.Fprintf(&b, "  %-13s %d clone groups (%.2f%%) (%d introduced)\n", "Duplication", dup.Stats.CloneGroups, dup.Stats.DuplicationPercentage, out.Attribution.DupIntroduced)
	} else {
		row("Duplication", "-", 0, 0, true)
	}
	fmt.Fprintf(&b, "  %-13s skipped\n", "Styling")
	section := func(title string, fs []*report.Finding) {
		if len(fs) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n● %s (%d)\n", title, len(fs))
		byPath := map[string][]*report.Finding{}
		var paths []string
		for _, x := range fs {
			if _, ok := byPath[x.Path]; !ok {
				paths = append(paths, x.Path)
			}
			byPath[x.Path] = append(byPath[x.Path], x)
		}
		sort.Strings(paths)
		for _, p := range paths {
			fmt.Fprintf(&b, "  %s\n", p)
			for _, x := range byPath[p] {
				tag := ""
				if x.Extra["introduced"] == false {
					tag = " [inherited]"
				} else if x.Extra["worsened"] == true {
					tag = " [worsened]"
				}
				fmt.Fprintf(&b, "    :%d %s%s\n", x.Line, x.Message, tag)
			}
		}
	}
	section("Dead code", dc)
	section("Complexity", cx)
	if dup != nil && len(dup.Groups) > 0 {
		fmt.Fprintf(&b, "\n● Duplication (%d)\n", len(dup.Groups))
		for _, g := range dup.Groups {
			tag := ""
			if !dupIntroduced[g.Fingerprint] {
				tag = " [inherited]"
			}
			fmt.Fprintf(&b, "  %s %d lines × %d instances%s\n", g.Fingerprint, g.Lines, len(g.Instances), tag)
		}
	}
	fmt.Fprintf(&b, "\nVerdict: %s (%.2fs)\n", out.Verdict, float64(elapsed)/1000)
	return b.String()
}

func header(label string) string {
	head := label + " "
	pad := 51 - len([]rune(head))
	if pad < 1 {
		pad = 1
	}
	return head + strings.Repeat("─", pad)
}

// prodDupIgnore keeps the config ignores and drops test files from the
// production dupes pass.
func prodDupIgnore(cfg *config.Config) func(string) bool {
	return func(rel string) bool {
		if strings.HasSuffix(rel, "_test.go") {
			return true
		}
		for _, p := range cfg.Duplicates.Ignore {
			if config.MatchPath(p, rel) {
				return true
			}
		}
		return false
	}
}
