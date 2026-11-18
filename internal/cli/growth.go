package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"goose/internal/gitx"
)

// baselineGrowth implements the --fail-on-baseline-growth ratchet: a change
// may add a finding and re-save the baseline in the same commit, which keeps
// --baseline quiet and --fail-on-stale-baseline green. The ratchet reads the
// baseline file twice — the working copy and its version at a base ref — and
// fails when the working copy has keys the base never had. It runs no
// analysis, so a bad or HEAD-resolved base is an error before work starts.
//
// It returns the count of new keys, whether the baseline is brand-new at the
// base (which passes with a note), the resolved base label, and a usage error
// (exit 2) when the base cannot be used.
func baselineGrowth(f *Flags, root, baseline string) (added int, isNew bool, baseLabel string, err error) {
	repo := gitx.Open(root)
	if !repo.Inside || !gitx.Available() {
		return 0, false, "", fmt.Errorf("--fail-on-baseline-growth needs git history, and %s is not in a git work tree. Run goose in a git checkout, or remove the flag", baseline)
	}
	// Resolve the base ref: --baseline-base wins, else --changed-since/--base,
	// else GOOSE_AUDIT_BASE, then the audit default (upstream / main).
	base, how := "", ""
	switch {
	case f.BaselineBase != "":
		base = f.BaselineBase
	case f.ChangedSince != "":
		base, how = f.ChangedSince, "--base"
	case os.Getenv("GOOSE_AUDIT_BASE") != "":
		base, how = os.Getenv("GOOSE_AUDIT_BASE"), "GOOSE_AUDIT_BASE"
	default:
		b, derr := repo.DefaultBase()
		if derr != nil || b == "" {
			return 0, false, "", fmt.Errorf("--fail-on-baseline-growth could not find a base ref to compare the baseline with. Pass --baseline-base <ref>, for example --baseline-base origin/main")
		}
		base, how = b, "merge-base with the default branch"
	}
	if !repo.ResolveRef(base) {
		remote, branch := base, ""
		if i := strings.Index(base, "/"); i > 0 {
			remote, branch = base[:i], base[i+1:]
		}
		hint := fmt.Sprintf("Fetch it with `git fetch %s %s`", remote, branch)
		if branch == "" {
			hint = "Check out with full history (fetch-depth: 0)"
		}
		return 0, false, "", fmt.Errorf("--fail-on-baseline-growth cannot resolve the base ref '%s', so it cannot compare the baseline. %s", base, hint)
	}
	baseCommit, _ := revParse(repo, base+"^{commit}")
	headCommit, _ := revParse(repo, "HEAD^{commit}")
	source := how
	if source == "" {
		source = "--baseline-base"
	}
	if baseCommit != "" && baseCommit == headCommit {
		return 0, false, "", fmt.Errorf("--fail-on-baseline-growth resolved its base to %s (%s), so the gate cannot detect growth. Pass --baseline-base <ref>, for example --baseline-base origin/main", base, source)
	}
	label := base + " (" + source + ")"
	rel, err := repoRelPath(repo, baseline)
	if err != nil {
		return 0, false, "", err
	}
	baseText, rerr := repo.ShowFile(base, rel)
	// "not in the base" is the brand-new-baseline case; git exits non-zero.
	if rerr != nil {
		if fileMissingAtBase(repo, base, rel) {
			return 0, true, label, nil
		}
		return 0, false, "", fmt.Errorf("--fail-on-baseline-growth could not read the baseline %s at '%s': %v", baseline, base, rerr)
	}
	headData, err := os.ReadFile(baseline)
	if err != nil {
		return 0, false, "", fmt.Errorf("--fail-on-baseline-growth could not read the baseline %s: %v", baseline, err)
	}
	headCounts, err := baselineMultiset(headData)
	if err != nil {
		return 0, false, "", fmt.Errorf("--fail-on-baseline-growth could not parse the baseline %s: %v", baseline, err)
	}
	baseCounts, err := baselineMultiset(baseText)
	if err != nil {
		return 0, false, "", fmt.Errorf("--fail-on-baseline-growth could not parse the baseline %s at '%s': %v", baseline, base, err)
	}
	// Growth = every key occurrence the working copy has beyond the base.
	for key, n := range headCounts {
		if extra := n - baseCounts[key]; extra > 0 {
			added += extra
			if !f.Quiet && added <= 20 {
				fmt.Fprintf(os.Stderr, "  %s\n", strings.TrimPrefix(key, "|"))
			}
		}
	}
	return added, false, label, nil
}

// baselineStaleInert is the fallow change-scope rule for the stale gate: a
// narrowed run cannot judge a whole-project baseline, and a --save-baseline
// naming the file --baseline loads can never leave it stale in the same
// invocation. Returns the reason, or "" when the stale gate can run. The
// growth gate compares the file at a base ref and is not scope-inert, so it
// is not consulted here.
func baselineStaleInert(f *Flags, root string) string {
	if f.BaselineScoped {
		return "this run analyzed only part of the project (a path, diff, base ref, workspace, or production scope)"
	}
	if f.SaveBaseline != "" && f.Baseline != "" && sameFile(root, f.SaveBaseline, f.Baseline) {
		return "--baseline and --save-baseline name the same file, which a run can never leave stale"
	}
	return ""
}

// sameFile compares two paths for identity after Abs+EvalSymlinks, so a
// baseline saved back to where it was read reads as the same file even
// through a /tmp symlink on macOS.
func sameFile(root, a, b string) bool {
	abs := func(p string) string {
		if !filepath.IsAbs(p) {
			p = filepath.Join(root, p)
		}
		p = filepath.Clean(p)
		if real, err := filepath.EvalSymlinks(p); err == nil {
			return real
		}
		return p
	}
	return abs(a) == abs(b)
}

// baselineStoodDown prints fallow's stand-down note so an opted-in gate that
// did not run is never silent. Only fires when the gate was asked for, a
// baseline is loaded, and the reason applies to it.
func baselineStoodDown(f *Flags, gate, baselinePath, reason string) {
	switch gate {
	case "stale-baseline":
		if !f.FailOnStaleBaseline {
			return
		}
		fmt.Fprintf(os.Stderr, "Note: --fail-on-stale-baseline did not run: %s, so the baseline %s was not judged.\n", reason, baselinePath)
	case "baseline-growth":
		if !f.FailOnBaselineGrowth {
			return
		}
		fmt.Fprintf(os.Stderr, "Note: --fail-on-baseline-growth did not run: %s, so the baseline %s was not judged.\n", reason, baselinePath)
	}
}

// baselineMultiset flattens a baseline document into key -> occurrences. Keys
// are "category|entry" so a per-category duplicate counts correctly; the
// dead-code map, duplicate-export lists, and any future array-shaped section
// all collapse through here.
func baselineMultiset(data []byte) (map[string]int, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := map[string]int{}
	var cats []string
	for k := range doc {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		v := doc[cat]
		switch t := v.(type) {
		case map[string]any: // entries map: key -> count
			for key, n := range t {
				if c, ok := number(n); ok {
					out[cat+"|"+key] += c
				}
			}
		case []any: // a list of keys
			for _, item := range t {
				if s, ok := item.(string); ok {
					out[cat+"|"+s]++
				}
			}
		}
	}
	return out, nil
}

func number(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	}
	return 0, false
}

// revParse resolves a rev to a commit sha; empty on failure.
func revParse(repo gitx.Repo, rev string) (string, error) {
	out, err := repo.RevParse(rev)
	return out, err
}

// repoRelPath maps the baseline file to a path inside the repo so git show
// can read it at the base ref. Symlinks are resolved on both sides: on macOS
// a cwd under /tmp compares unequal to git's /private/tmp toplevel otherwise.
func repoRelPath(repo gitx.Repo, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	repoRoot, _ := filepath.Abs(repo.Root)
	if real, err := filepath.EvalSymlinks(repoRoot); err == nil {
		repoRoot = real
	}
	rel, err := filepath.Rel(repoRoot, abs)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("--fail-on-baseline-growth requires the baseline %s to live inside the git repository at %s", path, repo.Root)
	}
	return filepath.ToSlash(rel), nil
}

// fileMissingAtBase reports whether git says the path is simply absent at the
// ref (versus an unrelated git failure worth exiting 2 on).
func fileMissingAtBase(repo gitx.Repo, ref, rel string) bool {
	out, err := repo.LsTree(ref, rel)
	return err == nil && out == ""
}
