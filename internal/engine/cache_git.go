package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// gitRepoFingerprints returns deterministic state digests (commit ID +
// uncommitted/staged/untracked status and file content hashes) for every unique
// git repository covering dirs. Directories outside any git repo are skipped
// with zero subprocess spawns.
func gitRepoFingerprints(dirs []string) ([]string, error) {
	seenDirs := map[string]bool{}
	var candidates []string
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if ap, err := filepath.Abs(d); err == nil {
			d = ap
		}
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			continue
		}
		cd := canonicalPath(d)
		if seenDirs[cd] || !hasGitContext(d) {
			continue
		}
		seenDirs[cd] = true
		candidates = append(candidates, d)
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	gitPath, lookErr := exec.LookPath("git")
	hasGitCLI := lookErr == nil && gitPath != ""

	seenRepos := map[string]bool{}
	var out []string
	for _, d := range candidates {
		if !hasGitCLI {
			if marker := findGitMarkerUpwards(d); marker != "" {
				key := canonicalPath(marker)
				if !seenRepos[key] {
					seenRepos[key] = true
					out = append(out, offlineGitFingerprint(marker))
				}
			}
			continue
		}
		fp, err := fingerprintSingleGitRepo(d, gitPath, seenRepos, 0)
		if err != nil {
			return nil, err
		}
		if fp != "" {
			out = append(out, fp)
		}
	}
	sort.Strings(out)
	return out, nil
}

func hasGitContext(dir string) bool {
	if os.Getenv("GIT_DIR") != "" || os.Getenv("GIT_WORK_TREE") != "" {
		return true
	}
	return findGitMarkerUpwards(dir) != ""
}

func findGitMarkerUpwards(dir string) string {
	cur := filepath.Clean(dir)
	for {
		cand := filepath.Join(cur, ".git")
		if _, err := os.Lstat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
}

func fingerprintSingleGitRepo(dir, gitPath string, seen map[string]bool, depth int) (string, error) {
	if depth > 4 {
		return "", nil
	}
	topLevel, gitDir, headState, err := resolveGitHeadAndRoot(dir, gitPath)
	if err != nil {
		return "", err
	}
	repoKey := canonicalPath(topLevel) + "\x00" + canonicalPath(gitDir)
	if seen[repoKey] {
		return "", nil
	}
	seen[repoKey] = true

	statusOut, err := gitRun(gitPath, topLevel, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return "", err
	}

	h := sha256.New()
	fmt.Fprintf(h, "repo=%s\x00gitdir=%s\x00head=%s\x00gitidx=%s\x00status=",
		repoKey, canonicalPath(gitDir), headState, os.Getenv("GIT_INDEX_FILE"))
	statusSum := sha256.Sum256([]byte(statusOut))
	h.Write(statusSum[:])
	h.Write([]byte{0})

	if statusOut != "" {
		if err := hashGitDirtyDetails(h, topLevel, headState, statusOut, gitPath, seen, depth); err != nil {
			return "", err
		}
	}

	gmPath := filepath.Join(topLevel, ".gitmodules")
	if fileExists(gmPath) {
		if gmHash, herr := hashFileSHA256(gmPath); herr == nil {
			h.Write([]byte("gm:"))
			h.Write(gmHash[:])
		}
		if subOut, serr := gitRun(gitPath, topLevel, "submodule", "status", "--recursive"); serr == nil {
			subSum := sha256.Sum256([]byte(subOut))
			h.Write([]byte("sub:"))
			h.Write(subSum[:])
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashGitDirtyDetails(h interface{ Write([]byte) (int, error) }, topLevel, headState, statusOut, gitPath string, seen map[string]bool, depth int) error {
	if strings.HasPrefix(headState, "UNBORN:") {
		if staged, err := gitRun(gitPath, topLevel, "ls-files", "--stage", "-z"); err == nil {
			sum := sha256.Sum256([]byte(staged))
			_, _ = h.Write([]byte("stage:"))
			_, _ = h.Write(sum[:])
		}
	} else if cachedDiff, err := gitRun(gitPath, topLevel, "diff", "--cached", "--raw", "-z", "HEAD"); err == nil {
		sum := sha256.Sum256([]byte(cachedDiff))
		_, _ = h.Write([]byte("cached:"))
		_, _ = h.Write(sum[:])
	}

	dirtyPaths := parsePorcelainZPaths(statusOut)
	for _, rel := range dirtyPaths {
		entryDigest, err := hashDirtyEntry(topLevel, rel, gitPath, seen, depth)
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "d:%s=%s\x00", rel, entryDigest)
	}
	return nil
}

func resolveGitHeadAndRoot(dir, gitPath string) (topLevel, gitDir, headState string, err error) {
	if out, rerr := gitRun(gitPath, dir, "rev-parse", "--show-toplevel", "--git-dir", "HEAD"); rerr == nil {
		lines := splitTrimmedLines(out)
		if len(lines) >= 3 {
			topLevel = lines[0]
			gitDir = resolveRelGitDir(dir, lines[1])
			headState = lines[2]
			return topLevel, gitDir, headState, nil
		}
	}
	out, err := gitRun(gitPath, dir, "rev-parse", "--show-toplevel", "--git-dir")
	if err != nil {
		return "", "", "", err
	}
	lines := splitTrimmedLines(out)
	if len(lines) < 2 {
		return "", "", "", errors.New("unexpected git rev-parse output")
	}
	topLevel = lines[0]
	gitDir = resolveRelGitDir(dir, lines[1])
	symRef, _ := gitRun(gitPath, topLevel, "symbolic-ref", "-q", "HEAD")
	headState = "UNBORN:" + strings.TrimSpace(symRef)
	return topLevel, gitDir, headState, nil
}

func resolveRelGitDir(baseDir, raw string) string {
	if filepath.IsAbs(raw) {
		return filepath.Clean(raw)
	}
	return filepath.Clean(filepath.Join(baseDir, raw))
}

func splitTrimmedLines(out string) []string {
	rawLines := strings.Split(strings.TrimRight(out, "\r\n"), "\n")
	lines := make([]string, 0, len(rawLines))
	for _, l := range rawLines {
		lines = append(lines, strings.TrimSpace(strings.TrimRight(l, "\r")))
	}
	return lines
}

func parsePorcelainZPaths(statusOut string) []string {
	recs := strings.Split(statusOut, "\x00")
	seen := map[string]bool{}
	var paths []string
	add := func(p string) {
		p = strings.TrimSuffix(filepath.ToSlash(p), "/")
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		paths = append(paths, p)
	}
	for i := 0; i < len(recs); i++ {
		rec := recs[i]
		if len(rec) < 4 {
			continue
		}
		x, y := rec[0], rec[1]
		add(rec[3:])
		if (x == 'R' || x == 'C' || y == 'R' || y == 'C') && i+1 < len(recs) {
			i++
			add(recs[i])
		}
	}
	sort.Strings(paths)
	return paths
}

func hashDirtyEntry(topLevel, rel, gitPath string, seen map[string]bool, depth int) (string, error) {
	full := filepath.Join(topLevel, filepath.FromSlash(rel))
	st, err := os.Lstat(full)
	if os.IsNotExist(err) {
		return "missing", nil
	}
	if err != nil {
		return "", err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		target, _ := os.Readlink(full)
		if tst, terr := os.Stat(full); terr == nil && tst.Mode().IsRegular() {
			if sum, herr := hashFileSHA256(full); herr == nil {
				return fmt.Sprintf("symlink:%s:%x", target, sum), nil
			}
		}
		return "symlink:" + target, nil
	}
	if st.IsDir() {
		if _, gerr := os.Lstat(filepath.Join(full, ".git")); gerr == nil {
			nestedFP, nerr := fingerprintSingleGitRepo(full, gitPath, seen, depth+1)
			if nerr != nil {
				return "", nerr
			}
			if nestedFP != "" {
				return "gitdir:" + nestedFP, nil
			}
		}
		return "dir", nil
	}
	sum, err := hashFileSHA256(full)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum[:]), nil
}

func offlineGitFingerprint(markerPath string) string {
	gitDir := markerPath
	if st, err := os.Lstat(markerPath); err == nil && !st.IsDir() {
		if data, rerr := os.ReadFile(markerPath); rerr == nil {
			line := strings.TrimSpace(string(data))
			if strings.HasPrefix(line, "gitdir:") {
				p := strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
				if !filepath.IsAbs(p) {
					p = filepath.Join(filepath.Dir(markerPath), p)
				}
				gitDir = filepath.Clean(p)
			}
		}
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "offline:%s\x00", canonicalPath(gitDir))
	headFile := filepath.Join(gitDir, "HEAD")
	if headBytes, err := os.ReadFile(headFile); err == nil {
		sum := sha256.Sum256(headBytes)
		_, _ = h.Write(sum[:])
		headText := strings.TrimSpace(string(headBytes))
		if strings.HasPrefix(headText, "ref:") {
			refRel := strings.TrimSpace(strings.TrimPrefix(headText, "ref:"))
			refPath := filepath.Join(gitDir, filepath.FromSlash(refRel))
			if refSum, rerr := hashFileSHA256(refPath); rerr == nil {
				_, _ = h.Write(refSum[:])
			}
		}
	}
	for _, extra := range []string{"packed-refs", "index"} {
		if sum, err := hashFileSHA256(filepath.Join(gitDir, extra)); err == nil {
			_, _ = h.Write([]byte(extra))
			_, _ = h.Write(sum[:])
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func gitRun(gitPath, dir string, args ...string) (string, error) {
	full := make([]string, 0, len(args)+2)
	full = append(full, "-C", dir)
	full = append(full, args...)
	cmd := exec.Command(gitPath, full...)
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", errors.New(strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return string(out), nil
}

