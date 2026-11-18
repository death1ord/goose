// Package gitx wraps the git plumbing that goose needs: changed-file scope,
// merge-base detection for audit, churn history for health, and repository
// identity for snapshots.
package gitx

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Repo describes a git checkout.
type Repo struct {
	// Root is the toplevel directory.
	Root string
	// Inside reports whether the query directory is in a work tree.
	Inside bool
	// Shallow reports a shallow clone (--is-shallow-repository).
	Shallow bool
}

// Open resolves the repository around dir.
func Open(dir string) Repo {
	out, err := run(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return Repo{}
	}
	root := strings.TrimSpace(out)
	r := Repo{Root: root, Inside: root != ""}
	if r.Inside {
		if shallow, err := run(dir, "rev-parse", "--is-shallow-repository"); err == nil {
			r.Shallow = strings.TrimSpace(shallow) == "true"
		}
	}
	return r
}

// CurrentSHA returns HEAD's short sha.
func (r Repo) CurrentSHA() string {
	if !r.Inside {
		return ""
	}
	out, err := run(r.Root, "rev-parse", "--short", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// Branch returns the current branch name.
func (r Repo) Branch() string {
	if !r.Inside {
		return ""
	}
	out, err := run(r.Root, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// ResolveRef reports whether a ref exists.
func (r Repo) ResolveRef(ref string) bool {
	if !r.Inside {
		return false
	}
	_, err := run(r.Root, "rev-parse", "--verify", ref+"^{commit}")
	return err == nil
}

// RevParse resolves a rev to its full commit sha ("^{commit}" applied by the
// caller when wanted). Empty on failure.
func (r Repo) RevParse(rev string) (string, error) {
	if !r.Inside {
		return "", errors.New("not-a-repository")
	}
	out, err := run(r.Root, "rev-parse", "--verify", rev)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// LsTree lists one path at a ref. An empty string with a nil error means the
// path is simply not tracked at that ref (the path IS inside the repo). A
// non-nil error is a real git failure (bad ref, missing history).
func (r Repo) LsTree(ref, path string) (string, error) {
	if !r.Inside {
		return "", errors.New("not-a-repository")
	}
	out, err := run(r.Root, "ls-tree", "--name-only", ref, "--", path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// MergeBase finds the merge-base of a ref and HEAD.
func (r Repo) MergeBase(ref string) (string, error) {
	out, err := run(r.Root, "merge-base", "HEAD", ref)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// DefaultBase picks the audit base: upstream, then the remote default branch,
// then main/master. It returns ("", nil) when nothing resolves.
func (r Repo) DefaultBase() (string, error) {
	out, err := run(r.Root, "rev-parse", "--abbrev-ref", "@{upstream}")
	if err == nil {
		up := strings.TrimSpace(out)
		if up != "" && up != "HEAD" {
			return up, nil
		}
	}
	for _, cand := range []string{"origin/main", "origin/master", "main", "master"} {
		if r.ResolveRef(cand) {
			return cand, nil
		}
	}
	return "", nil
}

// ChangedFiles lists files changed between the merge-base of base and HEAD,
// including the working tree. Paths come out repository-relative with forward
// slashes.
func (r Repo) ChangedFiles(base string) ([]string, error) {
	if !r.Inside {
		return nil, errors.New("not-a-repository")
	}
	mergeBase, err := r.MergeBase(base)
	if err != nil {
		return nil, err
	}
	out, err := run(r.Root, "diff", "--name-only", "-z", mergeBase, "--", ".")
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, p := range strings.Split(out, "\x00") {
		if p != "" {
			set[filepath.ToSlash(p)] = true
		}
	}
	out2, err := run(r.Root, "diff", "--name-only", "-z", "--no-index", "/dev/null", "/dev/null")
	_ = out2
	// Working-tree changes vs merge base and untracked files.
	out3, err3 := run(r.Root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err3 == nil {
		recs := strings.Split(out3, "\x00")
		for i := 0; i < len(recs); i++ {
			rec := recs[i]
			if len(rec) < 4 {
				continue
			}
			path := rec[3:]
			if strings.HasPrefix(rec, "R") {
				// renames carry the source in the next record
				i++
			}
			set[filepath.ToSlash(path)] = true
		}
	}
	var files []string
	for f := range set {
		files = append(files, f)
	}
	return files, nil
}

// Worktree adds a detached worktree at dir pinned to ref, returning a cleanup
// that removes it. Audit uses it to analyze the base snapshot without a stash
// or clone. The caller must remove dir from a path outside it.
func (r Repo) Worktree(dir, ref string) (func(), error) {
	if !r.Inside {
		return nil, errors.New("not-a-repository")
	}
	if _, err := run(r.Root, "worktree", "add", "--detach", "--force", dir, ref); err != nil {
		return nil, err
	}
	return func() { _, _ = run(r.Root, "worktree", "remove", "--force", dir) }, nil
}

// ChurnEvent is one (commit, file) numstat row.
type ChurnEvent struct {
	Path      string
	Timestamp int64 // unix seconds
	Author    string
	Added     int
	Deleted   int
}

// LogNumstat reads churn history for the window ("" or "12m" or "2024-01-01").
func (r Repo) LogNumstat(dir, since string) ([]ChurnEvent, string, error) {
	if !r.Inside {
		return nil, "", errors.New("not-a-repository")
	}
	args := []string{"log", "--no-merges", "--no-renames", "--use-mailmap", "--numstat", "--format=\x01%ct\x02%ae"}
	if since != "" {
		arg, err := sinceArg(since)
		if err != nil {
			return nil, "", err
		}
		args = append(args, arg)
	}
	out, err := run(r.Root, args...)
	if err != nil {
		return nil, "", err
	}
	var events []ChurnEvent
	var curTs int64
	var curAuthor string
	sep := "\x01"
	scanner := bufio.NewScanner(strings.NewReader(out))
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, sep) {
			parts := strings.SplitN(line, "\x02", 2)
			curTs, _ = strconv.ParseInt(parts[0][1:], 10, 64)
			if len(parts) > 1 {
				curAuthor = parts[1]
			}
			continue
		}
		if line == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 3 {
			continue
		}
		if cols[0] == "-" || cols[1] == "-" {
			continue // binary
		}
		added, _ := strconv.Atoi(cols[0])
		deleted, _ := strconv.Atoi(cols[1])
		events = append(events, ChurnEvent{
			Path: cols[2], Timestamp: curTs, Author: curAuthor,
			Added: added, Deleted: deleted,
		})
	}
	return events, r.CurrentSHA(), nil
}

// sinceArg converts a fallow-style duration ("6m", "90d", "1y", "2w") or an
// ISO date into a git --since argument.
func sinceArg(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	last := s[len(s)-1]
	switch last {
	case 'd', 'w', 'y':
		return "--since=" + s, nil
	case 'm':
		// months: approximate, git understands "6 months ago"
		return "--since=" + s[:len(s)-1] + " months ago", nil
	}
	if _, err := strconv.Atoi(s); err == nil {
		return "--since=" + s, nil
	}
	return "--since=" + s, nil
}

// ShowFile reads one file from a ref, or errors.
func (r Repo) ShowFile(ref, path string) ([]byte, error) {
	cmd := exec.Command("git", "-C", r.Root, "show", ref+":"+path)
	data, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func run(dir string, args ...string) (string, error) {
	full := append([]string{"-C", dir}, args...)
	cmd := exec.Command("git", full...)
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

// Available reports whether git is on PATH.
func Available() bool {
	_, err := exec.LookPath("git")
	return err == nil
}
