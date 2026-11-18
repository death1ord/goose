package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"goose/internal/engine"
)

// changedScope resolves the set of paths a run is scoped to. A nil result
// means "no scope set" and the caller keeps every finding; an empty non-nil
// set scopes to nothing. Sources combine: --changed-since/--base (git),
// --diff-file, and --diff-stdin (a `git diff` patch), plus the positional
// path prefix handled by scopeFilter.
func changedScope(f *Flags, ec *engine.Context) (map[string]bool, error) {
	var set map[string]bool
	add := func(m map[string]bool, err error) error {
		if err != nil {
			return err
		}
		if m == nil {
			return nil
		}
		if set == nil {
			set = map[string]bool{}
		}
		for k, v := range m {
			set[k] = v
		}
		return nil
	}
	if f.ChangedSince != "" {
		cs := changedSet(ec.Cfg.Root, f.ChangedSince)
		if cs == nil {
			return nil, fmt.Errorf("cannot resolve changed files vs %q (is it a git ref?)", f.ChangedSince)
		}
		if err := add(cs, nil); err != nil {
			return nil, err
		}
	}
	if f.DiffStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading --diff-stdin: %w", err)
		}
		add(diffPaths(string(data)), nil)
	} else if f.DiffFile != "" {
		data, err := os.ReadFile(f.DiffFile)
		if err != nil {
			return nil, fmt.Errorf("reading --diff-file: %w", err)
		}
		add(diffPaths(string(data)), nil)
	}
	return set, nil
}

// diffPaths extracts the touched file paths from unified-diff text. It reads
// the +++ / --- headers of each file section and drops the a/ and b/ prefixes
// git adds; /dev/null lines (new/deleted files) fall back to the other side.
// It also accepts a plain list of paths (one per line, or diff --git headers)
// so a tool can pipe `git diff --name-only`.
func diffPaths(text string) map[string]bool {
	set := map[string]bool{}
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "diff --git "):
			// "diff --git a/pkg/x.go b/pkg/x.go"
			if i := strings.Index(line, " b/"); i >= 0 {
				set[cleanDiffPath(line[i+3:])] = true
			}
		case strings.HasPrefix(line, "+++ "):
			p := cleanDiffPath(strings.TrimPrefix(line, "+++ "))
			if p != "/dev/null" {
				set[p] = true
			}
		case strings.HasPrefix(line, "--- "):
			p := cleanDiffPath(strings.TrimPrefix(line, "--- "))
			if p != "/dev/null" {
				set[p] = true
			}
		case strings.HasPrefix(line, "@@"),
			strings.HasPrefix(line, "+"),
			strings.HasPrefix(line, "-"),
			strings.HasPrefix(line, " "),
			strings.HasPrefix(trimmed, "index "),
			strings.HasPrefix(trimmed, "new file"),
			strings.HasPrefix(trimmed, "deleted file"),
			strings.HasPrefix(trimmed, "similarity "),
			strings.HasPrefix(trimmed, "rename "),
			strings.HasPrefix(trimmed, "old mode"),
			strings.HasPrefix(trimmed, "new mode"),
			strings.HasPrefix(trimmed, "Binary "),
			strings.HasPrefix(trimmed, "\\"):
			// diff metadata or hunk line
		default:
			set[filepath.ToSlash(strings.TrimPrefix(trimmed, "./"))] = true
		}
	}
	return set
}

// cleanDiffPath strips the a/ or b/ prefix, a possible timestamp tab, and
// normalizes to a forward-slash relative path.
func cleanDiffPath(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.IndexByte(p, '\t'); i > 0 {
		p = p[:i] // "+++ b/file.go<TAB>timestamp"
	}
	p = strings.TrimPrefix(p, "./")
	if len(p) > 2 {
		if strings.HasPrefix(p, "a/") || strings.HasPrefix(p, "b/") {
			p = p[2:]
		}
	}
	return p
}
