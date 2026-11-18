// Package health measures where a Go codebase is hard to change: function
// complexity, CRAP risk against coverage, file scores, git-churn hotspots,
// ranked refactoring targets, and the 0-100 project health score with
// snapshots and trends. It mirrors the fallow health contract, with real Go
// coverage profiles feeding CRAP instead of Istanbul data.
package health

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Coverage holds per-file basic blocks parsed from a Go coverage profile
// (go test -coverprofile). It is the goose equivalent of fallow's Istanbul
// reader and gives health exact per-function CRAP inputs.
type Coverage struct {
	// Blocks maps a file key (module-prefixed, from the profile) to blocks.
	Blocks map[string][]Block
	// RelKeys is set true once keys are folded to project-relative paths.
	RelKeys bool
	Source  string
}

// Block is one profiled basic block.
type Block struct {
	StartLine, EndLine int
	NumStmt            int
	Count              int
}

// ParseCoverage reads a coverage profile file into a Coverage.
func ParseCoverage(path string) (*Coverage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cov := &Coverage{Blocks: map[string][]Block{}, Source: path}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	mode := "set"
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "mode:") {
			mode = strings.TrimSpace(strings.TrimPrefix(line, "mode:"))
			continue
		}
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		file, sl, el, ok := parseRange(fields[0])
		if !ok {
			continue
		}
		num, err1 := strconv.Atoi(fields[1])
		count, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			continue
		}
		if mode == "set" && count > 0 {
			count = 1
		}
		cov.Blocks[file] = append(cov.Blocks[file], Block{StartLine: sl, EndLine: el, NumStmt: num, Count: count})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return cov, nil
}

// parseRange splits "path/file.go:12.34,20.5" into the file, start line, and
// end line.
func parseRange(s string) (file string, startLine, endLine int, ok bool) {
	sep := strings.LastIndex(s, ":")
	if sep < 0 {
		return "", 0, 0, false
	}
	file = s[:sep]
	span := s[sep+1:]
	comma := strings.Index(span, ",")
	if comma < 0 {
		return "", 0, 0, false
	}
	start := span[:comma]
	end := span[comma+1:]
	return file, leadingInt(start), leadingInt(end), true
}

func leadingInt(s string) int {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0
	}
	return n
}

// MatchFiles folds module-prefixed coverage keys onto project-relative paths.
// match returns the relative path when the key maps into the project.
func (c *Coverage) MatchFiles(match func(key string) (rel string, ok bool)) *Coverage {
	if c == nil {
		return nil
	}
	out := &Coverage{Blocks: map[string][]Block{}, Source: c.Source, RelKeys: true}
	for key, blocks := range c.Blocks {
		if rel, ok := match(key); ok {
			out.Blocks[rel] = append(out.Blocks[rel], blocks...)
		}
	}
	return out
}

// Percent returns the statement-weighted coverage in [l0,l1] for a project
// file, or nil when that range is not profiled.
func (c *Coverage) Percent(rel string, l0, l1 int) *float64 {
	if c == nil || len(c.Blocks[rel]) == 0 {
		return nil
	}
	var touched, covered int
	for _, b := range c.Blocks[rel] {
		if b.EndLine < l0 || b.StartLine > l1 {
			continue
		}
		touched += b.NumStmt
		if b.Count > 0 {
			covered += b.NumStmt
		}
	}
	if touched == 0 {
		return nil
	}
	v := float64(covered) / float64(touched)
	return &v
}

// FilePercent returns whole-file coverage, or nil when the file is not
// profiled at all.
func (c *Coverage) FilePercent(rel string) *float64 {
	if c == nil {
		return nil
	}
	return c.Percent(rel, 1, 1<<30)
}
