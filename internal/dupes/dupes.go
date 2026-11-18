// Package dupes finds copy-pasted code blocks. Each Go file is tokenized with
// go/scanner, tokens are normalized per detection mode, and maximal repeated
// token sequences are detected with a suffix array plus LCP runs over the
// concatenated stream. The output contract matches fallow dupes: clone groups
// with stable fingerprints, clone families, duplication stats, thresholds,
// reviewed-clone keys, and baselines.
package dupes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/scanner"
	"go/token"
	"os"
	"path"
	"sort"
	"strings"

	"goose/internal/config"
	"goose/internal/facts"
	"goose/internal/report"
)

// Mode is the normalization level, from strictest to loosest.
type Mode string

// Detection modes.
const (
	ModeStrict   Mode = "strict"
	ModeMild     Mode = "mild"
	ModeWeak     Mode = "weak"
	ModeSemantic Mode = "semantic"
)

// Options control one duplication run.
type Options struct {
	Mode           Mode
	MinTokens      int
	MinLines       int
	MinOccurrences int
	SkipLocal      bool
	IgnoreImports  bool
	// Fragments keeps verbatim source text on JSON instances.
	Fragments bool
	// ChangedSince holds repo-relative changed paths. When non-nil, only
	// groups with a changed instance stay in scope.
	ChangedSince map[string]bool
	// PathScope keeps groups with at least one instance under this file or
	// directory.
	PathScope string
	// IgnoredClones holds reviewed "<fingerprint>:<count>" keys from
	// duplicates.ignoredClones.
	IgnoredClones map[string]bool
	// Ignore reports whether a file is excluded from duplication analysis.
	Ignore func(rel string) bool
}

// DefaultOptions matches the documented duplicates defaults.
func DefaultOptions() Options {
	return Options{
		Mode: ModeMild, MinTokens: 50, MinLines: 5, MinOccurrences: 2,
		IgnoreImports: true, Fragments: true,
	}
}

// FromConfig maps the duplicates section of a resolved config to options.
func FromConfig(cfg *config.Config) Options {
	o := DefaultOptions()
	d := cfg.Duplicates
	switch d.Mode {
	case "strict":
		o.Mode = ModeStrict
	case "weak":
		o.Mode = ModeWeak
	case "semantic":
		o.Mode = ModeSemantic
	}
	if d.MinTokens >= 8 {
		o.MinTokens = d.MinTokens
	}
	if d.MinLines > 1 {
		o.MinLines = d.MinLines
	}
	if d.MinOccurrences >= 2 {
		o.MinOccurrences = d.MinOccurrences
	}
	o.SkipLocal = d.SkipLocal
	if d.IgnoreImports != nil {
		o.IgnoreImports = *d.IgnoreImports
	}
	o.IgnoredClones = map[string]bool{}
	for _, k := range d.IgnoredClones {
		o.IgnoredClones[k] = true
	}
	return o
}

// Instance is one occurrence of a clone.
type Instance struct {
	Path      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	StartCol  int    `json:"start_col"`
	EndCol    int    `json:"end_col"`
	Fragment  string `json:"fragment,omitempty"`
}

// Group is one maximal repeated token sequence across several places.
type Group struct {
	Fingerprint string     `json:"fingerprint"`
	Tokens      int        `json:"tokens"`
	Lines       int        `json:"lines"`
	Score       float64    `json:"score"`
	Spread      int        `json:"spread"`
	Instances   []Instance `json:"instances"`
}

// Family counts groups that share one fingerprint.
type Family struct {
	Fingerprint string `json:"fingerprint"`
	Tokens      int    `json:"tokens"`
	Groups      int    `json:"groups"`
}

// Stats summarizes the corpus the run measured.
type Stats struct {
	FilesAnalyzed         int     `json:"files_analyzed"`
	AnalyzedLines         int     `json:"analyzed_lines"`
	DuplicatedLines       int     `json:"duplicated_lines"`
	FilesWithDuplication  int     `json:"files_with_duplication"`
	CloneGroups           int     `json:"clone_groups"`
	CloneFamilies         int     `json:"clone_families"`
	DuplicationPercentage float64 `json:"duplication_percentage"`
}

// MirroredDirs names two directories that share most of their file names.
type MirroredDirs struct {
	DirA        string   `json:"dir_a"`
	DirB        string   `json:"dir_b"`
	SharedFiles []string `json:"shared_files"`
	TotalLines  int      `json:"total_lines"`
}

// Result bundles one duplication pass.
type Result struct {
	Groups             []Group
	Families           []Family
	Stats              Stats
	MirroredDirs       []MirroredDirs
	CloneGroupsIgnored int
}

// tok is one normalized token with byte and line coordinates.
type tok struct {
	norm      uint64
	file      int
	line      int
	col       int
	byteStart int
	byteEnd   int
}

// fileData is one analyzed file.
type fileData struct {
	rel   string
	src   string
	lines int
}

type index struct {
	files []fileData
	p     []tok
	total int
}

// Detect runs the full duplication pipeline over the project.
func Detect(proj *facts.Project, opts Options) *Result {
	idx := buildIndex(proj, opts)
	res := &Result{}
	if idx != nil {
		for _, g := range detectGroups(idx, opts) {
			key := fmt.Sprintf("%s:%d", g.Fingerprint, len(g.Instances))
			if opts.IgnoredClones != nil && opts.IgnoredClones[key] {
				res.CloneGroupsIgnored++
				continue
			}
			if opts.PathScope != "" && !hasScope(g.Instances, opts.PathScope) {
				continue
			}
			if opts.ChangedSince != nil && !hasAnyChanged(g.Instances, opts.ChangedSince) {
				continue
			}
			res.Groups = append(res.Groups, g)
		}
	}
	rankGroups(res.Groups)
	res.Families = buildFamilies(res.Groups)
	res.MirroredDirs = findMirrors(res.Groups)
	res.Stats = computeStats(idx, res.Groups)
	res.Stats.CloneGroups = len(res.Groups)
	res.Stats.CloneFamilies = len(res.Families)
	return res
}

// ---------------------------------------------------------------------------
// Token stream.
// ---------------------------------------------------------------------------

func buildIndex(proj *facts.Project, opts Options) *index {
	idx := &index{}
	for _, ff := range sortedFiles(proj) {
		if opts.Ignore != nil && opts.Ignore(ff.Rel) || strings.TrimSpace(ff.Src) == "" {
			continue
		}
		fi := len(idx.files)
		idx.files = append(idx.files, fileData{rel: ff.Rel, src: ff.Src, lines: ff.Loc})
		idx.p = append(idx.p, tokenizeFile(fi, ff, opts)...)
		// The sentinel blocks clones from crossing a file boundary.
		idx.p = append(idx.p, tok{})
	}
	if len(idx.p) == 0 {
		return nil
	}
	for _, f := range idx.files {
		idx.total += f.lines
	}
	return idx
}

// tokenizeFile normalizes one file's tokens. The scanner exposes only a
// token's start position, so each token's end byte is the start of the next
// scanned token; the last token ends at EOF.
func tokenizeFile(fi int, ff *facts.FileFacts, opts Options) []tok {
	skip := importSkips(ff, opts.IgnoreImports)
	var sc scanner.Scanner
	fset := token.NewFileSet()
	f := fset.AddFile("f", -1, len(ff.Src))
	f.SetLinesForContent([]byte(ff.Src))
	sc.Init(f, []byte(ff.Src), nil, scanner.ScanComments)
	type raw struct {
		pos  token.Pos
		kind token.Token
		lit  string
	}
	var raws []raw
	var eof token.Pos
	for {
		pos, kind, lit := sc.Scan()
		if kind == token.EOF {
			eof = pos
			break
		}
		raws = append(raws, raw{pos, kind, lit})
	}
	var out []tok
	for i, r := range raws {
		line := fset.Position(r.pos).Line
		if r.kind == token.COMMENT || r.kind == token.ILLEGAL {
			continue
		}
		if inLines(line, skip) {
			continue
		}
		norm := normalize(r.kind, r.lit, opts.Mode)
		if norm == 0 || norm == 1 {
			continue
		}
		end := len(ff.Src)
		if i+1 < len(raws) {
			end = fset.Position(raws[i+1].pos).Offset
		} else {
			end = fset.Position(eof).Offset
		}
		out = append(out, tok{
			norm: norm, file: fi, line: line,
			col:       fset.Position(r.pos).Column - 1,
			byteStart: fset.Position(r.pos).Offset,
			byteEnd:   end,
		})
	}
	return out
}

// normalize maps a token to a mode-dependent id. Id 1 is reserved so no real
// token collides with the sentinel zero.
func normalize(t token.Token, lit string, mode Mode) uint64 {
	switch t {
	case token.IDENT:
		if mode == ModeStrict {
			return fhash("ID:" + lit)
		}
		return fhash("ID:_")
	case token.INT, token.FLOAT, token.IMAG, token.CHAR, token.STRING:
		if mode == ModeStrict || mode == ModeMild {
			return fhash("L:" + t.String() + ":" + lit)
		}
		if mode == ModeWeak {
			switch t {
			case token.STRING, token.CHAR:
				return fhash("L:STR")
			default:
				return fhash("L:NUM")
			}
		}
		return fhash("lit")
	}
	return fhash(t.String())
}

func fhash(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	if h <= 1 {
		h += 2
	}
	return h
}

// ---------------------------------------------------------------------------
// Suffix array and LCP.
// ---------------------------------------------------------------------------

// detectGroups scans LCP runs whose common length stays above MinTokens. A
// greedy claim pass keeps only maximal repeats: a candidate is accepted when
// at least MinOccurrences of its suffixes reach past everything claimed, and
// then it claims its windows.
func detectGroups(idx *index, opts Options) []Group {
	p := idx.p
	n := len(p)
	if n < 2*opts.MinTokens+2 {
		return nil
	}
	sa := suffixArray(p)
	lcp := kasaiLCP(p, sa)
	L := opts.MinTokens

	type candidate struct {
		positions []int
		length    int
	}
	var cands []candidate
	i := 1
	for i < n {
		if lcp[i] < L {
			i++
			continue
		}
		start := i - 1
		j := i
		minCommon := lcp[i]
		for j < n && lcp[j] >= L {
			if lcp[j] < minCommon {
				minCommon = lcp[j]
			}
			j++
		}
		end := j
		if end > n {
			end = n
		}
		positions := make([]int, 0, end-start)
		for _, p0 := range sa[start:end] {
			if isSentinel(&p[p0]) {
				continue
			}
			positions = append(positions, p0)
		}
		if trimmed := idx.trim(positions, minCommon); len(positions) >= opts.MinOccurrences && trimmed >= L {
			cands = append(cands, candidate{positions: positions, length: trimmed})
		}
		i = j
	}
	// Longest (and widest) candidates claim first so shorter sub-clones are
	// swallowed. A shorter run is still kept when its anchor is free.
	sort.SliceStable(cands, func(a, b int) bool {
		ca := cands[a].length * len(cands[a].positions)
		cb := cands[b].length * len(cands[b].positions)
		if ca != cb {
			return ca > cb
		}
		return cands[a].length > cands[b].length
	})

	type claim struct{ start, end int }
	var claimed []claim
	covered := func(pos, length int) bool {
		for _, c := range claimed {
			if c.start <= pos && pos <= c.end && length <= c.end-c.start+1 {
				return true
			}
		}
		return false
	}

	var groups []Group
	seenFP := map[string]bool{}
	for _, cd := range cands {
		var alive []int
		for _, p0 := range cd.positions {
			if p0 >= n || isSentinel(&p[p0]) {
				continue
			}
			if covered(p0, cd.length) {
				continue
			}
			alive = append(alive, p0)
		}
		if len(alive) < opts.MinOccurrences {
			continue
		}
		instances := idx.instances(alive, cd.length, opts)
		if len(instances) < opts.MinOccurrences {
			continue
		}
		if opts.SkipLocal {
			distinct := map[string]bool{}
			for _, in := range instances {
				distinct[in.Path] = true
			}
			if len(distinct) < 2 {
				continue
			}
		}
		lines := 0
		for _, in := range instances {
			if n2 := in.EndLine - in.StartLine + 1; n2 > lines {
				lines = n2
			}
		}
		if lines < opts.MinLines {
			continue
		}
		fp := idx.fingerprint(alive[0], cd.length)
		if seenFP[fp] {
			for _, p0 := range alive {
				claimed = append(claimed, claim{start: p0, end: p0 + cd.length - 1})
			}
			continue
		}
		seenFP[fp] = true
		for _, p0 := range alive {
			claimed = append(claimed, claim{start: p0, end: p0 + cd.length - 1})
		}
		groups = append(groups, Group{
			Fingerprint: fp, Tokens: cd.length, Lines: lines, Instances: instances,
		})
	}
	return groups
}

// trim shortens length until every suffix stops at a sentinel first.
func (idx *index) trim(positions []int, length int) int {
	minRun := length
	for _, p0 := range positions {
		run := 0
		for run < length && p0+run < len(idx.p) && !isSentinel(&idx.p[p0+run]) {
			run++
		}
		if run < minRun {
			minRun = run
		}
	}
	return minRun
}

func isSentinel(t *tok) bool { return t.norm == 0 }

// instances maps suffix positions to source instances, merging overlapping
// starts within one file.
func (idx *index) instances(positions []int, length int, opts Options) []Instance {
	var out []Instance
	for _, p0 := range positions {
		start := idx.p[p0]
		if isSentinel(&start) {
			continue
		}
		fd := idx.files[start.file]
		lastTok := endTokTill(idx, p0, length)
		in := Instance{
			Path: fd.rel, StartLine: start.line,
			EndLine: lastTok.line, StartCol: start.col,
		}
		in.EndCol = lineEndCol(fd.src, lastTok.line)
		if opts.Fragments {
			in.Fragment = strings.TrimRight(fd.src[start.byteStart:lastTok.byteEnd], " \t\n")
		}
		out = append(out, in)
	}
	// Merge instances in the same file whose spans overlap.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].StartLine < out[j].StartLine
	})
	merged := out[:0]
	var last *Instance
	for i := range out {
		in := out[i]
		if last != nil && in.Path == last.Path && in.StartLine <= last.EndLine {
			continue
		}
		merged = append(merged, in)
		last = &merged[len(merged)-1]
	}
	return merged
}

// endTokTill returns the last real token within [p0, p0+length) stopping at a
// sentinel.
func endTokTill(idx *index, p0, length int) tok {
	last := idx.p[p0]
	for k := 0; k < length && p0+k < len(idx.p); k++ {
		if isSentinel(&idx.p[p0+k]) {
			break
		}
		last = idx.p[p0+k]
	}
	return last
}

// fingerprint is a content hash of the normalized window: dup:<8hex>, stable
// while the tokens stay the same.
func (idx *index) fingerprint(p0, length int) string {
	h := sha256.New()
	for k := 0; k < length; k++ {
		if p0+k >= len(idx.p) || isSentinel(&idx.p[p0+k]) {
			break
		}
		fmt.Fprintf(h, "%016x\n", idx.p[p0+k].norm)
	}
	return "dup:" + hex.EncodeToString(h.Sum(nil)[:4])
}

// suffixArray builds a suffix array by prefix doubling over a coordinate-
// compressed token alphabet.
func suffixArray(s []tok) []int {
	n := len(s)
	sa := make([]int, n)
	for i := range sa {
		sa[i] = i
	}
	// Compress token hashes to small integer ranks.
	vals := make([]uint64, n)
	for i := range s {
		vals[i] = s[i].norm
	}
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool { return vals[order[i]] < vals[order[j]] })
	rank := make([]int, n)
	r := -1
	var prev uint64
	for idx, oi := range order {
		if idx == 0 || vals[oi] != prev {
			r++
			prev = vals[oi]
		}
		rank[oi] = r
	}
	tmp := make([]int, n)
	for k := 1; ; k *= 2 {
		by, rk := k, rank
		sort.SliceStable(sa, func(i, j int) bool {
			a, b := sa[i], sa[j]
			if rk[a] != rk[b] {
				return rk[a] < rk[b]
			}
			ra, rb := -1, -1
			if a+by < n {
				ra = rk[a+by]
			}
			if b+by < n {
				rb = rk[b+by]
			}
			return ra < rb
		})
		tmp[sa[0]] = 0
		for i := 1; i < n; i++ {
			tmp[sa[i]] = tmp[sa[i-1]]
			if rankPair(rank, sa[i-1], sa[i], by, n) < 0 {
				tmp[sa[i]]++
			}
		}
		copy(rank, tmp)
		if rank[sa[n-1]] == n-1 || k >= n {
			break
		}
	}
	return sa
}

func rankPair(rank []int, a, b, k, n int) int {
	if rank[a] != rank[b] {
		if rank[a] < rank[b] {
			return -1
		}
		return 1
	}
	ra, rb := -1, -1
	if a+k < n {
		ra = rank[a+k]
	}
	if b+k < n {
		rb = rank[b+k]
	}
	switch {
	case ra < rb:
		return -1
	case ra > rb:
		return 1
	}
	return 0
}

func kasaiLCP(s []tok, sa []int) []int {
	n := len(s)
	rank := make([]int, n)
	lcp := make([]int, n)
	for i, p := range sa {
		rank[p] = i
	}
	h := 0
	for i := 0; i < n; i++ {
		if rank[i] == 0 {
			continue
		}
		j := sa[rank[i]-1]
		for i+h < n && j+h < n && s[i+h].norm == s[j+h].norm {
			h++
		}
		lcp[rank[i]] = h
		if h > 0 {
			h--
		}
	}
	return lcp
}

// ---------------------------------------------------------------------------
// Ranking, families, mirrors, stats, filters.
// ---------------------------------------------------------------------------

func rankGroups(groups []Group) {
	for i := range groups {
		g := &groups[i]
		g.Spread = groupSpread(*g)
		boost := 1 + clampF(0.15*float64(g.Spread)/8.0, 0, 0.15)
		g.Score = float64(g.Tokens*len(g.Instances)) * boost
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Score != groups[j].Score {
			return groups[i].Score > groups[j].Score
		}
		if groups[i].Lines != groups[j].Lines {
			return groups[i].Lines > groups[j].Lines
		}
		if groups[i].Instances[0].Path != groups[j].Instances[0].Path {
			return groups[i].Instances[0].Path < groups[j].Instances[0].Path
		}
		return groups[i].Instances[0].StartLine < groups[j].Instances[0].StartLine
	})
}

func groupSpread(g Group) int {
	best := 0
	for i := 0; i < len(g.Instances); i++ {
		for j := i + 1; j < len(g.Instances); j++ {
			a, b := g.Instances[i], g.Instances[j]
			d := 0
			if a.Path == b.Path {
				if b.StartLine-a.StartLine > 0 {
					d = 1 + (b.StartLine-a.StartLine)/250
				}
			} else {
				d = dirDistance(a.Path, b.Path)
			}
			if d > best {
				best = d
			}
		}
	}
	return best
}

func dirDistance(a, b string) int {
	as := strings.Split(path.Dir(a), "/")
	bs := strings.Split(path.Dir(b), "/")
	i := 0
	for i < len(as) && i < len(bs) && as[i] == bs[i] {
		i++
	}
	return (len(as) - i) + (len(bs) - i)
}

func hasScope(instances []Instance, scope string) bool {
	scope = strings.TrimSuffix(scope, "/")
	for _, in := range instances {
		if in.Path == scope || strings.HasPrefix(in.Path, scope+"/") {
			return true
		}
	}
	return false
}

func hasAnyChanged(instances []Instance, changed map[string]bool) bool {
	for _, in := range instances {
		if changed[in.Path] {
			return true
		}
	}
	return false
}

func buildFamilies(groups []Group) []Family {
	byFP := map[string]*Family{}
	var order []string
	for _, g := range groups {
		f, ok := byFP[g.Fingerprint]
		if !ok {
			f = &Family{Fingerprint: g.Fingerprint, Tokens: g.Tokens}
			byFP[g.Fingerprint] = f
			order = append(order, g.Fingerprint)
		}
		f.Groups++
	}
	out := make([]Family, 0, len(order))
	for _, fp := range order {
		out = append(out, *byFP[fp])
	}
	return out
}

func computeStats(idx *index, groups []Group) Stats {
	st := Stats{}
	if idx != nil {
		st.FilesAnalyzed = len(idx.files)
		st.AnalyzedLines = idx.total
	}
	dupLinesByFile := map[string]map[int]bool{}
	involved := map[string]bool{}
	for _, g := range groups {
		for _, in := range g.Instances {
			involved[in.Path] = true
			linesMap := dupLinesByFile[in.Path]
			if linesMap == nil {
				linesMap = map[int]bool{}
				dupLinesByFile[in.Path] = linesMap
			}
			for line := in.StartLine; line <= in.EndLine; line++ {
				linesMap[line] = true
			}
		}
	}
	duped := 0
	for _, linesMap := range dupLinesByFile {
		duped += len(linesMap)
	}
	if st.AnalyzedLines > 0 && duped > st.AnalyzedLines {
		duped = st.AnalyzedLines
	}
	st.DuplicatedLines = duped
	st.FilesWithDuplication = len(involved)
	if st.AnalyzedLines > 0 {
		st.DuplicationPercentage = round2(100 * float64(duped) / float64(st.AnalyzedLines))
	}
	return st
}

func findMirrors(groups []Group) []MirroredDirs {
	type pair struct{ a, b string }
	counts := map[pair]map[string]int{}
	lines := map[pair]int{}
	for _, g := range groups {
		for i := 0; i < len(g.Instances); i++ {
			for j := i + 1; j < len(g.Instances); j++ {
				a, b := g.Instances[i], g.Instances[j]
				da, db := path.Dir(a.Path), path.Dir(b.Path)
				if da == db || path.Base(a.Path) != path.Base(b.Path) {
					continue
				}
				if da > db {
					da, db = db, da
				}
				pr := pair{da, db}
				if counts[pr] == nil {
					counts[pr] = map[string]int{}
				}
				counts[pr][path.Base(a.Path)] = g.Lines
				lines[pr] += g.Lines
			}
		}
	}
	var out []MirroredDirs
	for pr, files := range counts {
		if len(files) < 2 {
			continue
		}
		shared := make([]string, 0, len(files))
		for f := range files {
			shared = append(shared, f)
		}
		sort.Strings(shared)
		out = append(out, MirroredDirs{DirA: pr.a, DirB: pr.b, SharedFiles: shared, TotalLines: lines[pr]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TotalLines > out[j].TotalLines })
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// Doc renders the run into a report envelope.
func (r *Result) Doc(threshold float64, failOnIssues, fragments bool, elapsed int64) *report.Doc {
	doc := report.NewDoc("dupes")
	stats := map[string]any{
		"files_analyzed":         r.Stats.FilesAnalyzed,
		"analyzed_lines":         r.Stats.AnalyzedLines,
		"duplicated_lines":       r.Stats.DuplicatedLines,
		"files_with_duplication": r.Stats.FilesWithDuplication,
		"clone_groups":           r.Stats.CloneGroups,
		"clone_families":         r.Stats.CloneFamilies,
		"duplication_percentage": r.Stats.DuplicationPercentage,
	}
	if r.CloneGroupsIgnored > 0 {
		stats["clone_groups_ignored"] = r.CloneGroupsIgnored
	}
	doc.Envelope["stats"] = stats
	if len(r.MirroredDirs) > 0 {
		doc.Envelope["mirrored_directories"] = r.MirroredDirs
	}
	groupsJSON := make([]any, 0, len(r.Groups))
	for _, g := range r.Groups {
		insts := make([]any, 0, len(g.Instances))
		for _, in := range g.Instances {
			m := map[string]any{
				"file": in.Path, "start_line": in.StartLine, "end_line": in.EndLine,
				"start_col": in.StartCol, "end_col": in.EndCol,
			}
			if in.Fragment != "" && fragments {
				m["fragment"] = in.Fragment
			}
			insts = append(insts, m)
		}
		groupsJSON = append(groupsJSON, map[string]any{
			"fingerprint": g.Fingerprint, "tokens": g.Tokens, "lines": g.Lines,
			"score": round2(g.Score), "spread": g.Spread, "instances": insts,
			"actions": []any{map[string]any{
				"type":         "extract-function",
				"description":  fmt.Sprintf("Extract the %d shared lines into one helper.", g.Lines),
				"note":         fmt.Sprintf("Estimated saving: %d lines.", g.Lines*(len(g.Instances)-1)),
				"auto_fixable": false,
			}},
		})
	}
	doc.Envelope["clone_groups"] = groupsJSON
	fams := make([]any, 0, len(r.Families))
	for _, f := range r.Families {
		fams = append(fams, map[string]any{"fingerprint": f.Fingerprint, "tokens": f.Tokens, "groups": f.Groups})
	}
	doc.Envelope["clone_families"] = fams
	doc.Envelope["clone_groups_shown"] = len(r.Groups)
	doc.Envelope["clone_groups_omitted"] = 0
	doc.Envelope["clone_families_shown"] = len(r.Families)
	doc.Envelope["clone_families_omitted"] = 0
	doc.ElapsedMS = elapsed
	// Shared-format findings.
	for _, g := range r.Groups {
		doc.Findings = append(doc.Findings, &report.Finding{
			Kind: "clone-group", Rule: "duplicated-code",
			Path: g.Instances[0].Path, Line: g.Instances[0].StartLine,
			Message:  fmt.Sprintf("%d lines duplicated across %d places (%s)", g.Lines, len(g.Instances), g.Fingerprint),
			Severity: config.Warn,
			ID:       g.Fingerprint,
			Extra: map[string]any{
				"fingerprint": g.Fingerprint, "instances": len(g.Instances),
				"lines": g.Lines, "tokens": g.Tokens,
			},
		})
	}
	if threshold > 0 {
		status := "passed"
		if r.Stats.DuplicationPercentage > threshold {
			status = "failed"
		}
		doc.Gates["duplication-threshold"] = &report.Gate{
			Status: status, Enforced: true,
			Observed: r.Stats.DuplicationPercentage, Threshold: threshold,
		}
	}
	if failOnIssues {
		status := "passed"
		if len(r.Groups) > 0 {
			status = "failed"
		}
		doc.Gates["duplication-findings"] = &report.Gate{
			Status: status, Enforced: true, Observed: len(r.Groups), Threshold: 0,
		}
	}
	return doc
}

// ---------------------------------------------------------------------------
// Baseline.
// ---------------------------------------------------------------------------

// Baseline is the saved dupes baseline keyed by "<fingerprint>:<count>".
type Baseline struct {
	Kind    string         `json:"kind"`
	Version string         `json:"version,omitempty"`
	SavedBy string         `json:"saved_by,omitempty"`
	Entries map[string]int `json:"entries"`
}

// LoadBaseline reads a dupes baseline file.
func LoadBaseline(p string) (*Baseline, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("invalid baseline %s: %w", p, err)
	}
	if b.Entries == nil {
		b.Entries = map[string]int{}
	}
	return &b, nil
}

// SaveBaseline writes the run as a baseline.
func SaveBaseline(p string, r *Result, ver string) error {
	b := Baseline{Kind: "dupes", Version: ver, SavedBy: "dupes", Entries: map[string]int{}}
	for _, g := range r.Groups {
		b.Entries[fmt.Sprintf("%s:%d", g.Fingerprint, len(g.Instances))]++
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(data, '\n'), 0o644)
}

// ApplyBaseline masks clone groups the baseline covers and counts stale keys.
func ApplyBaseline(r *Result, b *Baseline) (stale int) {
	counts := map[string]int{}
	for k, n := range b.Entries {
		counts[k] = n
	}
	var kept []Group
	for _, g := range r.Groups {
		key := fmt.Sprintf("%s:%d", g.Fingerprint, len(g.Instances))
		if counts[key] > 0 {
			counts[key]--
			continue
		}
		kept = append(kept, g)
	}
	for _, n := range counts {
		if n > 0 {
			stale++
		}
	}
	r.Groups = kept
	r.Stats.CloneGroups = len(kept)
	return stale
}

// Staleness reports how much of a loaded baseline still matches.
type Staleness struct {
	BaselineEntries int `json:"baseline_entries"`
	StaleEntries    int `json:"stale_entries"`
	CurrentEntries  int `json:"current_findings"`
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

func importSkips(ff *facts.FileFacts, enabled bool) [][2]int {
	if !enabled {
		return nil
	}
	var ranges [][2]int
	lines := strings.Split(ff.Src, "\n")
	inBlock := false
	var block [2]int
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		switch {
		case !inBlock && strings.HasPrefix(t, "import ("):
			inBlock = true
			block = [2]int{i + 1, i + 1}
		case inBlock:
			block[1] = i + 1
			if strings.Contains(t, ")") {
				ranges = append(ranges, block)
				inBlock = false
			}
		case strings.HasPrefix(t, "import ") && !inBlock:
			ranges = append(ranges, [2]int{i + 1, i + 1})
		}
	}
	return ranges
}

func inLines(line int, ranges [][2]int) bool {
	for _, r := range ranges {
		if line >= r[0] && line <= r[1] {
			return true
		}
	}
	return false
}

func lineEndCol(src string, line int) int {
	start := lineOffset(src, line)
	if start >= len(src) {
		return 0
	}
	if idx := strings.IndexByte(src[start:], '\n'); idx >= 0 {
		return idx
	}
	return len(src) - start
}

func lineOffset(src string, line int) int {
	if line <= 1 {
		return 0
	}
	off, cur := 0, 1
	for off < len(src) && cur < line {
		if src[off] == '\n' {
			cur++
		}
		off++
	}
	if cur < line {
		return len(src)
	}
	return off
}

func clampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func round2(v float64) float64 { return float64(int(v*100+0.5)) / 100 }

func sortedFiles(p *facts.Project) []*facts.FileFacts { return p.NonTestFiles() }

// DivergedCloneSiblings reports clone groups where at least one instance sits
// in changedSet while at least one sibling instance sits in an unchanged file.
func DivergedCloneSiblings(groups []Group, changedSet map[string]bool, cfg *config.Config) []*report.Finding {
	const rule = "diverged-clone-sibling"
	if cfg == nil || !cfg.RuleEnabled(rule) || len(changedSet) == 0 {
		return nil
	}
	var out []*report.Finding
	for _, g := range groups {
		var changedInsts []Instance
		var untouchedSiblings []string
		for _, in := range g.Instances {
			if changedSet[in.Path] {
				changedInsts = append(changedInsts, in)
			} else {
				untouchedSiblings = append(untouchedSiblings, fmt.Sprintf("%s:%d-%d", in.Path, in.StartLine, in.EndLine))
			}
		}
		if len(changedInsts) == 0 || len(untouchedSiblings) == 0 {
			continue
		}
		for _, ci := range changedInsts {
			sev := cfg.RuleSeverity(rule, ci.Path)
			if sev == config.Off {
				continue
			}
			out = append(out, &report.Finding{
				Kind: "diverged-clone-sibling", Rule: rule,
				Path: ci.Path, Line: ci.StartLine, Col: ci.StartCol,
				Message:  fmt.Sprintf("Clone group %s was modified in %s while sibling(s) %s were not updated", g.Fingerprint, ci.Path, strings.Join(untouchedSiblings, ", ")),
				Severity: sev,
				ID:       report.Fingerprint("diverged-clone-sibling", ci.Path, g.Fingerprint, fmt.Sprint(ci.StartLine)),
				Extra: map[string]any{
					"symbol":      g.Fingerprint,
					"fingerprint": g.Fingerprint,
					"siblings":    untouchedSiblings,
				},
			})
		}
	}
	return out
}
