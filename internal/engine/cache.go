package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/modfile"

	"goose/internal/config"
	"goose/internal/facts"
	"goose/internal/loader"
	"goose/internal/version"
)

const cacheSchemaVersion = "goose-facts-cache-v4"

var (
	binFpOnce sync.Once
	binFpVal  string
)

// binarySelfFingerprint returns a stable identity string for the running goose
// binary (version + build info + resolved executable size + mtime) so rebuilding
// or upgrading goose automatically busts stale cache entries.
func binarySelfFingerprint() string {
	binFpOnce.Do(func() {
		var b strings.Builder
		b.WriteString(version.Version)
		if bi, ok := debug.ReadBuildInfo(); ok {
			b.WriteByte(':')
			b.WriteString(bi.Main.Version)
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision", "vcs.time", "vcs.modified", "-tags", "-ldflags", "CGO_ENABLED":
					fmt.Fprintf(&b, ":%s=%s", s.Key, s.Value)
				}
			}
		}
		if exe, err := os.Executable(); err == nil && exe != "" {
			if realExe, rerr := filepath.EvalSymlinks(exe); rerr == nil && realExe != "" {
				exe = realExe
			}
			if st, stErr := os.Stat(exe); stErr == nil {
				fmt.Fprintf(&b, ":%s:%d:%d", exe, st.Size(), st.ModTime().UnixNano())
			}
		}
		binFpVal = b.String()
	})
	return binFpVal
}

type cachedFuncInfo struct {
	Loc            int
	BodyLoc        int
	Params         int
	Results        int
	Cyclomatic     int
	Cognitive      int
	Statements     int
	IsTest         bool
	IsInit         bool
	IsMain         bool
	RecvTypeName   string
	UnusedParams   []facts.ParamFact
	UnusedReceiver *facts.ParamFact
}

type cachedEntity struct {
	Key                   facts.Key
	Kind                  facts.Kind
	PkgPath               string
	PkgName               string
	Recv                  string
	Name                  string
	File                  string
	Line                  int
	Col                   int
	Exported              bool
	Doc                   string
	Deprecated            bool
	TestFile              bool
	InterfaceMethod       bool
	Func                  *cachedFuncInfo
	Field                 *facts.FieldInfo
	Local                 bool
	DocTags               map[string]bool
	PrivateTypeCandidates []string
	StructSize            int64
	OptimalStructSize     int64
}

type cachedSnapshot struct {
	Module             facts.ModuleInfo
	Files              map[string]*facts.FileFacts
	Entities           map[facts.Key]*cachedEntity
	Uses               map[facts.Key][]facts.UseSite
	EntitySpans        map[facts.Key][]facts.Span
	EntryPkgs          map[string]bool
	InterfaceMethods   map[facts.Key][]facts.Key
	InterfaceSatisfied map[facts.Key]bool
	ReflectivePkgs     map[string]bool
	SkippedFiles       map[string]bool
	LoaderSkipped      []loader.SkippedFile
	Tests              bool
}

func resolveCacheDir(cfg *config.Config) string {
	if cfg != nil && cfg.Cache.Dir != "" {
		if filepath.IsAbs(cfg.Cache.Dir) {
			return cfg.Cache.Dir
		}
		if cfg.Root != "" {
			return filepath.Join(cfg.Root, cfg.Cache.Dir)
		}
		return cfg.Cache.Dir
	}
	if dir, err := os.UserCacheDir(); err == nil && dir != "" {
		return filepath.Join(dir, "goose", "v1")
	}
	return filepath.Join(os.TempDir(), "goose-cache-v1")
}

func computeCacheKey(dir string, tests bool, maxFileSizeMB float64) (string, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	mod, err := loader.FindModule(absDir)
	if err != nil {
		return "", err
	}
	// Resolve workspace and transitive local replace directories.
	wsDirs := map[string]bool{}
	seenRealDirs := map[string]bool{}
	var extraRoots []string
	var queue []string
	enqueue := func(p string) {
		if p == "" {
			return
		}
		if ap, aerr := filepath.Abs(p); aerr == nil {
			p = ap
		}
		rp := canonicalPath(p)
		wsDirs[p] = true
		wsDirs[rp] = true
		if seenRealDirs[rp] {
			return
		}
		seenRealDirs[rp] = true
		queue = append(queue, p)
		extraRoots = append(extraRoots, p)
	}

	if mod.Dir != "" {
		enqueue(mod.Dir)
	}
	for _, ws := range mod.Workspaces {
		enqueue(ws)
	}
	if mod.WorkFile != "" {
		for _, repDir := range localReplaceDirsFromWork(mod.WorkFile) {
			enqueue(repDir)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, repDir := range localReplaceDirs(cur) {
			enqueue(repDir)
		}
	}

	var files []string
	var vendorMeta []string
	walkRoot := func(root string) error {
		return filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				if path == root {
					return nil
				}
				name := d.Name()
				if name == "vendor" {
					if mtxt := filepath.Join(path, "modules.txt"); fileExists(mtxt) {
						files = append(files, mtxt)
					}
					vendorMeta = append(vendorMeta, collectVendorMeta(path)...)
					return filepath.SkipDir
				}
				if name == "testdata" || name == "node_modules" ||
					strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
					return filepath.SkipDir
				}
				if !wsDirs[path] && !wsDirs[canonicalPath(path)] {
					if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 {
				st, serr := os.Stat(path)
				if serr != nil {
					return nil
				}
				if st.IsDir() {
					if d.Name() == "vendor" {
						if mtxt := filepath.Join(path, "modules.txt"); fileExists(mtxt) {
							files = append(files, mtxt)
						}
						vendorMeta = append(vendorMeta, collectVendorMeta(path)...)
					}
					return nil
				}
			}
			name := d.Name()
			if name == "go.mod" || name == "go.sum" || name == "go.work" || name == "go.work.sum" {
				files = append(files, path)
				return nil
			}
			if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return nil
			}
			if strings.HasSuffix(name, ".go") {
				if !tests && strings.HasSuffix(name, "_test.go") {
					return nil
				}
				files = append(files, path)
				return nil
			}
			if isCgoOrAsmFile(name) {
				files = append(files, path)
			}
			return nil
		})
	}

	if err := walkRoot(absDir); err != nil {
		return "", err
	}
	walkedReal := map[string]bool{canonicalPath(absDir): true}
	if mod.Dir != "" && mod.Dir != absDir {
		for _, mf := range []string{"go.mod", "go.sum", "go.work", "go.work.sum"} {
			p := filepath.Join(mod.Dir, mf)
			if fileExists(p) {
				files = append(files, p)
			}
		}
		vdir := filepath.Join(mod.Dir, "vendor")
		if mtxt := filepath.Join(vdir, "modules.txt"); fileExists(mtxt) {
			files = append(files, mtxt)
		}
		vendorMeta = append(vendorMeta, collectVendorMeta(vdir)...)
	}
	if mod.WorkFile != "" {
		for _, wf := range []string{mod.WorkFile, mod.WorkFile + ".sum"} {
			if fileExists(wf) {
				files = append(files, wf)
			}
		}
	}
	realAbsDir := canonicalPath(absDir)
	for _, r := range extraRoots {
		realR := canonicalPath(r)
		if walkedReal[realR] {
			continue
		}
		// Skip if r is already strictly under absDir (already walked by walkRoot(absDir)).
		if strings.HasPrefix(realR, realAbsDir+string(filepath.Separator)) {
			walkedReal[realR] = true
			continue
		}
		if st, serr := os.Stat(r); serr != nil || !st.IsDir() {
			continue
		}
		walkedReal[realR] = true
		_ = walkRoot(r)
	}
	if len(files) == 0 {
		return "", fmt.Errorf("no files")
	}
	sort.Strings(files)
	sort.Strings(vendorMeta)

	gitDirs := make([]string, 0, 3+len(extraRoots))
	gitDirs = append(gitDirs, absDir)
	if mod.Dir != "" {
		gitDirs = append(gitDirs, mod.Dir)
	}
	if mod.WorkFile != "" {
		gitDirs = append(gitDirs, filepath.Dir(mod.WorkFile))
	}
	gitDirs = append(gitDirs, extraRoots...)
	gitFps, err := gitRepoFingerprints(gitDirs)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%v\x00%v\x00",
		cacheSchemaVersion, binarySelfFingerprint(), goBinaryFingerprint(),
		runtime.Version(), runtime.GOOS, runtime.GOARCH,
		absDir, tests, maxFileSizeMB)
	for _, k := range toolchainEnvKeys {
		fmt.Fprintf(h, "%s=%s\x00", k, os.Getenv(k))
	}
	for _, gfp := range gitFps {
		h.Write([]byte("g:"))
		h.Write([]byte(gfp))
		h.Write([]byte{0})
	}
	prevVM := ""
	for _, vm := range vendorMeta {
		if vm == prevVM {
			continue
		}
		prevVM = vm
		h.Write([]byte("v:"))
		h.Write([]byte(vm))
		h.Write([]byte{0})
	}

	prev := ""
	for _, f := range files {
		if f == prev {
			continue
		}
		prev = f
		fh, readErr := hashFileSHA256(f)
		if readErr != nil {
			return "", readErr
		}
		h.Write([]byte(f))
		h.Write([]byte{0})
		h.Write(fh[:])
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var toolchainEnvKeys = []string{
	"GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS", "GOWORK", "GOEXPERIMENT",
	"GOARM", "GOAMD64", "GO386", "GOMIPS", "GOMIPS64", "GOPPC64", "GORISCV64", "GOWASM",
	"GOMOD", "GOTOOLCHAIN", "GODEBUG", "GOPATH", "GOMODCACHE", "GOROOT", "GOCACHE", "HOME",
	"CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS",
}

func goBinaryFingerprint() string {
	p, err := exec.LookPath("go")
	if err != nil || p == "" {
		return ""
	}
	if realP, rerr := filepath.EvalSymlinks(p); rerr == nil && realP != "" {
		p = realP
	}
	st, err := os.Stat(p)
	if err != nil {
		return p
	}
	return fmt.Sprintf("%s:%d:%d", p, st.Size(), st.ModTime().UnixNano())
}

func canonicalPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil && r != "" {
		return filepath.Clean(r)
	}
	return filepath.Clean(p)
}

func isCgoOrAsmFile(name string) bool {
	switch filepath.Ext(name) {
	case ".c", ".h", ".hh", ".hpp", ".cc", ".cpp", ".cxx", ".s", ".S", ".syso":
		return true
	}
	return false
}

func collectVendorMeta(vendorRoot string) []string {
	st, err := os.Stat(vendorRoot)
	if err != nil || !st.IsDir() {
		return nil
	}
	var out []string
	_ = filepath.WalkDir(vendorRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path != vendorRoot && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if st, serr := os.Stat(path); serr != nil || st.IsDir() {
				return nil
			}
		}
		name := d.Name()
		if name == "go.mod" || strings.HasSuffix(name, ".go") || isCgoOrAsmFile(name) {
			if info, ierr := os.Stat(path); ierr == nil {
				out = append(out, fmt.Sprintf("%s\x00%d\x00%d", path, info.Size(), info.ModTime().UnixNano()))
			}
		}
		return nil
	})
	return out
}

func hashFileSHA256(path string) ([32]byte, error) {
	var zero [32]byte
	f, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return zero, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func localReplaceDirs(modDir string) []string {
	gomod := filepath.Join(modDir, "go.mod")
	data, err := os.ReadFile(gomod)
	if err != nil {
		return nil
	}
	f, err := modfile.Parse(gomod, data, nil)
	if err != nil {
		return nil
	}
	return resolveReplaceTargets(modDir, f.Replace)
}

func localReplaceDirsFromWork(workFile string) []string {
	data, err := os.ReadFile(workFile)
	if err != nil {
		return nil
	}
	f, err := modfile.ParseWork(workFile, data, nil)
	if err != nil {
		return nil
	}
	return resolveReplaceTargets(filepath.Dir(workFile), f.Replace)
}

func resolveReplaceTargets(baseDir string, replaces []*modfile.Replace) []string {
	var out []string
	for _, rep := range replaces {
		p := rep.New.Path
		if p == "" || rep.New.Version != "" {
			continue
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(baseDir, filepath.FromSlash(p))
		}
		if abs, aerr := filepath.Abs(p); aerr == nil {
			if st, serr := os.Stat(abs); serr == nil && st.IsDir() {
				out = append(out, abs)
			}
		}
	}
	return out
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func loadCachedSnapshot(cacheDir, key string, maxAgeDays *int) (*loader.Loaded, *facts.Project, bool) {
	if key == "" || cacheDir == "" {
		return nil, nil, false
	}
	path := filepath.Join(cacheDir, key+".gob")
	if maxAgeDays != nil {
		if *maxAgeDays <= 0 {
			_ = os.Remove(path)
			return nil, nil, false
		}
		if st, err := os.Stat(path); err == nil {
			if time.Since(st.ModTime()) > time.Duration(*maxAgeDays)*24*time.Hour {
				_ = os.Remove(path)
				return nil, nil, false
			}
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, false
	}
	var snap cachedSnapshot
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&snap); err != nil {
		_ = os.Remove(path)
		return nil, nil, false
	}
	entities := make(map[facts.Key]*facts.Entity, len(snap.Entities))
	for k, ce := range snap.Entities {
		var fi *facts.FuncInfo
		if ce.Func != nil {
			fi = &facts.FuncInfo{
				Loc:            ce.Func.Loc,
				BodyLoc:        ce.Func.BodyLoc,
				Params:         ce.Func.Params,
				Results:        ce.Func.Results,
				Cyclomatic:     ce.Func.Cyclomatic,
				Cognitive:      ce.Func.Cognitive,
				Statements:     ce.Func.Statements,
				IsTest:         ce.Func.IsTest,
				IsInit:         ce.Func.IsInit,
				IsMain:         ce.Func.IsMain,
				RecvTypeName:   ce.Func.RecvTypeName,
				UnusedParams:   ce.Func.UnusedParams,
				UnusedReceiver: ce.Func.UnusedReceiver,
			}
		}
		entities[k] = &facts.Entity{
			Key:                   ce.Key,
			Kind:                  ce.Kind,
			PkgPath:               ce.PkgPath,
			PkgName:               ce.PkgName,
			Recv:                  ce.Recv,
			Name:                  ce.Name,
			File:                  ce.File,
			Line:                  ce.Line,
			Col:                   ce.Col,
			Exported:              ce.Exported,
			Doc:                   ce.Doc,
			Deprecated:            ce.Deprecated,
			TestFile:              ce.TestFile,
			InterfaceMethod:       ce.InterfaceMethod,
			Func:                  fi,
			Field:                 ce.Field,
			Local:                 ce.Local,
			DocTags:               ce.DocTags,
			PrivateTypeCandidates: ce.PrivateTypeCandidates,
			StructSize:            ce.StructSize,
			OptimalStructSize:     ce.OptimalStructSize,
		}
	}
	fset := token.NewFileSet()
	proj := &facts.Project{
		Module:             snap.Module,
		Files:              snap.Files,
		Entities:           entities,
		Uses:               snap.Uses,
		EntitySpans:        snap.EntitySpans,
		EntryPkgs:          snap.EntryPkgs,
		InterfaceMethods:   snap.InterfaceMethods,
		InterfaceSatisfied: snap.InterfaceSatisfied,
		ReflectivePkgs:     snap.ReflectivePkgs,
		SkippedFiles:       snap.SkippedFiles,
		Fset:               fset,
	}
	if proj.Files == nil {
		proj.Files = map[string]*facts.FileFacts{}
	}
	if proj.Uses == nil {
		proj.Uses = map[facts.Key][]facts.UseSite{}
	}
	if proj.EntitySpans == nil {
		proj.EntitySpans = map[facts.Key][]facts.Span{}
	}
	if proj.EntryPkgs == nil {
		proj.EntryPkgs = map[string]bool{}
	}
	if proj.InterfaceMethods == nil {
		proj.InterfaceMethods = map[facts.Key][]facts.Key{}
	}
	if proj.InterfaceSatisfied == nil {
		proj.InterfaceSatisfied = map[facts.Key]bool{}
	}
	if proj.ReflectivePkgs == nil {
		proj.ReflectivePkgs = map[string]bool{}
	}
	if proj.SkippedFiles == nil {
		proj.SkippedFiles = map[string]bool{}
	}
	ld := &loader.Loaded{
		Fset: setFset(fset),
		Module: loader.Module{
			Path:       snap.Module.Path,
			Dir:        snap.Module.Dir,
			Requires:   snap.Module.Requires,
			Vendor:     snap.Module.Vendor,
			WorkFile:   snap.Module.WorkFile,
			Workspaces: snap.Module.Workspaces,
		},
		Tests:        snap.Tests,
		Files:        map[string]*loader.FileEntry{},
		SkippedFiles: snap.LoaderSkipped,
	}
	return ld, proj, true
}

func setFset(fset *token.FileSet) *token.FileSet {
	return fset
}

func saveCachedSnapshot(cacheDir, key string, ld *loader.Loaded, proj *facts.Project, maxSizeMB int, maxAgeDays *int) {
	if key == "" || cacheDir == "" || ld == nil || proj == nil || len(ld.TypeErrors) > 0 {
		return
	}
	if maxAgeDays != nil && *maxAgeDays <= 0 {
		pruneCacheDir(cacheDir, int64(maxSizeMB)*1024*1024, maxAgeDays)
		return
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return
	}
	entities := make(map[facts.Key]*cachedEntity, len(proj.Entities))
	for k, e := range proj.Entities {
		var fi *cachedFuncInfo
		if e.Func != nil {
			fi = &cachedFuncInfo{
				Loc:            e.Func.Loc,
				BodyLoc:        e.Func.BodyLoc,
				Params:         e.Func.Params,
				Results:        e.Func.Results,
				Cyclomatic:     e.Func.Cyclomatic,
				Cognitive:      e.Func.Cognitive,
				Statements:     e.Func.Statements,
				IsTest:         e.Func.IsTest,
				IsInit:         e.Func.IsInit,
				IsMain:         e.Func.IsMain,
				RecvTypeName:   e.Func.RecvTypeName,
				UnusedParams:   e.Func.UnusedParams,
				UnusedReceiver: e.Func.UnusedReceiver,
			}
		}
		entities[k] = &cachedEntity{
			Key:                   e.Key,
			Kind:                  e.Kind,
			PkgPath:               e.PkgPath,
			PkgName:               e.PkgName,
			Recv:                  e.Recv,
			Name:                  e.Name,
			File:                  e.File,
			Line:                  e.Line,
			Col:                   e.Col,
			Exported:              e.Exported,
			Doc:                   e.Doc,
			Deprecated:            e.Deprecated,
			TestFile:              e.TestFile,
			InterfaceMethod:       e.InterfaceMethod,
			Func:                  fi,
			Field:                 e.Field,
			Local:                 e.Local,
			DocTags:               e.DocTags,
			PrivateTypeCandidates: e.PrivateTypeCandidates,
			StructSize:            e.StructSize,
			OptimalStructSize:     e.OptimalStructSize,
		}
	}
	snap := cachedSnapshot{
		Module:             proj.Module,
		Files:              proj.Files,
		Entities:           entities,
		Uses:               proj.Uses,
		EntitySpans:        proj.EntitySpans,
		EntryPkgs:          proj.EntryPkgs,
		InterfaceMethods:   proj.InterfaceMethods,
		InterfaceSatisfied: proj.InterfaceSatisfied,
		ReflectivePkgs:     proj.ReflectivePkgs,
		SkippedFiles:       proj.SkippedFiles,
		LoaderSkipped:      ld.SkippedFiles,
		Tests:              ld.Tests,
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&snap); err != nil {
		return
	}
	tmp, err := os.CreateTemp(cacheDir, "tmp-*.gob")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	dst := filepath.Join(cacheDir, key+".gob")
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
	}
	if maxSizeMB > 0 || maxAgeDays != nil {
		pruneCacheDir(cacheDir, int64(maxSizeMB)*1024*1024, maxAgeDays)
	}
}

func pruneCacheDir(cacheDir string, maxBytes int64, maxAgeDays *int) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return
	}
	type item struct {
		path  string
		size  int64
		mtime time.Time
	}
	var items []item
	var total int64
	var ttl time.Duration
	hasTTL := false
	if maxAgeDays != nil {
		hasTTL = true
		if *maxAgeDays > 0 {
			ttl = time.Duration(*maxAgeDays) * 24 * time.Hour
		}
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".gob") {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		p := filepath.Join(cacheDir, e.Name())
		if hasTTL && (*maxAgeDays <= 0 || time.Since(info.ModTime()) > ttl) {
			_ = os.Remove(p)
			continue
		}
		items = append(items, item{path: p, size: info.Size(), mtime: info.ModTime()})
		total += info.Size()
	}
	if maxBytes <= 0 || total <= maxBytes {
		return
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].mtime.Before(items[j].mtime)
	})
	for _, it := range items {
		if total <= maxBytes {
			break
		}
		if os.Remove(it.path) == nil {
			total -= it.size
		}
	}
}

