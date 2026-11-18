package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"goose/internal/architecture"
	"goose/internal/config"
	"goose/internal/deadcode"
	"goose/internal/facts"
	"goose/internal/health"
)

func TestIsStdPathGoroot(t *testing.T) {
	for _, pkg := range []string{"fmt", "net/http", "crypto/sha256", "unsafe", "builtin", "C"} {
		if !IsStdPath(pkg, nil) {
			t.Errorf("expected %q to be recognized as stdlib", pkg)
		}
	}
	for _, nonStd := range []string{"nonexistent_stdlib_pkg_xyz", "github.com/example/pkg", "golang.org/x/mod/modfile"} {
		if IsStdPath(nonStd, nil) {
			t.Errorf("expected %q NOT to be recognized as stdlib", nonStd)
		}
	}
}

func TestCacheParityAndInvalidation(t *testing.T) {
	tmp := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")

	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("go.mod", "module example.com/cachetest\n\ngo 1.22\n")
	write("main.go", `package main

import "example.com/cachetest/pkg"

func main() {
	_ = pkg.ExportedFunc()
}
`)
	write("pkg/pkg.go", `package pkg

type secret struct {
	x int
}

// ExportedFunc leaks unexported type secret.
func ExportedFunc() *secret {
	return &secret{x: 1}
}

func UnusedExport() int {
	return 42
}
`)

	cfg := config.Defaults()
	cfg.Root = tmp
	cfg.Cache.Dir = cacheDir
	cfg.Rules["private-type-leaks"] = "error"

	// 1. Cold run (populates cache).
	ctx1, err := LoadAndBuild(context.Background(), cfg, true)
	if err != nil {
		t.Fatalf("cold LoadAndBuild failed: %v", err)
	}
	doc1 := ctx1.DeadCode(deadcode.Options{})
	h1 := ctx1.Health(HealthInput{Options: health.Options{Complexity: true, FileScores: true, Score: true}})

	// 2. Warm run (loads from gob cache).
	ctx2, err := LoadAndBuild(context.Background(), cfg, true)
	if err != nil {
		t.Fatalf("warm LoadAndBuild failed: %v", err)
	}
	if len(ctx2.Loaded.Pkgs) != 0 {
		t.Fatalf("expected warm LoadAndBuild to load from cache (Loaded.Pkgs empty), got %d pkgs", len(ctx2.Loaded.Pkgs))
	}
	doc2 := ctx2.DeadCode(deadcode.Options{})
	h2 := ctx2.Health(HealthInput{Options: health.Options{Complexity: true, FileScores: true, Score: true}})

	if len(doc1.Findings) != len(doc2.Findings) {
		t.Fatalf("finding count mismatch between cold (%d) and warm (%d)", len(doc1.Findings), len(doc2.Findings))
	}
	sawLeak := false
	for i := range doc1.Findings {
		if doc1.Findings[i].ID != doc2.Findings[i].ID || doc1.Findings[i].Message != doc2.Findings[i].Message {
			t.Errorf("finding[%d] mismatch: cold=%+v warm=%+v", i, doc1.Findings[i], doc2.Findings[i])
		}
		if doc2.Findings[i].Kind == "private-type-leak" {
			sawLeak = true
		}
	}
	if !sawLeak {
		t.Errorf("expected private-type-leak finding in cached run")
	}
	if h1.Score.Score != h2.Score.Score {
		t.Errorf("health score mismatch: cold=%v warm=%v", h1.Score.Score, h2.Score.Score)
	}

	// 3. Modify source file -> must invalidate cache key and reflect change.
	write("pkg/pkg.go", `package pkg

func ExportedFunc() int {
	return 1
}
`)
	ctx3, err := LoadAndBuild(context.Background(), cfg, true)
	if err != nil {
		t.Fatalf("invalidated LoadAndBuild failed: %v", err)
	}
	doc3 := ctx3.DeadCode(deadcode.Options{})
	if len(doc3.Findings) != 0 {
		t.Errorf("expected 0 findings after removing unused code, got %d", len(doc3.Findings))
	}
}

func TestLoadSyntaxAndBuildParity(t *testing.T) {
	tmp := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/synctest\n\ngo 1.22\n")
	write("cmd/app/main.go", "package main\n\nimport \"example.com/synctest/internal/a\"\n\nfunc main() { a.Run() }\n")
	write("internal/a/a.go", "package a\n\nfunc Run() {}\n")

	cfg := config.Defaults()
	cfg.Root = tmp
	cfg.NoCache = true

	fullCtx, err := LoadAndBuild(context.Background(), cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	synCtx, err := LoadSyntaxAndBuild(context.Background(), cfg, true)
	if err != nil {
		t.Fatal(err)
	}

	if len(fullCtx.Proj.Files) != len(synCtx.Proj.Files) {
		t.Fatalf("files count mismatch: full=%d syntax=%d", len(fullCtx.Proj.Files), len(synCtx.Proj.Files))
	}
	if len(fullCtx.Proj.EntryPkgs) != len(synCtx.Proj.EntryPkgs) {
		t.Fatalf("entry pkgs mismatch: full=%v syntax=%v", fullCtx.Proj.EntryPkgs, synCtx.Proj.EntryPkgs)
	}
	d1, _, err := fullCtx.Architecture(architecture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	d2, _, err := synCtx.Architecture(architecture.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(d1.Findings) != len(d2.Findings) {
		t.Fatalf("architecture findings mismatch: full=%d syntax=%d", len(d1.Findings), len(d2.Findings))
	}
}

func TestCacheBustingVectors(t *testing.T) {
	tmp := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")

	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("go.mod", `module example.com/busttest

go 1.22

require example.com/localdep v0.0.0

replace example.com/localdep => ./localdep
`)
	write("localdep/go.mod", "module example.com/localdep\n\ngo 1.22\n")
	write("localdep/dep.go", "package localdep\n\nfunc Val() int { return 1 }\n")
	write("main.go", "package main\n\nimport \"example.com/localdep\"\n\nfunc main() { _ = localdep.Val() }\n")
	write("main_test.go", "package main\n\nimport \"testing\"\n\nfunc TestMainFunc(t *testing.T) {}\n")

	kBase, err := computeCacheKey(tmp, true, 256)
	if err != nil {
		t.Fatalf("computeCacheKey failed: %v", err)
	}

	// 1. Changing tests bool must bust key.
	kNoTests, err := computeCacheKey(tmp, false, 256)
	if err != nil || kNoTests == kBase {
		t.Errorf("changing tests=false did not bust cache key: %s vs %s", kNoTests, kBase)
	}

	// 2. Changing maxFileSizeMB must bust key.
	kSize, err := computeCacheKey(tmp, true, 128)
	if err != nil || kSize == kBase {
		t.Errorf("changing maxFileSizeMB did not bust cache key")
	}

	// 3. Changing build env (GOOS / GOARCH / CGO_ENABLED / GOFLAGS) must bust key.
	t.Setenv("GOFLAGS", "-tags=integration")
	kEnv, err := computeCacheKey(tmp, true, 256)
	if err != nil || kEnv == kBase {
		t.Errorf("changing GOFLAGS env did not bust cache key")
	}
	t.Setenv("GOFLAGS", "")

	// 4. Modifying a file inside a local `replace => ./localdep` directory (with its own go.mod) must bust key.
	write("localdep/dep.go", "package localdep\n\nfunc Val() int { return 2 }\n")
	kReplaced, err := computeCacheKey(tmp, true, 256)
	if err != nil || kReplaced == kBase {
		t.Errorf("modifying file in local replace module did not bust cache key")
	}

	// 5. Adding a new .go file must bust key.
	write("extra.go", "package main\n\nfunc extra() {}\n")
	kAdded, err := computeCacheKey(tmp, true, 256)
	if err != nil || kAdded == kReplaced {
		t.Errorf("adding a new .go file did not bust cache key")
	}

	// 6. Deleting a .go file must bust key.
	_ = os.Remove(filepath.Join(tmp, "extra.go"))
	kDeleted, err := computeCacheKey(tmp, true, 256)
	if err != nil || kDeleted == kAdded || kDeleted != kReplaced {
		t.Errorf("deleting extra.go did not restore expected cache key")
	}

	// 7. Modifying vendor/modules.txt must bust key.
	write("vendor/modules.txt", "# example.com/localdep v0.0.0 => ./localdep\n")
	kVendor, err := computeCacheKey(tmp, true, 256)
	if err != nil || kVendor == kDeleted {
		t.Errorf("adding vendor/modules.txt did not bust cache key")
	}
	_ = os.RemoveAll(filepath.Join(tmp, "vendor"))

	// 8. Cache TTL expiration (CacheMaxAgeDays = 0) must bust and evict cached snapshot.
	cfg := config.Defaults()
	cfg.Root = tmp
	cfg.Cache.Dir = cacheDir
	ctx1, err := LoadAndBuild(context.Background(), cfg, true)
	if err != nil {
		t.Fatalf("LoadAndBuild failed: %v", err)
	}
	if len(ctx1.Loaded.Pkgs) == 0 {
		t.Fatalf("expected cold run to load packages")
	}
	zeroDays := 0
	cfg.Audit.CacheMaxAgeDays = &zeroDays
	ctxExpired, err := LoadAndBuild(context.Background(), cfg, true)
	if err != nil {
		t.Fatalf("LoadAndBuild with expired TTL failed: %v", err)
	}
	if len(ctxExpired.Loaded.Pkgs) == 0 {
		t.Errorf("expected CacheMaxAgeDays=0 to bust cache and force reload")
	}
}

func TestCacheBustingEdgeCases(t *testing.T) {
	ws := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")
	write := func(base, rel, content string) string {
		t.Helper()
		full := filepath.Join(base, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return full
	}

	// 1. go.work without root go.mod + parent ../go.work + transitive local replace (a -> b -> c).
	write(ws, "go.work", "go 1.24\n\nuse (\n\t./a\n\t./b\n)\n")
	write(ws, "a/go.mod", "module example.com/a\n\ngo 1.24\n\nrequire example.com/b v0.0.0\n\nreplace example.com/b => ../b\n")
	write(ws, "a/a.go", "package a\n\nimport \"example.com/b\"\n\nfunc A() int { return b.B() }\n")
	write(ws, "b/go.mod", "module example.com/b\n\ngo 1.24\n\nrequire example.com/c v0.0.0\n\nreplace example.com/c => ../c\n")
	write(ws, "b/b.go", "package b\n\nimport \"example.com/c\"\n\nfunc B() int { return c.C() }\n")
	write(ws, "c/go.mod", "module example.com/c\n\ngo 1.24\n")
	write(ws, "c/c.go", "package c\n\nfunc C() int { return 1 }\n")

	kRoot1, err := computeCacheKey(ws, true, 256)
	if err != nil {
		t.Fatalf("computeCacheKey(ws) failed: %v", err)
	}
	subA := filepath.Join(ws, "a")
	kSub1, err := computeCacheKey(subA, true, 256)
	if err != nil {
		t.Fatalf("computeCacheKey(subA) failed: %v", err)
	}

	// Editing transitive local replace target c/c.go must bust BOTH root and subA keys.
	write(ws, "c/c.go", "package c\n\nfunc C() int { return 2 }\n")
	kRootTrans, err := computeCacheKey(ws, true, 256)
	if err != nil || kRootTrans == kRoot1 {
		t.Errorf("editing transitive replace c/c.go did not bust root cache key")
	}
	kSubTrans, err := computeCacheKey(subA, true, 256)
	if err != nil || kSubTrans == kSub1 {
		t.Errorf("editing transitive replace c/c.go did not bust subA cache key")
	}

	// Editing sibling b/b.go via parent ../go.work must bust subA too.
	write(ws, "b/b.go", "package b\n\nimport \"example.com/c\"\n\nfunc B() int { return c.C() + 1 }\n")
	kSubWork, err := computeCacheKey(subA, true, 256)
	if err != nil || kSubWork == kSubTrans {
		t.Errorf("editing sibling workspace module did not bust subA via parent go.work")
	}

	// GOWORK=off must change subA key.
	t.Setenv("GOWORK", "off")
	kNoWork, err := computeCacheKey(subA, true, 256)
	if err != nil || kNoWork == kSubWork {
		t.Errorf("GOWORK=off did not bust cache key")
	}
	t.Setenv("GOWORK", "")

	// 2. Vendor source file patch without modifying vendor/modules.txt.
	write(ws, "a/vendor/modules.txt", "# example.com/v v0.0.0\n")
	vFile := write(ws, "a/vendor/v/v.go", "package v\n\nfunc V() int { return 1 }\n")
	kVend1, err := computeCacheKey(subA, true, 256)
	if err != nil {
		t.Fatalf("computeCacheKey with vendor failed: %v", err)
	}
	write(ws, "a/vendor/v/v.go", "package v\n\nfunc V() int { return 12345 }\n")
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(vFile, future, future)
	kVend2, err := computeCacheKey(subA, true, 256)
	if err != nil || kVend2 == kVend1 {
		t.Errorf("in-place edit in vendor/ did not bust cache key")
	}
	_ = os.RemoveAll(filepath.Join(subA, "vendor"))

	// 3. Cgo header (.h) edits must bust key.
	write(ws, "a/helper.h", "#define VAL 1\n")
	kCgo1, err := computeCacheKey(subA, true, 256)
	if err != nil {
		t.Fatalf("computeCacheKey with .h failed: %v", err)
	}
	write(ws, "a/helper.h", "#define VAL 2\n")
	kCgo2, err := computeCacheKey(subA, true, 256)
	if err != nil || kCgo2 == kCgo1 {
		t.Errorf("editing cgo header helper.h did not bust cache key")
	}

	// 4. Symlinked directory inside module must not cause EISDIR error.
	targetOutside := t.TempDir()
	write(targetOutside, "x.go", "package x\n")
	_ = os.Symlink(targetOutside, filepath.Join(subA, "symlinkdir"))
	if _, err := computeCacheKey(subA, true, 256); err != nil {
		t.Errorf("symlinked dir caused computeCacheKey error: %v", err)
	}
	_ = os.Remove(filepath.Join(subA, "symlinkdir"))

	// 5. Additional Go toolchain env vars (GOAMD64, GOTOOLCHAIN, CGO_CFLAGS).
	t.Setenv("GOAMD64", "v3")
	kArch1, err := computeCacheKey(subA, true, 256)
	if err != nil || kArch1 == kCgo2 {
		t.Errorf("GOAMD64 env did not bust cache key")
	}
	t.Setenv("GOTOOLCHAIN", "local")
	kTool, err := computeCacheKey(subA, true, 256)
	if err != nil || kTool == kArch1 {
		t.Errorf("GOTOOLCHAIN env did not bust cache key")
	}
	t.Setenv("GOAMD64", "")
	t.Setenv("GOTOOLCHAIN", "")

	// 6. Corrupt .gob removal & expired cache sweeping in pruneCacheDir.
	corruptKey := "corrupt_entry"
	corruptPath := filepath.Join(cacheDir, corruptKey+".gob")
	write(cacheDir, corruptKey+".gob", "not-valid-gob-bytes")
	if _, _, ok := loadCachedSnapshot(cacheDir, corruptKey, nil); ok {
		t.Errorf("expected corrupt gob to fail loadCachedSnapshot")
	}
	if _, serr := os.Stat(corruptPath); !os.IsNotExist(serr) {
		t.Errorf("expected corrupt gob file %s to be deleted after decode failure", corruptPath)
	}

	stalePath := write(cacheDir, "stale_entry.gob", "old-data")
	tenDaysAgo := time.Now().Add(-10 * 24 * time.Hour)
	if err := os.Chtimes(stalePath, tenDaysAgo, tenDaysAgo); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Root = subA
	cfg.Cache.Dir = cacheDir
	threeDays := 3
	cfg.Audit.CacheMaxAgeDays = &threeDays
	t.Setenv("GOWORK", "off")
	if _, err := LoadAndBuild(context.Background(), cfg, false); err != nil {
		t.Fatalf("LoadAndBuild failed: %v", err)
	}
	if _, serr := os.Stat(stalePath); !os.IsNotExist(serr) {
		t.Errorf("expected expired cache entry %s to be swept by pruneCacheDir", stalePath)
	}
	t.Setenv("GOWORK", "")

	// 7. Production mode (tests=false) must NOT credit build-tagged _test.go files.
	prodDir := t.TempDir()
	write(prodDir, "go.mod", "module example.com/prodcheck\n\ngo 1.24\n")
	write(prodDir, "main.go", "package main\n\nfunc Used() {}\nfunc UnusedInProd() {}\nfunc main() { Used() }\n")
	write(prodDir, "tagged_test.go", "//go:build customtag\n\npackage main\n\nimport \"testing\"\n\nfunc TestOnly(t *testing.T) { UnusedInProd() }\n")
	kProd1, err := computeCacheKey(prodDir, false, 256)
	if err != nil {
		t.Fatalf("computeCacheKey(prodDir, false) failed: %v", err)
	}
	prodCfg := config.Defaults()
	prodCfg.Root = prodDir
	prodCfg.NoCache = true
	pCtx, err := LoadAndBuild(context.Background(), prodCfg, false)
	if err != nil {
		t.Fatalf("LoadAndBuild(prodDir, false) failed: %v", err)
	}
	unusedKey := facts.MakeKey(facts.KindFunc, "example.com/prodcheck", "", "UnusedInProd")
	if uses := pCtx.Proj.Uses[unusedKey]; len(uses) != 0 {
		t.Errorf("expected tests=false NOT to credit build-tagged _test.go use sites, got %d uses", len(uses))
	}
	write(prodDir, "tagged_test.go", "//go:build customtag\n\npackage main\n\nfunc helperChanged() { UnusedInProd() }\n")
	kProd2, err := computeCacheKey(prodDir, false, 256)
	if err != nil || kProd2 != kProd1 {
		t.Errorf("editing _test.go with tests=false should keep cache key stable")
	}

	// 8. GOROOT env updates deadcode.IsGorootStd cleanly without permanent sync.Once lock-in.
	fakeGR := t.TempDir()
	write(fakeGR, "src/fakeCustomStd/fake.go", "package fakeCustomStd\n")
	if deadcode.IsGorootStd("fakeCustomStd") {
		t.Fatalf("expected fakeCustomStd not to be std before GOROOT override")
	}
	t.Setenv("GOROOT", fakeGR)
	if !deadcode.IsGorootStd("fakeCustomStd") {
		t.Errorf("expected IsGorootStd to honor updated GOROOT env var")
	}
}

func TestGitCommitAndUncommittedCacheBusting(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil || gitBin == "" {
		t.Skip("git binary not installed")
	}

	root := t.TempDir()
	mainRepo := filepath.Join(root, "app")
	extRepo := filepath.Join(root, "ext")
	cacheDir := filepath.Join(root, "cache")

	write := func(base, rel, content string) {
		t.Helper()
		full := filepath.Join(base, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command(gitBin, append([]string{"-C", dir}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v in %s failed: %v\n%s", args, dir, err, string(out))
		}
		return string(out)
	}
	initRepo := func(dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		git(dir, "init", "-q")
		git(dir, "config", "user.email", "test@example.com")
		git(dir, "config", "user.name", "Test User")
	}

	initRepo(extRepo)
	write(extRepo, "go.mod", "module example.com/ext\n\ngo 1.24\n")
	write(extRepo, "ext.go", "package ext\n\nfunc Hello() string { return \"hi\" }\n")
	git(extRepo, "add", ".")
	git(extRepo, "commit", "-q", "-m", "init ext")

	initRepo(mainRepo)
	write(mainRepo, ".gitignore", "*.pb.go\n")
	write(mainRepo, "go.mod", "module example.com/app\n\ngo 1.24\n\nrequire example.com/ext v0.0.0\n\nreplace example.com/ext => ../ext\n")
	write(mainRepo, "main.go", "package main\n\nimport \"example.com/ext\"\n\nfunc main() { _ = ext.Hello() }\n")
	write(mainRepo, "asset.txt", "v1\n")

	// 1. Unborn HEAD (pre-commit) vs staged pre-commit must differ.
	kUnbornUntracked, err := computeCacheKey(mainRepo, true, 256)
	if err != nil {
		t.Fatalf("computeCacheKey unborn failed: %v", err)
	}
	git(mainRepo, "add", ".")
	kUnbornStaged, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kUnbornStaged == kUnbornUntracked {
		t.Errorf("staging files on unborn HEAD did not bust cache key")
	}

	// 2. Clean commit C1: LoadAndBuild caches cleanly on disk and repeats identically.
	git(mainRepo, "commit", "-q", "-m", "commit C1")
	kC1, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kC1 == kUnbornStaged {
		t.Fatalf("committing C1 did not produce distinct key")
	}
	cfg := config.Defaults()
	cfg.Root = mainRepo
	cfg.Cache.Dir = cacheDir
	if _, err := LoadAndBuild(context.Background(), cfg, true); err != nil {
		t.Fatalf("LoadAndBuild C1 cold failed: %v", err)
	}
	if !fileExists(filepath.Join(cacheDir, kC1+".gob")) {
		t.Fatalf("expected C1 snapshot file %s.gob", kC1)
	}
	// Repeating unchanged state must hit exact same key.
	kC1Again, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kC1Again != kC1 {
		t.Errorf("clean C1 key unstable: %s vs %s", kC1Again, kC1)
	}

	// 3. Uncommitted non-.go edit must bust cache vs clean C1.
	write(mainRepo, "asset.txt", "v2\n")
	kDirty1, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kDirty1 == kC1 {
		t.Errorf("modifying tracked non-.go asset.txt did not bust cache key")
	}

	// 4. Subsequent edit to uncommitted asset must bust again.
	write(mainRepo, "asset.txt", "v3\n")
	kDirty2, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kDirty2 == kDirty1 {
		t.Errorf("second uncommitted edit to asset.txt did not bust cache key")
	}

	// 5. Staging change (index modification) must bust vs unstaged worktree edit.
	git(mainRepo, "add", "asset.txt")
	kStaged, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kStaged == kDirty2 {
		t.Errorf("staging asset.txt did not bust cache key")
	}

	// 6. Untracked file creation & edit must bust cache.
	write(mainRepo, "untracked.txt", "one\n")
	kUntracked1, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kUntracked1 == kStaged {
		t.Errorf("creating untracked file did not bust cache key")
	}
	write(mainRepo, "untracked.txt", "two\n")
	kUntracked2, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kUntracked2 == kUntracked1 {
		t.Errorf("modifying untracked file did not bust cache key")
	}

	// Resetting back to clean C1 restores exact clean C1 key.
	_ = os.Remove(filepath.Join(mainRepo, "untracked.txt"))
	git(mainRepo, "reset", "-q", "--hard", "HEAD")
	kRestoredC1, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kRestoredC1 != kC1 {
		t.Errorf("resetting to clean C1 did not restore C1 key: %s vs %s", kRestoredC1, kC1)
	}

	// 7. New commit ID with identical files (empty commit) must bust cache.
	git(mainRepo, "commit", "-q", "--allow-empty", "-m", "commit C2")
	kC2, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kC2 == kC1 {
		t.Errorf("new empty commit C2 did not bust cache key")
	}

	// 8. Commit amend (new commit ID) must bust cache.
	git(mainRepo, "commit", "-q", "--amend", "--allow-empty", "-m", "commit C2 amended")
	kAmend, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kAmend == kC2 {
		t.Errorf("amending commit did not bust cache key")
	}

	// 9. New commit or uncommitted file in external replace repo extRepo must bust app key.
	git(extRepo, "commit", "-q", "--allow-empty", "-m", "ext bump")
	kExtCommit, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kExtCommit == kAmend {
		t.Errorf("new commit in replaced ext repo did not bust main repo cache key")
	}
	write(extRepo, "ext_dirty.txt", "dirty\n")
	kExtDirty, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kExtDirty == kExtCommit {
		t.Errorf("uncommitted file in replaced ext repo did not bust main repo cache key")
	}
	_ = os.Remove(filepath.Join(extRepo, "ext_dirty.txt"))

	// 10. Gitignored generated .pb.go changes on a clean commit still bust cache.
	write(mainRepo, "gen.pb.go", "package main\n\nfunc Gen1() {}\n")
	kGen1, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kGen1 == kExtCommit {
		t.Errorf("adding gitignored gen.pb.go did not bust cache key")
	}
	write(mainRepo, "gen.pb.go", "package main\n\nfunc Gen2() {}\n")
	kGen2, err := computeCacheKey(mainRepo, true, 256)
	if err != nil || kGen2 == kGen1 {
		t.Errorf("editing gitignored gen.pb.go did not bust cache key")
	}
}
