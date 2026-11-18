package dupes

import (
	"strings"
	"testing"

	"goose/internal/config"
	"goose/internal/facts"
)

func proj(files map[string]string) *facts.Project {
	p := &facts.Project{Files: map[string]*facts.FileFacts{}}
	for rel, src := range files {
		p.Files["/abs/"+rel] = &facts.FileFacts{
			Path: "/abs/" + rel, Rel: rel, Src: src, Loc: countNL(src),
		}
	}
	return p
}

func countNL(s string) int { return strings.Count(s, "\n") + 1 }

func twoCopies() map[string]string {
	body := "func calc(x int) int {\n" +
		"  if x > 0 {\n" +
		"    total := 0\n" +
		"    for i := 0; i < x; i++ {\n" +
		"      total = total + i * 2\n" +
		"    }\n" +
		"    return total\n" +
		"  }\n" +
		"  return -x\n" +
		"}\n"
	return map[string]string{
		"a/x.go": "package a\n\n" + strings.ReplaceAll(body, "calc", "calcA"),
		"b/y.go": "package b\n\n" + strings.ReplaceAll(body, "calc", "calcB"),
	}
}

func TestDetectFindsClone(t *testing.T) {
	res := Detect(proj(twoCopies()), Options{
		Mode: ModeMild, MinTokens: 15, MinLines: 3, MinOccurrences: 2,
		IgnoreImports: true,
	})
	if res.Stats.CloneGroups == 0 {
		t.Fatalf("expected a clone group, got none (stats %+v)", res.Stats)
	}
	found := false
	for _, g := range res.Groups {
		if len(g.Instances) >= 2 {
			found = true
			if g.Fingerprint == "" {
				t.Error("group missing a fingerprint")
			}
		}
	}
	if !found {
		t.Errorf("no group with >=2 instances: %+v", res.Groups)
	}
}

func TestNoDuplicationInUniqueCode(t *testing.T) {
	res := Detect(proj(map[string]string{
		"a/x.go": "package a\n\nfunc X() int { return 1 }\n",
		"b/y.go": "package b\n\nfunc Y() string { return \"hi\" }\n",
	}), Options{Mode: ModeStrict, MinTokens: 25, MinLines: 4, MinOccurrences: 2})
	if res.Stats.CloneGroups != 0 {
		t.Errorf("unique code should yield no clones, got %d", res.Stats.CloneGroups)
	}
}

func TestDuplicationPercentagePositive(t *testing.T) {
	res := Detect(proj(twoCopies()), Options{
		Mode: ModeMild, MinTokens: 15, MinLines: 3, MinOccurrences: 2,
	})
	if res.Stats.DuplicationPercentage <= 0 {
		t.Errorf("expected positive duplication percentage, got %v", res.Stats.DuplicationPercentage)
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	p := proj(twoCopies())
	res := Detect(p, Options{Mode: ModeMild, MinTokens: 15, MinLines: 3, MinOccurrences: 2})
	if res.Stats.CloneGroups == 0 {
		t.Skip("no clones to baseline")
	}
	b := &Baseline{Kind: "dupes", Entries: map[string]int{}}
	for _, g := range res.Groups {
		b.Entries[g.Fingerprint+":"+itoa(len(g.Instances))]++
	}
	res2 := Detect(p, Options{Mode: ModeMild, MinTokens: 15, MinLines: 3, MinOccurrences: 2})
	ApplyBaseline(res2, b)
	if res2.Stats.CloneGroups != 0 {
		t.Errorf("baseline should zero the groups, got %d", res2.Stats.CloneGroups)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestCloneRepeatedAcrossThreeFiles(t *testing.T) {
	block := "func work() int {\n" +
		"  a := 10\n" +
		"  b := 20\n" +
		"  c := a + b\n" +
		"  for i := 0; i < c; i++ {\n" +
		"    a += i\n" +
		"  }\n" +
		"  return a\n" +
		"}\n"
	p := proj(map[string]string{
		"f1.go": "package f1\n\n" + block,
		"f2.go": "package f2\n\n" + block,
		"f3.go": "package f3\n\n" + block,
	})
	res := Detect(p, Options{
		Mode: ModeMild, MinTokens: 15, MinLines: 4, MinOccurrences: 2,
	})
	if len(res.Groups) == 0 {
		t.Fatalf("expected clone groups, got 0")
	}
	found3 := false
	for _, g := range res.Groups {
		if len(g.Instances) == 3 {
			found3 = true
			break
		}
	}
	if !found3 {
		t.Errorf("expected a group with 3 instances, got groups: %+v", res.Groups)
	}
}

func TestSkipLocalIgnoresSameFileClones(t *testing.T) {
	localBlock := "func helperA(x int, y int) (int, error) {\n" +
		"  switch x {\n" +
		"  case 1:\n" +
		"    return y + 10, nil\n" +
		"  case 2:\n" +
		"    return y + 20, nil\n" +
		"  default:\n" +
		"    return 0, nil\n" +
		"  }\n" +
		"}\n"
	localBlock2 := "func helperB(x int, y int) (int, error) {\n" +
		"  switch x {\n" +
		"  case 1:\n" +
		"    return y + 10, nil\n" +
		"  case 2:\n" +
		"    return y + 20, nil\n" +
		"  default:\n" +
		"    return 0, nil\n" +
		"  }\n" +
		"}\n"
	crossBlock := "func crossRun() int {\n" +
		"  var arr [10]int\n" +
		"  for idx := 0; idx < 10; idx++ {\n" +
		"    arr[idx] = idx * idx\n" +
		"  }\n" +
		"  return arr[0]\n" +
		"}\n"

	p := proj(map[string]string{
		"local.go":  "package local\n\n" + localBlock + "\n" + localBlock2,
		"cross1.go": "package cross\n\n" + crossBlock,
		"cross2.go": "package cross\n\n" + crossBlock,
	})

	// With SkipLocal: false, both local clone and cross-file clone are reported.
	resAll := Detect(p, Options{
		Mode: ModeMild, MinTokens: 15, MinLines: 4, MinOccurrences: 2, SkipLocal: false,
	})
	var hasLocal bool
	for _, g := range resAll.Groups {
		for _, in := range g.Instances {
			if in.Path == "local.go" {
				hasLocal = true
			}
		}
	}
	if !hasLocal {
		t.Fatalf("expected local.go to have a clone group when SkipLocal is false")
	}

	// With SkipLocal: true, only the cross-file clone should be reported, not the same-file one.
	// With SkipLocal: true, only the cross-file clone should be reported, not the same-file one.
	res := Detect(p, Options{
		Mode: ModeMild, MinTokens: 15, MinLines: 4, MinOccurrences: 2, SkipLocal: true,
	})
	for _, g := range res.Groups {
		for _, in := range g.Instances {
			if in.Path == "local.go" {
				t.Errorf("group with instance in local.go should have been skipped by SkipLocal: %+v", g)
			}
		}
	}
	if len(res.Groups) != 1 {
		t.Fatalf("expected 1 cross-file group, got %d", len(res.Groups))
	}
}

func TestModeStrictVsMild(t *testing.T) {
	fn1 := "func computeAlpha(first int) int {\n" +
		"  acc := 0\n" +
		"  for idx := 0; idx < first; idx++ {\n" +
		"    acc = acc + idx * 7\n" +
		"  }\n" +
		"  return acc\n" +
		"}\n"
	fn2 := "func computeBeta(second int) int {\n" +
		"  total := 0\n" +
		"  for count := 0; count < second; count++ {\n" +
		"    total = total + count * 7\n" +
		"  }\n" +
		"  return total\n" +
		"}\n"

	p := proj(map[string]string{
		"a.go": "package a\n\n" + fn1,
		"b.go": "package b\n\n" + fn2,
	})

	// In ModeStrict, identifiers are distinct so no clone is found.
	resStrict := Detect(p, Options{
		Mode: ModeStrict, MinTokens: 15, MinLines: 4, MinOccurrences: 2,
	})
	if len(resStrict.Groups) != 0 {
		t.Errorf("expected 0 groups in ModeStrict, got %d", len(resStrict.Groups))
	}

	// In ModeMild, identifier names are normalized so clone IS found.
	resMild := Detect(p, Options{
		Mode: ModeMild, MinTokens: 15, MinLines: 4, MinOccurrences: 2,
	})
	if len(resMild.Groups) == 0 {
		t.Errorf("expected clone group in ModeMild, got 0")
	}
}

func TestDivergedCloneSiblings(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules["diverged-clone-sibling"] = string(config.Warn)
	groups := []Group{
		{
			Fingerprint: "dup:abc123",
			Lines:       12,
			Tokens:      60,
			Instances: []Instance{
				{Path: "a.go", StartLine: 10, EndLine: 21},
				{Path: "b.go", StartLine: 30, EndLine: 41},
			},
		},
	}
	changed := map[string]bool{"a.go": true}
	findings := DivergedCloneSiblings(groups, changed, cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 diverged-clone-sibling finding, got %d", len(findings))
	}
	if findings[0].Path != "a.go" || findings[0].Kind != "diverged-clone-sibling" {
		t.Errorf("unexpected finding: %+v", findings[0])
	}

	// When both siblings are updated in the same diff, no finding is emitted.
	bothChanged := map[string]bool{"a.go": true, "b.go": true}
	if got := DivergedCloneSiblings(groups, bothChanged, cfg); len(got) != 0 {
		t.Errorf("expected 0 findings when all siblings changed, got %d", len(got))
	}
}
