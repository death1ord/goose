package facts_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"goose/internal/facts"
	"goose/internal/loader"
)

func writeTestModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestComputeComplexityNestingAndElseIf(t *testing.T) {
	src := `package p

func DeeplyNested(a, b, c bool) {
	if a {
		for b {
			switch {
			case c:
				fn := func() {
					if a {
					}
				}
				fn()
			}
		}
	}
}

func ElseIfChain(a, b, c bool) {
	if a {
	} else if b {
	} else if c {
	} else {
	}
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	var deepFn, elseIfFn *ast.FuncDecl
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			switch fn.Name.Name {
			case "DeeplyNested":
				deepFn = fn
			case "ElseIfChain":
				elseIfFn = fn
			}
		}
	}

	if deepFn == nil || elseIfFn == nil {
		t.Fatal("could not find test functions")
	}

	deepComp := facts.ComputeComplexity(fset, deepFn)
	if deepComp.Cognitive <= deepComp.Cyclomatic {
		t.Errorf("DeeplyNested: expected Cognitive > Cyclomatic, got Cognitive=%d, Cyclomatic=%d",
			deepComp.Cognitive, deepComp.Cyclomatic)
	}

	elseIfComp := facts.ComputeComplexity(fset, elseIfFn)
	if elseIfComp.Cyclomatic != 4 {
		t.Errorf("ElseIfChain: Cyclomatic want 4, got %d", elseIfComp.Cyclomatic)
	}
	if elseIfComp.Cognitive != 4 {
		t.Errorf("ElseIfChain: Cognitive want 4, got %d", elseIfComp.Cognitive)
	}
}

func TestBuildFieldLineNumbers(t *testing.T) {
	files := map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n",
		"model.go": `package testmod

type Sample struct {
	First  string
	Second int
}
`,
	}
	dir := writeTestModule(t, files)
	ld, err := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	if err != nil {
		t.Fatalf("loader.Load failed: %v", err)
	}
	proj := facts.Build(ld)

	firstKey := facts.MakeKey(facts.KindField, "testmod", "Sample", "First")
	secondKey := facts.MakeKey(facts.KindField, "testmod", "Sample", "Second")

	first := proj.Entities[firstKey]
	second := proj.Entities[secondKey]

	if first == nil {
		t.Fatalf("missing entity for %s", firstKey)
	}
	if second == nil {
		t.Fatalf("missing entity for %s", secondKey)
	}

	if first.Line != 4 {
		t.Errorf("First field line want 4, got %d", first.Line)
	}
	if second.Line != 5 {
		t.Errorf("Second field line want 5, got %d", second.Line)
	}

	firstSpans := proj.EntitySpans[firstKey]
	if len(firstSpans) == 0 || firstSpans[0].StartLine != 4 || firstSpans[0].EndLine != 4 {
		t.Errorf("First field span want [4, 4], got %+v", firstSpans)
	}
	secondSpans := proj.EntitySpans[secondKey]
	if len(secondSpans) == 0 || secondSpans[0].StartLine != 5 || secondSpans[0].EndLine != 5 {
		t.Errorf("Second field span want [5, 5], got %+v", secondSpans)
	}
}

func TestBuildReflectionCreditsNestedSliceFieldsInTestFile(t *testing.T) {
	files := map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n",
		"model.go": `package testmod

type Inner struct {
	Name string ` + "`json:\"name\"`" + `
}

type Outer struct {
	Items []Inner ` + "`json:\"items\"`" + `
}

func NewOuter() Outer {
	return Outer{Items: []Inner{{Name: "test"}}}
}
`,
		"model_test.go": `package testmod

import (
	"encoding/json"
	"testing"
)

func TestMarshal(t *testing.T) {
	o := NewOuter()
	_, _ = json.Marshal(o)
}
`,
	}
	dir := writeTestModule(t, files)
	ld, err := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	if err != nil {
		t.Fatalf("loader.Load failed: %v", err)
	}
	proj := facts.Build(ld)

	innerTypeKey := facts.MakeKey(facts.KindType, "testmod", "", "Inner")
	outerItemsKey := facts.MakeKey(facts.KindField, "testmod", "Outer", "Items")
	innerNameKey := facts.MakeKey(facts.KindField, "testmod", "Inner", "Name")

	outerUses := proj.Uses[outerItemsKey]
	if len(outerUses) == 0 {
		t.Errorf("expected uses for Outer.Items, got 0")
	}

	innerTypeUses := proj.Uses[innerTypeKey]
	if len(innerTypeUses) == 0 {
		t.Errorf("expected uses for Inner type, got 0")
	}

	innerNameUses := proj.Uses[innerNameKey]
	if len(innerNameUses) == 0 {
		t.Errorf("expected uses for Inner.Name field, got 0")
	}
}

func TestBuildCreditsErrorAndUnwrapMethods(t *testing.T) {
	files := map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n",
		"myerr/err.go": `package myerr

type CustomErr struct {
	Msg string
	Err error
}

func (e CustomErr) Error() string {
	return e.Msg
}

func (e CustomErr) Unwrap() error {
	return e.Err
}

func New(msg string, err error) error {
	return CustomErr{Msg: msg, Err: err}
}
`,
		"main.go": `package main

import "testmod/myerr"

func main() {
	_ = myerr.New("fail", nil)
}
`,
	}
	dir := writeTestModule(t, files)
	ld, err := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	if err != nil {
		t.Fatalf("loader.Load failed: %v", err)
	}
	proj := facts.Build(ld)

	errorMethodKey := facts.MakeKey(facts.KindMethod, "testmod/myerr", "CustomErr", "Error")
	unwrapMethodKey := facts.MakeKey(facts.KindMethod, "testmod/myerr", "CustomErr", "Unwrap")

	errorUses := proj.Uses[errorMethodKey]
	if len(errorUses) == 0 {
		t.Errorf("expected uses for CustomErr.Error, got 0")
	}

	unwrapUses := proj.Uses[unwrapMethodKey]
	if len(unwrapUses) == 0 {
		t.Errorf("expected uses for CustomErr.Unwrap, got 0")
	}
}

func TestFactsAccessors(t *testing.T) {
	files := map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n",
		"lib.go": "package testmod\n\n" +
			"// " + "goose-ignore-file dead-code -- reason\n" +
			"// ExportedFunc is an exported API function.\n" +
			"func ExportedFunc() {\n" +
			"\tvar local int\n" +
			"\t_ = local\n" +
			"}\n",
	}
	dir := writeTestModule(t, files)
	ld, err := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	if err != nil {
		t.Fatalf("loader.Load failed: %v", err)
	}
	proj := facts.Build(ld)

	funcKey := facts.MakeKey(facts.KindFunc, "testmod", "", "ExportedFunc")
	ent := proj.Entity(funcKey)
	if ent == nil {
		t.Fatalf("Entity(%s) returned nil", funcKey)
	}

	if !proj.IsExportedAPI(funcKey) {
		t.Errorf("IsExportedAPI(%s) = false, want true", funcKey)
	}

	fileFacts := proj.File(ent.File)
	if fileFacts == nil {
		t.Fatalf("File(%s) returned nil", ent.File)
	}

	if len(fileFacts.Suppressions) == 0 {
		t.Fatalf("expected at least 1 suppression in %s", ent.File)
	}
	sup := fileFacts.Suppressions[0]
	if sup.Col < 0 {
		t.Errorf("unexpected negative Col: %d", sup.Col)
	}

	uses := proj.UsesOf(funcKey)
	_ = uses

	var u facts.UseSite
	_ = u.Containing()
}

func TestAccuracyHardening(t *testing.T) {
	files := map[string]string{
		"go.mod": "module testmod\n\ngo 1.24\n",
		"acc.go": "package testmod\n\n" +
			"import \"encoding/json\"\n\n" +
			"type Alpha struct {\n" +
			"\tName string\n" +
			"}\n\n" +
			"type Beta struct {\n" +
			"\tName string\n" +
			"}\n\n" +
			"type OptionsTarget struct {\n" +
			"\tOptional string `json:\",omitempty\"`\n" +
			"}\n\n" +
			"type TargetAlias = OptionsTarget\n\n" +
			"var RawText = \"\" +\n" +
			"\t\"// \" + \"goose-ignore-next-line unused-export\"\n\n" +
			"var BacktickRaw = `" + "\n// " + "goose-ignore-next-line unused-export\n`\n\n" +
			"func SerializeAlias(v TargetAlias) ([]byte, error) {\n" +
			"\treturn json.Marshal(v)\n" +
			"}\n",
		"acc_test.go": `package testmod

import "testing"

func TestSharedFieldInTest(t *testing.T) {
	a := Alpha{Name: "alpha"}
	b := Beta{Name: "beta"}
	if a.Name == b.Name {
		t.Fatal("unexpected equal")
	}
}
`,
	}
	dir := writeTestModule(t, files)
	ld, err := loader.Load(context.Background(), loader.Options{Dir: dir, Tests: true})
	if err != nil {
		t.Fatalf("loader.Load failed: %v", err)
	}
	proj := facts.Build(ld)

	// 1. Disambiguates shared field name "Name" between Alpha and Beta from _test.go.
	alphaNameKey := facts.MakeKey(facts.KindField, "testmod", "Alpha", "Name")
	betaNameKey := facts.MakeKey(facts.KindField, "testmod", "Beta", "Name")
	if len(proj.LiveUses(alphaNameKey)) == 0 {
		t.Errorf("expected live uses on Alpha.Name from test file, got 0")
	}
	if len(proj.LiveUses(betaNameKey)) == 0 {
		t.Errorf("expected live uses on Beta.Name from test file, got 0")
	}

	// 2. Raw string literal containing ignore comment must NOT produce a suppression.
	for _, ff := range proj.Files {
		if len(ff.Suppressions) > 0 {
			t.Errorf("unexpected suppression in %s: %+v", ff.Rel, ff.Suppressions)
		}
	}

	// 3 & 4. Options-only json:",omitempty" tag + type alias TargetAlias resolve and credit Optional.
	optFieldKey := facts.MakeKey(facts.KindField, "testmod", "OptionsTarget", "Optional")
	ent := proj.Entity(optFieldKey)
	if ent == nil || ent.Field == nil || len(ent.Field.TagNames) == 0 {
		t.Fatalf("expected non-empty TagNames on json:\",omitempty\" field, got %+v", ent)
	}
	if len(proj.LiveUses(optFieldKey)) == 0 {
		t.Errorf("expected OptionsTarget.Optional to be credited via TargetAlias reflection, got 0")
	}
}
