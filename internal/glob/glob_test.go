package glob

import "testing"

func TestPathGlobs(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"src/*.ts", "src/a.ts", true},
		{"src/*.ts", "src/a/b.ts", false},
		{"src/**/*.ts", "src/a.ts", true},
		{"src/**/*.ts", "src/a/b.ts", true},
		{"*.test.ts", "a.test.ts", true},
		{"*.test.ts", "src/a.test.ts", false},
		{"**/*.test.ts", "src/a.test.ts", true},
		{"src/**/build/**", "src/cli/build/x.ts", true},
		{"src/**", "src", false},
		{"src/**", "src/a", true},
		{"**/node_modules/**", "node_modules/x/y.js", true},
		{"**/node_modules/**", "src/node_modules/x/y.js", true},
		{"src/{a,b}/*.ts", "src/a/x.ts", true},
		{"src/{a,b}/*.ts", "src/c/x.ts", false},
		{"src/@(a|b)/*.ts", "src/b/x.ts", true},
		{"**/__tests__/**", "src/__tests__/a.ts", true},
		{"**/*.d.ts", "src/x.d.ts", true},
		{"**/*.d.ts", "src/x.ts", false},
	}
	for _, c := range cases {
		p, err := Compile(c.pattern, Options{})
		if err != nil {
			t.Fatalf("%s: %v", c.pattern, err)
		}
		if got := p.Match(c.path); got != c.want {
			t.Errorf("%s ~ %s = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestMatcherNegation(t *testing.T) {
	m, err := NewMatcher([]string{"dist/**", "!dist/keep/**"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match("dist/x.js") {
		t.Error("dist/x.js should be ignored")
	}
	if m.Match("dist/keep/x.js") {
		t.Error("exception should lift the ignore")
	}
}

func TestNameGlob(t *testing.T) {
	if !MatchName("@acme/*", "@acme/lib") {
		t.Error("scope glob should match")
	}
	if MatchName("@acme/*", "@other/lib") {
		t.Error("scope glob should not match another scope")
	}
}

func TestMustCompileAndSource(t *testing.T) {
	p := MustCompile("src/*.ts", Options{})
	if p.Source() != "src/*.ts" {
		t.Errorf("Source() = %q, want src/*.ts", p.Source())
	}
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on invalid glob")
		}
	}()
	_ = MustCompile("", Options{})
}

func TestMatcherAny(t *testing.T) {
	m, err := NewMatcher([]string{"dist/**", "!dist/keep/**"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Any("dist/keep/x.js") {
		t.Error("Any should match dist/keep/x.js ignoring negation")
	}
	if m.Any("other/file.js") {
		t.Error("Any should not match unrelated file")
	}
	var nilMatcher *Matcher
	if nilMatcher.Any("anything") {
		t.Error("nil Matcher.Any should return false")
	}
}
