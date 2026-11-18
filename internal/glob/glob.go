// Package glob implements the path matching rules fallow documents: a single
// `*` and `?` stay inside one path segment, only `**` crosses directories,
// while import specifiers use a variant where `*` also crosses `/`.
package glob

import (
	"fmt"
	"regexp"
	"strings"
)

// Options controls how a pattern is translated.
type Options struct {
	// AllCross makes `*` and `?` match `/` as well. It is used for import
	// specifiers and package names rather than file paths.
	AllCross bool
}

// Pattern is a compiled glob.
type Pattern struct {
	source string
	re     *regexp.Regexp
}

// Source returns the pattern text the user wrote.
func (p *Pattern) Source() string { return p.source }

// Compile translates a glob into an anchored regular expression.
func Compile(pattern string, opts Options) (*Pattern, error) {
	pattern = strings.TrimPrefix(pattern, "./")
	if pattern == "" {
		return nil, fmt.Errorf("empty glob pattern")
	}
	alts, err := expandBraces(pattern)
	if err != nil {
		return nil, err
	}
	var parts []string
	for _, alt := range alts {
		body, err := translate(alt, opts)
		if err != nil {
			return nil, err
		}
		parts = append(parts, body)
	}
	re, err := regexp.Compile("^(?:" + strings.Join(parts, "|") + ")$")
	if err != nil {
		return nil, fmt.Errorf("invalid glob %q: %w", pattern, err)
	}
	return &Pattern{source: pattern, re: re}, nil
}

// MustCompile is Compile for patterns known to be valid.
func MustCompile(pattern string, opts Options) *Pattern {
	p, err := Compile(pattern, opts)
	if err != nil {
		panic(err)
	}
	return p
}

// Match reports whether the path matches.
func (p *Pattern) Match(path string) bool {
	path = strings.TrimPrefix(path, "./")
	return p.re.MatchString(path)
}

// Matcher is an ordered set of patterns with `!` exceptions. A leading `!`
// re-includes paths that an earlier pattern excluded, which mirrors
// fallow's ignorePatterns handling.
type Matcher struct {
	rules []matcherRule
}

type matcherRule struct {
	pat     *Pattern
	negated bool
}

// NewMatcher compiles every pattern. Negations are kept in order.
func NewMatcher(patterns []string, opts Options) (*Matcher, error) {
	m := &Matcher{}
	for _, raw := range patterns {
		negated := false
		p := raw
		if strings.HasPrefix(p, "!") && len(p) > 1 {
			negated = true
			p = p[1:]
		}
		pat, err := Compile(p, opts)
		if err != nil {
			return nil, fmt.Errorf("%w (in %q)", err, raw)
		}
		m.rules = append(m.rules, matcherRule{pat: pat, negated: negated})
	}
	return m, nil
}

// Match reports whether path is selected. The last matching rule wins, and a
// matcher with only negations selects everything a negation matches.
func (m *Matcher) Match(path string) bool {
	if m == nil || len(m.rules) == 0 {
		return false
	}
	onlyNegations := true
	for _, r := range m.rules {
		if !r.negated {
			onlyNegations = false
			break
		}
	}
	matched := onlyNegations
	for _, r := range m.rules {
		if r.pat.Match(path) {
			matched = !r.negated
		}
	}
	return matched
}

// Any reports whether any rule matches the path, ignoring negation ordering.
func (m *Matcher) Any(path string) bool {
	if m == nil {
		return false
	}
	for _, r := range m.rules {
		if r.pat.Match(path) {
			return true
		}
	}
	return false
}

// MatchName applies package-name semantics: `*` crosses `/`.
func MatchName(pattern, name string) bool {
	p, err := Compile(pattern, Options{AllCross: true})
	if err != nil {
		return false
	}
	return p.Match(name)
}

// expandBraces expands `{a,b}` alternatives, including nested groups.
func expandBraces(pattern string) ([]string, error) {
	open := -1
	depth := 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '{':
			if depth == 0 {
				open = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && open >= 0 {
					head := pattern[:open]
					inner := pattern[open+1 : i]
					tail := pattern[i+1:]
					var out []string
					for _, alt := range splitTop(inner, ',') {
						rest, err := expandBraces(tail)
						if err != nil {
							return nil, err
						}
						for _, r := range rest {
							out = append(out, head+alt+r)
						}
					}
					var expanded []string
					for _, o := range out {
						more, err := expandBraces(o)
						if err != nil {
							return nil, err
						}
						expanded = append(expanded, more...)
					}
					return expanded, nil
				}
			}
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced brace in glob %q", pattern)
	}
	return []string{pattern}, nil
}

func splitTop(s string, sep byte) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case sep:
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

func translate(pattern string, opts Options) (string, error) {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '\\':
			if i+1 < len(pattern) {
				b.WriteString(regexp.QuoteMeta(string(pattern[i+1])))
				i++
			} else {
				b.WriteString(`\\`)
			}
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				// `**/` may match zero directories.
				j := i + 2
				if j < len(pattern) && pattern[j] == '/' {
					b.WriteString(`(?:[^/]+/)*`)
					i = j
				} else {
					b.WriteString(`.*`)
					i = j - 1
				}
			} else if opts.AllCross {
				b.WriteString(`.*`)
			} else {
				b.WriteString(`[^/]*`)
			}
		case '?':
			if i+1 < len(pattern) && pattern[i+1] == '(' {
				end, inner, err := readGroup(pattern, i+1)
				if err != nil {
					return "", err
				}
				body, err := translateAlternatives(inner, opts)
				if err != nil {
					return "", err
				}
				b.WriteString(`(?:` + body + `)?`)
				i = end
			} else if opts.AllCross {
				b.WriteString(`.`)
			} else {
				b.WriteString(`[^/]`)
			}
		case '@', '+':
			if i+1 < len(pattern) && pattern[i+1] == '(' {
				end, inner, err := readGroup(pattern, i+1)
				if err != nil {
					return "", err
				}
				body, err := translateAlternatives(inner, opts)
				if err != nil {
					return "", err
				}
				if c == '@' {
					b.WriteString(`(?:` + body + `)`)
				} else {
					b.WriteString(`(?:` + body + `)+`)
				}
				i = end
				continue
			}
			b.WriteString(regexp.QuoteMeta(string(c)))
		case '!':
			if i+1 < len(pattern) && pattern[i+1] == '(' {
				end, inner, err := readGroup(pattern, i+1)
				if err != nil {
					return "", err
				}
				body, err := translateAlternatives(inner, opts)
				if err != nil {
					return "", err
				}
				star := `[^/]*`
				if opts.AllCross {
					star = `.*`
				}
				b.WriteString(`(?:(?!(?:` + body + `)(?:/|$))` + star + `)`)
				i = end
				continue
			}
			b.WriteString(`!`)
		case '[':
			// Character class, copied with `[!` translated to `[^`.
			j := i + 1
			neg := false
			if j < len(pattern) && (pattern[j] == '!' || pattern[j] == '^') {
				neg = true
				j++
			}
			if j < len(pattern) && pattern[j] == ']' {
				j++
			}
			for ; j < len(pattern) && pattern[j] != ']'; j++ {
			}
			if j >= len(pattern) {
				b.WriteString(`\[`)
				continue
			}
			body := pattern[i+1 : j]
			if neg {
				body = body[1:]
				b.WriteString("[^" + body + "]")
			} else {
				b.WriteString("[" + body + "]")
			}
			i = j
		case '/':
			b.WriteString(`/`)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String(), nil
}

// readGroup reads a balanced `(...)` group starting at the `(` index and
// returns the index of the closing paren and the inner text.
func readGroup(pattern string, openIdx int) (int, string, error) {
	depth := 0
	for i := openIdx; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, pattern[openIdx+1 : i], nil
			}
		}
	}
	return 0, "", fmt.Errorf("unbalanced extglob group in %q", pattern)
}

func translateAlternatives(inner string, opts Options) (string, error) {
	var parts []string
	for _, alt := range splitTop(inner, '|') {
		body, err := translate(alt, opts)
		if err != nil {
			return "", err
		}
		parts = append(parts, body)
	}
	return strings.Join(parts, "|"), nil
}

// DirPrefixes returns every directory prefix of a path, used by directory
// mirror detection.
// goose-ignore-next-line unused-export -- the viz map links to every prefix
func DirPrefixes(path string) []string {
	parts := strings.Split(path, "/")
	var out []string
	if len(parts) <= 1 {
		return out
	}
	for i := 1; i < len(parts); i++ {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}
