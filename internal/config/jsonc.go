package config

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParseJSONC parses JSON with comments and trailing commas, the accepted
// format for .fallowrc.json and .fallowrc.jsonc.
func ParseJSONC(text string) (map[string]any, error) {
	clean, err := stripJSONComments(text)
	if err != nil {
		return nil, err
	}
	clean = stripTrailingCommas(clean)
	var out map[string]any
	dec := json.NewDecoder(strings.NewReader(clean))
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

func stripJSONComments(text string) (string, error) {
	var b strings.Builder
	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch c {
		case '"':
			b.WriteRune(c)
			i++
			for ; i < len(runes); i++ {
				b.WriteRune(runes[i])
				if runes[i] == '\\' {
					i++
					if i < len(runes) {
						b.WriteRune(runes[i])
					}
					continue
				}
				if runes[i] == '"' {
					break
				}
			}
		case '/':
			if i+1 < len(runes) && runes[i+1] == '/' {
				for i < len(runes) && runes[i] != '\n' {
					i++
				}
				b.WriteRune('\n')
			} else if i+1 < len(runes) && runes[i+1] == '*' {
				i += 2
				closed := false
				for ; i < len(runes); i++ {
					if runes[i] == '*' && i+1 < len(runes) && runes[i+1] == '/' {
						closed = true
						i++
						break
					}
				}
				if !closed {
					return "", fmt.Errorf("unterminated block comment")
				}
				b.WriteRune(' ')
			} else {
				b.WriteRune(c)
			}
		default:
			b.WriteRune(c)
		}
	}
	return b.String(), nil
}

func stripTrailingCommas(text string) string {
	var b strings.Builder
	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if c == '"' {
			b.WriteRune(c)
			i++
			for ; i < len(runes); i++ {
				b.WriteRune(runes[i])
				if runes[i] == '\\' {
					i++
					if i < len(runes) {
						b.WriteRune(runes[i])
					}
					continue
				}
				if runes[i] == '"' {
					break
				}
			}
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(runes) && (runes[j] == ' ' || runes[j] == '\t' || runes[j] == '\n' || runes[j] == '\r') {
				j++
			}
			if j < len(runes) && (runes[j] == '}' || runes[j] == ']') {
				continue
			}
		}
		b.WriteRune(c)
	}
	return b.String()
}
