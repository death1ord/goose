package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseTOML parses the subset of TOML that fallow configuration files use:
// tables, arrays of tables, dotted keys, strings, numbers, booleans, arrays,
// and inline tables. It rejects anything it cannot read.
func ParseTOML(text string) (map[string]any, error) {
	root := map[string]any{}
	current := root
	var arrayTable map[string]any
	lines := splitLines(text)
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(stripTomlComment(lines[i]))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[[") && strings.HasSuffix(line, "]]") {
			path := parseDottedKey(strings.TrimSpace(line[2 : len(line)-2]))
			target := ensurePath(root, path[:len(path)-1])
			key := path[len(path)-1]
			var arr []any
			if existing, ok := target[key].([]any); ok {
				arr = existing
			}
			newTable := map[string]any{}
			arr = append(arr, newTable)
			target[key] = arr
			current = newTable
			arrayTable = newTable
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			path := parseDottedKey(strings.TrimSpace(line[1 : len(line)-1]))
			current = ensurePath(root, path)
			arrayTable = nil
			continue
		}
		eq := findTopLevel(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("expected key = value, got %q", line)
		}
		key := parseDottedKey(strings.TrimSpace(line[:eq]))
		valueText := strings.TrimSpace(line[eq+1:])
		// Multiline arrays: consume until brackets balance.
		for bracketDepth(valueText) > 0 && i+1 < len(lines) {
			i++
			valueText += "\n" + strings.TrimSpace(stripTomlComment(lines[i]))
		}
		value, err := parseTomlValue(valueText)
		if err != nil {
			return nil, err
		}
		target := current
		if len(key) > 1 {
			target = ensurePath(current, key[:len(key)-1])
		}
		target[key[len(key)-1]] = value
		_ = arrayTable
	}
	return root, nil
}

func splitLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	return strings.Split(text, "\n")
}

func stripTomlComment(line string) string {
	inString := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inString != 0 {
			if c == '\\' && inString == '"' {
				i++
				continue
			}
			if c == inString {
				inString = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inString = c
		case '#':
			return line[:i]
		}
	}
	return line
}

func parseDottedKey(text string) []string {
	var parts []string
	var cur strings.Builder
	inString := byte(0)
	for i := 0; i < len(text); i++ {
		c := text[i]
		if inString != 0 {
			if c == inString {
				inString = 0
				continue
			}
			cur.WriteByte(c)
			continue
		}
		switch c {
		case '"', '\'':
			inString = c
		case '.':
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	parts = append(parts, strings.TrimSpace(cur.String()))
	return parts
}

func ensurePath(root map[string]any, path []string) map[string]any {
	cur := root
	for _, part := range path {
		next, ok := cur[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[part] = next
		}
		cur = next
	}
	return cur
}

func findTopLevel(s string, target byte) int {
	depth := 0
	inString := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString != 0 {
			if c == '\\' && inString == '"' {
				i++
				continue
			}
			if c == inString {
				inString = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inString = c
		case '[', '{', '(':
			depth++
		case ']', '}', ')':
			depth--
		default:
			if c == target && depth == 0 {
				return i
			}
		}
	}
	return -1
}

func bracketDepth(s string) int {
	depth := 0
	inString := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString != 0 {
			if c == '\\' && inString == '"' {
				i++
				continue
			}
			if c == inString {
				inString = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inString = c
		case '[', '{':
			depth++
		case ']', '}':
			depth--
		}
	}
	return depth
}

func parseTomlValue(text string) (any, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("missing value")
	}
	switch text[0] {
	case '"', '\'':
		s, rest, err := parseTomlString(text)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(rest) != "" {
			return nil, fmt.Errorf("trailing text after string: %q", rest)
		}
		return s, nil
	case '[':
		return parseTomlArray(text)
	case '{':
		return parseTomlInlineTable(text)
	}
	lower := strings.ToLower(text)
	if lower == "true" {
		return true, nil
	}
	if lower == "false" {
		return false, nil
	}
	clean := strings.ReplaceAll(text, "_", "")
	if n, err := strconv.ParseInt(clean, 10, 64); err == nil {
		return n, nil
	}
	if f, err := strconv.ParseFloat(clean, 64); err == nil {
		return f, nil
	}
	return nil, fmt.Errorf("invalid TOML value %q", text)
}

func parseTomlString(text string) (string, string, error) {
	quote := text[0]
	if quote == '\'' {
		if len(text) < 2 {
			return "", "", fmt.Errorf("unterminated string")
		}
		end := strings.IndexByte(text[1:], '\'')
		if end < 0 {
			return "", "", fmt.Errorf("unterminated string")
		}
		return text[1 : 1+end], text[2+end:], nil
	}
	var b strings.Builder
	for i := 1; i < len(text); i++ {
		c := text[i]
		if c == '\\' && i+1 < len(text) {
			i++
			switch text[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			default:
				b.WriteByte(text[i])
			}
			continue
		}
		if c == '"' {
			return b.String(), text[i+1:], nil
		}
		b.WriteByte(c)
	}
	return "", "", fmt.Errorf("unterminated string")
}

func parseTomlArray(text string) ([]any, error) {
	inner := strings.TrimSpace(text)
	if !strings.HasPrefix(inner, "[") {
		return nil, fmt.Errorf("expected array")
	}
	depth := 0
	end := -1
	inString := byte(0)
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if inString != 0 {
			if c == '\\' && inString == '"' {
				i++
				continue
			}
			if c == inString {
				inString = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inString = c
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return nil, fmt.Errorf("unterminated array")
	}
	body := inner[1:end]
	var out []any
	for _, piece := range splitTop(body, ',') {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		v, err := parseTomlValue(piece)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func parseTomlInlineTable(text string) (map[string]any, error) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "{") || !strings.HasSuffix(text, "}") {
		return nil, fmt.Errorf("expected inline table")
	}
	body := text[1 : len(text)-1]
	out := map[string]any{}
	for _, piece := range splitTop(body, ',') {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		eq := findTopLevel(piece, '=')
		if eq < 0 {
			return nil, fmt.Errorf("invalid inline table entry %q", piece)
		}
		key := parseDottedKey(strings.TrimSpace(piece[:eq]))
		v, err := parseTomlValue(strings.TrimSpace(piece[eq+1:]))
		if err != nil {
			return nil, err
		}
		target := out
		if len(key) > 1 {
			target = ensurePath(out, key[:len(key)-1])
		}
		target[key[len(key)-1]] = v
	}
	return out, nil
}

// splitTop splits on sep at bracket depth zero, outside strings.
func splitTop(s string, sep byte) []string {
	var out []string
	depth := 0
	inString := byte(0)
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString != 0 {
			if c == '\\' && inString == '"' {
				i++
				continue
			}
			if c == inString {
				inString = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inString = c
		case '[', '{', '(':
			depth++
		case ']', '}', ')':
			depth--
		default:
			if c == sep && depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}
