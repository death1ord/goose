package report

import (
	"bytes"
	"encoding/json"
)

// marshalMap encodes a map with sorted keys and no HTML escaping, matching the
// tool's stable JSON output requirement.
func marshalMap(m map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// JSONString is a convenience for compact output with the same rules.
func JSONString(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return string(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

// MarshalIndent encodes pretty JSON with the tool's stable ordering.
func MarshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// JSONStringIndent is MarshalIndent as a string.
func JSONStringIndent(v any) (string, error) {
	b, err := MarshalIndent(v)
	return string(b), err
}
