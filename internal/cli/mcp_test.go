package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPServerAndAllCommand(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/mcptest\n\ngo 1.24\n")
	write("main.go", `package main

func Used() int { return 42 }
func deadHelper() int { return 0 }

func main() {
	_ = Used()
}
`)

	// 1. Test default bare `goose` (runs all 4 engines without needing `all` or `--all`).
	outDefault, code := executeCapturedCLI(context.Background(), []string{"--root", dir, "--format", "json"})
	if code != 0 && code != 1 {
		t.Fatalf("bare goose failed with exit %d: %s", code, outDefault)
	}
	if !strings.Contains(outDefault, `"health_score"`) || !strings.Contains(outDefault, `"clone_groups"`) || !strings.Contains(outDefault, "deadHelper") {
		t.Errorf("expected default bare goose JSON output to include dead-code, health_score, and clone_groups; got:\n%s", outDefault)
	}

	// 2. Test newline-delimited MCP session: initialize, notification, ping, tools/list, tools/call.
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"goose_explain","arguments":{"topic":"context-leak"}}}`,
		fmt.Sprintf(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"goose_check_all","arguments":{"root":%q}}}`, dir),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"goose_trace","arguments":{"root":%q,"target":"main.go:Used"}}}`, dir),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"goose_fix","arguments":{"root":%q,"dry_run":true}}}`, dir),
		`{"jsonrpc":"2.0","id":8,"method":"unknown/method"}`,
	}
	inBuf := bytes.NewBufferString(strings.Join(requests, "\n") + "\n")
	var outBuf bytes.Buffer
	if err := serveMCP(context.Background(), inBuf, &outBuf, dir); err != nil {
		t.Fatalf("serveMCP failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
	// 8 requests had IDs (1 notification had no ID and must produce no response).
	if len(lines) != 8 {
		t.Fatalf("expected 8 JSON-RPC responses, got %d:\n%s", len(lines), outBuf.String())
	}

	// Verify tools/list (response index 2 -> id 3).
	if !strings.Contains(lines[2], `"goose_check_all"`) || !strings.Contains(lines[2], `"goose_fix"`) {
		t.Errorf("tools/list response missing expected tools: %s", lines[2])
	}
	// Verify goose_explain (response index 3 -> id 4).
	if !strings.Contains(lines[3], "CancelFunc") {
		t.Errorf("goose_explain response missing context-leak explanation: %s", lines[3])
	}
	// Verify goose_check_all (response index 4 -> id 5).
	if !strings.Contains(lines[4], "deadHelper") || !strings.Contains(lines[4], "health_score") {
		t.Errorf("goose_check_all response missing deadHelper or health_score: %s", lines[4])
	}
	// Verify unknown method error (response index 7 -> id 8).
	if !strings.Contains(lines[7], `"-32601"`) && !strings.Contains(lines[7], `-32601`) {
		t.Errorf("expected -32601 error for unknown method: %s", lines[7])
	}

	// 3. Test Content-Length framed MCP message.
	body := `{"jsonrpc":"2.0","id":99,"method":"ping"}`
	framedIn := bytes.NewBufferString(fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body))
	var framedOut bytes.Buffer
	if err := serveMCP(context.Background(), framedIn, &framedOut, dir); err != nil {
		t.Fatalf("serveMCP Content-Length failed: %v", err)
	}
	if !strings.HasPrefix(framedOut.String(), "Content-Length:") {
		t.Errorf("expected Content-Length framed response, got: %q", framedOut.String())
	}
	var dummy map[string]any
	parts := strings.SplitN(framedOut.String(), "\r\n\r\n", 2)
	if len(parts) != 2 || json.Unmarshal([]byte(parts[1]), &dummy) != nil {
		t.Errorf("invalid Content-Length framed JSON payload: %q", framedOut.String())
	}
}
