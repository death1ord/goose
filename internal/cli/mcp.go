package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"goose/internal/version"
)

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpRPCError    `json:"error,omitempty"`
}

type mcpRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type mcpCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type mcpContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpCallResult struct {
	Content []mcpContentItem `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

var mcpCaptureMu sync.Mutex

func runMCP(ctx context.Context, f *Flags) int {
	if err := serveMCP(ctx, os.Stdin, os.Stdout, f.Root); err != nil {
		fmt.Fprintln(os.Stderr, "goose mcp:", err)
		return 2
	}
	return 0
}

func serveMCP(ctx context.Context, r io.Reader, w io.Writer, defaultRoot string) error {
	br := bufio.NewReader(r)
	for {
		payload, framed, err := readMCPMessage(br)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(bytes.TrimSpace(payload)) == 0 {
			continue
		}
		var req mcpRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			resp := mcpResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &mcpRPCError{Code: -32700, Message: "parse error"},
			}
			if werr := writeMCPMessage(w, resp, framed); werr != nil {
				return werr
			}
			continue
		}
		// JSON-RPC notifications omit id and expect no response.
		if len(req.ID) == 0 {
			continue
		}
		resp := dispatchMCPRequest(ctx, req, defaultRoot)
		if err := writeMCPMessage(w, resp, framed); err != nil {
			return err
		}
	}
}

func readMCPMessage(br *bufio.Reader) ([]byte, bool, error) {
	for {
		line, err := br.ReadString('\n')
		if err != nil && len(line) == 0 {
			return nil, false, err
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if err != nil {
				return nil, false, err
			}
			continue
		}
		if strings.HasPrefix( strings.ToLower(trimmed), "content-length:") {
			return readContentLengthBody(br, trimmed)
		}
		return []byte(trimmed), false, nil
	}
}

func readContentLengthBody(br *bufio.Reader, firstHeader string) ([]byte, bool, error) {
	valStr := strings.TrimSpace(firstHeader[len("content-length:"):])
	length, err := strconv.Atoi(valStr)
	if err != nil || length < 0 {
		return nil, true, fmt.Errorf("invalid Content-Length: %q", valStr)
	}
	for {
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			return nil, true, rerr
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, true, err
	}
	return buf, true, nil
}

func writeMCPMessage(w io.Writer, resp mcpResponse, framed bool) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if framed {
		header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(data))
		if _, err := io.WriteString(w, header); err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

func dispatchMCPRequest(ctx context.Context, req mcpRequest, defaultRoot string) mcpResponse {
	switch req.Method {
	case "initialize":
		return handleMCPInitialize(req)
	case "ping":
		return mcpResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}
	case "tools/list":
		return mcpResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": mcpToolDefinitions()}}
	case "tools/call":
		return handleMCPToolCall(ctx, req, defaultRoot)
	default:
		return mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &mcpRPCError{Code: -32601, Message: "method not found: " + req.Method},
		}
	}
}

func handleMCPInitialize(req mcpRequest) mcpResponse {
	proto := "2024-11-05"
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len(req.Params) > 0 && json.Unmarshal(req.Params, &p) == nil && p.ProtocolVersion != "" {
		proto = p.ProtocolVersion
	}
	res := map[string]any{
		"protocolVersion": proto,
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    "goose",
			"version": version.Version,
		},
		"instructions": "Use goose_check_all to run all 4 Go analysis engines (dead-code, architecture, health, dupes) in one pass, or call specific tools. Use goose_trace before removing suspicious symbols, goose_fix (with dry_run=true first) for safe mechanical dead-code cleanup, and goose_explain for remediation details.",
	}
	return mcpResponse{JSONRPC: "2.0", ID: req.ID, Result: res}
}

func handleMCPToolCall(ctx context.Context, req mcpRequest, defaultRoot string) mcpResponse {
	var params mcpCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &mcpRPCError{Code: -32602, Message: "invalid params: " + err.Error()},
		}
	}
	argv, err := buildMCPToolArgv(params.Name, params.Arguments, defaultRoot)
	if err != nil {
		return mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: mcpCallResult{
				Content: []mcpContentItem{{Type: "text", Text: err.Error()}},
				IsError: true,
			},
		}
	}
	outText, exitCode := executeCapturedCLI(ctx, argv)
	return mcpResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: mcpCallResult{
			Content: []mcpContentItem{{Type: "text", Text: outText}},
			IsError: exitCode == 2,
		},
	}
}

func buildMCPToolArgv(name string, args map[string]any, defaultRoot string) ([]string, error) {
	root := argString(args, "root", defaultRoot)
	switch name {
	case "goose_check_all":
		argv := []string{"--format", "json"}
		return appendCommonMCPFlags(argv, root, args), nil
	case "goose_dead_code":
		argv := []string{"dead-code", "--format", "json"}
		if argBool(args, "include_entry_exports", false) {
			argv = append(argv, "--include-entry-exports")
		}
		return appendCommonMCPFlags(argv, root, args), nil
	case "goose_architecture":
		argv := []string{"architecture", "--format", "json"}
		if argBool(args, "cycles_only", false) {
			argv = append(argv, "--cycles")
		}
		if argBool(args, "boundaries_only", false) {
			argv = append(argv, "--boundaries")
		}
		if argBool(args, "policy_only", false) {
			argv = append(argv, "--policy")
		}
		return appendCommonMCPFlags(argv, root, args), nil
	case "goose_health":
		argv := []string{"health", "--format", "json", "--score"}
		if argBool(args, "coverage_gaps", false) {
			argv = append(argv, "--coverage-gaps")
		}
		if cov := argString(args, "coverage_profile", ""); cov != "" {
			argv = append(argv, "--coverage", cov)
		}
		if top := argInt(args, "top", 0); top > 0 {
			argv = append(argv, "--top", strconv.Itoa(top))
		}
		return appendCommonMCPFlags(argv, root, args), nil
	case "goose_dupes":
		argv := []string{"dupes", "--format", "json"}
		if mode := argString(args, "mode", ""); mode != "" {
			argv = append(argv, "--mode", mode)
		}
		if mt := argInt(args, "min_tokens", 0); mt > 0 {
			argv = append(argv, "--min-tokens", strconv.Itoa(mt))
		}
		if ml := argInt(args, "min_lines", 0); ml > 0 {
			argv = append(argv, "--min-lines", strconv.Itoa(ml))
		}
		return appendCommonMCPFlags(argv, root, args), nil
	case "goose_audit":
		argv := []string{"audit", "--format", "json"}
		if base := argString(args, "base", ""); base != "" {
			argv = append(argv, "--base", base)
		}
		if argBool(args, "brief", false) {
			argv = append(argv, "--brief")
		}
		return appendCommonMCPFlags(argv, root, args), nil
	case "goose_fix":
		argv := []string{"fix", "--format", "json"}
		if argBool(args, "dry_run", true) {
			argv = append(argv, "--dry-run")
		} else {
			argv = append(argv, "--yes")
		}
		if argBool(args, "force", false) {
			argv = append(argv, "--force")
		}
		return appendCommonMCPFlags(argv, root, args), nil
	case "goose_trace":
		target := argString(args, "target", "")
		if target == "" {
			return nil, errors.New("missing required argument: target (e.g. internal/pkg/file.go:Symbol)")
		}
		argv := []string{"dead-code", "--trace", target}
		if root != "" {
			argv = append(argv, "--root", root)
		}
		return argv, nil
	case "goose_explain":
		argv := []string{"explain"}
		if topic := argString(args, "topic", ""); topic != "" {
			argv = append(argv, topic)
		}
		return argv, nil
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

func appendCommonMCPFlags(argv []string, root string, args map[string]any) []string {
	if root != "" {
		argv = append(argv, "--root", root)
	}
	if argBool(args, "production", false) {
		argv = append(argv, "--production")
	}
	if cs := argString(args, "changed_since", ""); cs != "" {
		argv = append(argv, "--changed-since", cs)
	}
	if argBool(args, "no_cache", false) {
		argv = append(argv, "--no-cache")
	}
	if p := argString(args, "path", ""); p != "" {
		argv = append(argv, p)
	}
	return argv
}

func argString(args map[string]any, key, def string) string {
	if args == nil {
		return def
	}
	if v, ok := args[key].(string); ok && v != "" {
		return v
	}
	return def
}

func argBool(args map[string]any, key string, def bool) bool {
	if args == nil {
		return def
	}
	if v, ok := args[key].(bool); ok {
		return v
	}
	return def
}

func argInt(args map[string]any, key string, def int) int {
	if args == nil {
		return def
	}
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return def
}

func executeCapturedCLI(ctx context.Context, argv []string) (string, int) {
	mcpCaptureMu.Lock()
	defer mcpCaptureMu.Unlock()

	origOut, origErr := os.Stdout, os.Stderr
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		return fmt.Sprintf("failed to allocate stdio pipe: %v", err), 2
	}
	os.Stdout = wPipe
	os.Stderr = wPipe

	outCh := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rPipe)
		outCh <- buf.String()
	}()

	code := Run(ctx, argv)
	_ = wPipe.Close()
	os.Stdout = origOut
	os.Stderr = origErr
	out := <-outCh
	_ = rPipe.Close()
	return strings.TrimSpace(out), code
}

func mcpToolDefinitions() []mcpTool {
	rootProp := map[string]any{"type": "string", "description": "Project root directory (defaults to server working directory)."}
	prodProp := map[string]any{"type": "boolean", "description": "Ignore _test.go files and analyze production code only."}
	changedProp := map[string]any{"type": "string", "description": "Scope findings to files changed since this git ref (e.g. origin/main)."}
	return []mcpTool{
		{
			Name:        "goose_check_all",
			Description: "Run all 4 goose engines (dead-code, architecture, health complexity/scores, and code duplication) on a Go project in a single pass and return structured JSON findings and remediation actions.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"root":          rootProp,
					"production":    prodProp,
					"changed_since": changedProp,
					"path":          map[string]any{"type": "string", "description": "Optional sub-path filter."},
				},
			},
		},
		{
			Name:        "goose_dead_code",
			Description: "Find unused files, exports, unexported symbols, types, fields, methods, dependencies, and Go correctness/concurrency/leak/security issues.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"root":                  rootProp,
					"production":            prodProp,
					"include_entry_exports": map[string]any{"type": "boolean", "description": "Check exported symbols in main/entry packages."},
					"changed_since":         changedProp,
				},
			},
		},
		{
			Name:        "goose_architecture",
			Description: "Analyze import cycles, boundary zone violations, and rule-pack policy violations.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"root":            rootProp,
					"cycles_only":     map[string]any{"type": "boolean", "description": "Report import cycles only."},
					"boundaries_only": map[string]any{"type": "boolean", "description": "Report boundary violations only."},
					"policy_only":     map[string]any{"type": "boolean", "description": "Report rule-pack policy violations only."},
				},
			},
		},
		{
			Name:        "goose_health",
			Description: "Compute function cyclomatic/cognitive complexity, CRAP scores, git-churn hotspots, coverage gaps, refactoring targets, and 0-100 health score.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"root":             rootProp,
					"production":       prodProp,
					"coverage_gaps":    map[string]any{"type": "boolean", "description": "Include untested-file and untested-export findings."},
					"coverage_profile": map[string]any{"type": "string", "description": "Path to Go coverage profile for exact CRAP scores."},
					"top":              map[string]any{"type": "integer", "description": "Cap output tables to top N entries."},
				},
			},
		},
		{
			Name:        "goose_dupes",
			Description: "Detect duplicated code blocks (clone groups and clone families).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"root":       rootProp,
					"mode":       map[string]any{"type": "string", "description": "Clone matching mode: strict, mild, weak, or semantic."},
					"min_tokens": map[string]any{"type": "integer", "description": "Minimum token count for a clone."},
					"min_lines":  map[string]any{"type": "integer", "description": "Minimum line count for a clone."},
				},
			},
		},
		{
			Name:        "goose_audit",
			Description: "Run the changed-file PR quality gate (dead-code, complexity, and duplication) against a base git ref.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"root":  rootProp,
					"base":  map[string]any{"type": "string", "description": "Base git ref (defaults to upstream or origin/main)."},
					"brief": map[string]any{"type": "boolean", "description": "Advisory mode (always exits 0)."},
				},
			},
		},
		{
			Name:        "goose_fix",
			Description: "Preview (dry_run=true) or apply (dry_run=false) automatic removal of dead files, unused symbols, stale suppressions, and unused go.mod dependencies with build verification and rollback.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"root":    rootProp,
					"dry_run": map[string]any{"type": "boolean", "description": "Preview changes without modifying files (defaults to true)."},
					"force":   map[string]any{"type": "boolean", "description": "Allow fixing even when the git worktree has uncommitted changes."},
				},
			},
		},
		{
			Name:        "goose_trace",
			Description: "Explain why a symbol (e.g. internal/pkg/file.go:Symbol) is kept alive or reported dead.",
			InputSchema: map[string]any{
				"type":     "object",
				"required": []string{"target"},
				"properties": map[string]any{
					"root":   rootProp,
					"target": map[string]any{"type": "string", "description": "Symbol target in path/to/file.go:SymbolName format."},
				},
			},
		},
		{
			Name:        "goose_explain",
			Description: "Explain a goose rule or finding kind and how to remediate or suppress it. Omit topic to list all supported topics.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"topic": map[string]any{"type": "string", "description": "Rule or finding kind (e.g. unused-export, context-leak, nil-error-interface)."},
				},
			},
		},
	}
}

