---
name: goose
description: Analyze and remediate Go codebase issues using goose (dead code, Go correctness/concurrency/leak/security checks, architecture boundaries, complexity/CRAP health, and code duplication) via CLI or MCP.
---

# Goose — Go Codebase Intelligence & Remediation Skill

Use `goose` whenever inspecting, auditing, cleaning up, or refactoring a Go repository. `goose` combines `go/packages` + `go/types` + AST static analysis across four engines:
1. **`dead-code`**: Unused files, exports, unexported symbols, types, fields, methods, interface methods, params/receivers, `go.mod` dependencies, plus Go correctness, concurrency, resource-leak, struct-padding, and security checks.
2. **`architecture`**: Import cycles, boundary zone violations, and declarative rule-pack violations.
3. **`health`**: Cyclomatic/cognitive complexity, CRAP scores, git-churn hotspots, coverage gaps (`untested-file`, `untested-export`), and 0–100 health score.
4. **`dupes`**: Token-level code duplication and diverged clone siblings.

---

## 1. How to Invoke Goose

### Via MCP (`goose mcp`)
Configure the MCP server in your agent settings:
```json
{
  "mcpServers": {
    "goose": {
      "command": "goose",
      "args": ["mcp"]
    }
  }
}
```
Available MCP tools:
- `goose_check_all` — Run all 4 engines (`dead-code`, `architecture`, `health`, `dupes`) in a single shared pass.
- `goose_dead_code`, `goose_architecture`, `goose_health`, `goose_dupes`, `goose_audit` — Run individual engines.
- `goose_trace` — Trace symbol liveness (`path/to/file.go:Symbol`) before deleting.
- `goose_fix` — Preview (`dry_run: true`) or apply (`dry_run: false`) safe auto-removals with `go build` rollback verification.
- `goose_explain` — Get detailed rule explanations and remediation steps.

### Via CLI
```bash
# Default invocation runs all 4 engines (dead-code, architecture, health, dupes) in one pass
goose --format json

# Individual engines when you want to focus on one category
goose dead-code --format json
goose architecture --format json
goose health --score --coverage-gaps --format json
goose dupes --format json

# PR / branch quality gate against base ref
goose audit --base origin/main --format json
```

---

## 2. Agent Remediation Workflow

Follow this exact order when fixing findings reported by `goose`:

### Step 1: Run `goose --format json` (or `goose_check_all`)
Inspect the `findings[]` list. Every finding includes:
- `kind` and `rule`
- `path`, `line`, `col`
- `message`
- `actions[]` (`type`, `description`, `auto_fixable`)

### Step 2: Trace Suspicious Symbols Before Deleting
If an exported or unexported symbol looks like it might be used via reflection, codegen, or build tags, trace it first:
```bash
goose dead-code --trace internal/pkg/file.go:SymbolName
```

### Step 3: Auto-Fix Mechanical Dead Code with `goose fix`
Do **not** manually delete dozens of unused declarations by hand when `auto_fixable: true`. Let `goose fix` remove them AST-safely and verify the build:
```bash
goose fix --dry-run
goose fix --yes
```
`goose fix --yes` automatically runs `go build ./...` after applying edits and rolls back if compilation fails.

### Step 4: Fix Semantic Go Correctness, Concurrency, Leak, and Security Issues
These findings require targeted code edits:

| Rule / Kind | What is wrong | How to correct it |
|-------------|---------------|-------------------|
| `can-be-unexported` | Exported symbol is only used inside its own declaring package. | Rename `Foo` -> `foo` across its declaring package to shrink public API surface. |
| `unused-parameter` / `unused-receiver` | Function parameter or method receiver is never read in the body. | Rename the unused parameter/receiver to `_` (or remove the parameter if callers are internal and don't follow an interface). |
| `unused-interface-method` | A method declared on an interface has 0 call sites across the project. | Remove the method from the interface definition (and remove dead implementations if no longer needed). |
| `write-only-field` / `write-only-variable` | Struct field or package variable is assigned/initialized but never read. | Either wire up the missing read logic (if it's a bug) or delete the field/variable and its assignments. |
| `struct-padding` | Struct fields are ordered poorly for 64-bit alignment, wasting memory. | Reorder struct fields from largest alignment (8-byte pointers/slices/int64) down to smallest (1-byte `bool`/`uint8`). |
| `nil-error-interface` | Returning a typed `nil` pointer (`var p *MyErr = nil; return p`) as `error`, which makes `err != nil` evaluate to `true`! | Return literal `nil` explicitly (`if p == nil { return nil }`). |
| `unchecked-type-assertion` | Single-value `x := v.(T)` panics on mismatch. | Use comma-ok: `x, ok := v.(T)` and handle `!ok`. |
| `context-leak` | `context.WithCancel` / `WithTimeout` / `WithDeadline` without calling `cancel` on all paths. | Add `defer cancel()` immediately after creating the derived context. |
| `unclosed-body` / `unclosed-resource` | `*http.Response.Body` or `*sql.Rows` is not closed (or `rows.Err()` not checked). | After checking `if err != nil`, add `defer resp.Body.Close()` (or `defer rows.Close()` and check `rows.Err()`). |
| `defer-in-loop` | `defer` inside a `for`/`range` loop retains resources until function exit. | Extract the loop body into a helper function so `defer` runs per iteration, or close explicitly before loop end. |
| `copylocks` / `sync-value-copy` | Passing/assigning `sync.Mutex`, `sync.WaitGroup`, `sync.Once`, `sync.Map`, or `sync.Cond` by value. | Pass a pointer (`*sync.Mutex`, `*sync.WaitGroup`, or pointer receiver `(s *Struct)`). |
| `goroutine-leak` | Unbuffered channel in goroutine risks blocking forever if receiver exits early (e.g. `ctx.Done()`). | Use a buffered channel (`make(chan T, 1)`) or `select` with `case <-ctx.Done():`. |
| `security-sink` | Dynamic string concatenation in `exec.Command` / SQL query, `math/rand` in crypto context, or `InsecureSkipVerify: true`. | Parameterize SQL queries, pass discrete args to `exec.Command`, use `crypto/rand`, and enforce TLS verification. |
| `secret-in-code` | Hardcoded API key, private key, or credential literal in source. | Load the secret from environment variables or a secret manager. |
| `circular-dependency` / `boundary-violation` / `deep-import` | Package import violates architecture boundaries or creates cycles. | Move shared types/interfaces into a lower-layer package or depend on an interface in the consumer package. |
| `complexity-finding` | Function exceeds cyclomatic/cognitive threshold or has high CRAP score. | Extract branches/loops into small, single-purpose helper functions and add unit tests. |
| `code-duplication` / `diverged-clone-sibling` | Duplicated logic across files/functions. | Extract shared logic into a parameterized helper function. |

### Step 5: Suppress Intentional Findings Cleanly
When a symbol or pattern is intentionally kept (e.g. plugin hook, external ABI, cgo callback, benchmark fixture), add a suppression comment with a rationale:
```go
// goose-ignore-next-line unused-export -- called by external plugin loader
func RegisterPlugin() {}
```
Do not leave unused suppressions behind (`goose` reports them as `stale-suppression`).

### Step 6: Verify Clean State
Re-run `goose` and `go test ./...` to confirm zero remaining issues and passing tests.

