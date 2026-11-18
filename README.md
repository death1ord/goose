# goose

Codebase intelligence for Go. `goose` analyzes a Go module — its package
graph, symbols, complexity, duplication, and architecture — and reports dead
code, hot spots, boundary violations, and a health score, with the same
machine-readable contracts a CI gate or an agent needs.

It is a Go analyzer, not a rewrite: it reads Go using `go/ast`, `go/types`,
and `golang.org/x/tools/go/packages`, so findings understand the language
(entry points are real `main` packages, interface satisfaction and
reflection-based codecs keep symbols alive, and Go coverage profiles give
exact CRAP numbers).

## Install

```sh
go build -o goose ./cmd/goose
```

## Quick start

```sh
goose                      # runs all 4 engines: dead-code + architecture + health + dupes
goose dead-code            # unused files, symbols, fields, methods, deps
goose health --score       # complexity, hotspots, file scores, 0-100 score
goose dupes                # duplicated code blocks (clone groups)
goose architecture         # import cycles, boundary zones, policy packs
goose audit --base main    # changed-file PR quality gate (verdict: pass/warn/fail)
goose fix --dry-run        # preview removals; apply with --yes
goose list                 # inventory files, entry points, boundaries
goose mcp                  # start MCP server over stdio for AI agents
```

## Commands

| Command | What it reports |
|---------|-----------------|
| `dead-code`, `check` | Unused files, exports, unexported symbols, types, fields, methods, constants, variables, dependencies, unresolved imports, duplicate exports, stale suppressions. `--trace <file:Symbol>` explains one symbol's liveness. |
| `health` | Function complexity (cyclomatic, cognitive, CRAP), large functions/files, file health scores, git-churn hotspots, ranked refactoring targets, and the project health score. `--coverage profile.out` switches CRAP from static-estimated to exact. |
| `dupes` | Token-level clone detection with stable fingerprints and clone families. Thresholds: `--min-tokens`, `--min-lines`, `--threshold <pct>`. |
| `architecture` | Import cycles (`--cycles`), boundary zone violations from presets or configured zones (`--boundaries`), and rule-pack policy violations (`--policy`). No selector reports all three. |
| `audit` | The changed-file gate: dead-code + complexity + duplication over files changed since a base, with introduced-vs-inherited attribution and a pass/warn/fail verdict. |
| `review` | Advisory `audit --brief`: same report, gates unenforced, always exits 0. Pairs with `--format review-github`/`review-gitlab` envelopes for PR automation. |
| `fix` | Auto-removes dead files, symbols, stale suppressions, and unused `go.mod` requires. Re-verifies the build and rolls every edit back if it stops compiling. |
| `list` | Read-only inventory: files, entry points, architecture zones, suppression markers. |
| `all` (`--all`) | Runs all four engines (`dead-code`, `architecture`, `health`, `dupes`) in a single shared pass. |
| `mcp` | Starts a JSON-RPC 2.0 Model Context Protocol (MCP) server over stdio (`goose_check_all`, `goose_dead_code`, `goose_health`, `goose_dupes`, `goose_architecture`, `goose_audit`, `goose_fix`, `goose_trace`, `goose_explain`). See `skills/goose/SKILL.md` for agent remediation guidance. |
| `explain`, `version`, `init` | Issue-type help, the version, and a starter config. |

## Output formats

Every analysis renders through one finding model:

```
human  json  compact  markdown  sarif  codeclimate  gitlab-codequality
github-annotations  github-summary  pr-comment-github  pr-comment-gitlab
review-github  review-gitlab  badge
```

`--format json` emits a typed envelope with `findings`, stable
`finding_id`s (line-free, so they survive edits), `effective_severity`,
per-finding `actions`, `gate_outcomes`, `summary`, and `next_steps`.

## Scoping & grouping

Analyze only the code that changed, or partition a report per team:

```bash
goose dead-code --changed-since origin/main      # diff base (alias --base, GOOSE_AUDIT_BASE)
goose dead-code --diff-file pr.patch --format json
cat pr.patch | goose dupes --diff-stdin
goose audit --base main                          # changed-file quality gate
goose dead-code docs/                            # positional path scope

goose dead-code --group-by owner                 # CODEOWNERS (owner|directory|package|section)
goose health --group-by directory --score        # per-bucket scores
goose health --group-by owner --group '@team/*,!@team/b'  # keep selected groups
```

Machine formats (SARIF, CodeClimate) annotate each result with its group
key; compact/markdown/badge stay flat and print a stderr note pointing at
`--format json`. `--group-by owner` needs a CODEOWNERS file (root,
`.github/`, `.gitlab/`, `docs/`, or the config `codeowners` path);
`section` needs GitLab `[Section]` headers; `package` needs a `go.work`.
`goose audit` and `goose dupes --top` refuse `--group-by`.

## Baselines & the ratchet

```bash
goose dead-code --save-baseline goose-baseline.json   # accept today's findings
goose dead-code --baseline goose-baseline.json        # report only what's new
goose dead-code --baseline goose-baseline.json --fail-on-stale-baseline
goose dead-code --baseline goose-baseline.json \
    --fail-on-baseline-growth --baseline-base origin/main
```

`--fail-on-baseline-growth` compares the baseline file in the worktree
against itself at a base ref (default: the audit base — upstream, remote
default, then `GOOSE_AUDIT_BASE`), so a PR that adds a finding **and**
re-saves the baseline in one commit still fails. A missing/unparsable base
or a base that resolves to HEAD is exit 2; a brand-new baseline passes with
a note. The stale gate stands down, with a note, on scope-narrowed runs
(path/diff/base/workspace/production) — a partial run cannot judge a
whole-project baseline. `dupes`, `architecture`, and `audit` support
per-analysis baselines (`--dead-code-baseline`, `--health-baseline`,
`--dupes-baseline`) through the same gates.

## Health trends & snapshots

```bash
goose health --score --save-snapshot            # .goose/snapshots/<ts>.json
goose health --score --trend                  # deltas vs the newest snapshot
goose health --score --trend-from base.json   # deltas vs one file
goose health --coverage-gaps                  # runtime code no test reaches
```

`--trend` emits `health_trend`: per-metric deltas (score only when both
snapshots share a score formula) with improving/declining/stable
directions. `--coverage-gaps` reports `untested-file`/`untested-export`
findings for code outside the test dependency closure, plus file-coverage
stats. Grouped runs store per-bucket vital signs; each `groups[]` entry
then carries its own `trend`.

## Flags

Global: `--format` (+ `review-github`/`review-gitlab` envelope formats),
`--pretty`, `--quiet`, `--ci`, `--fail-on-issues`, `--only`/`--skip`,
`--baseline`/`--save-baseline`, `--fail-on-stale-baseline`,
`--fail-on-baseline-growth`, `--baseline-base`, `--changed-since`,
`--diff-file`/`--diff-stdin`, `--since` (churn window: `90d`, `6m`, `1y`,
`2w`), `--group-by`/`--group`, `--lean` (+`--full-tables`) for the trimmed
JSON profile, `--threads`, `--max-file-size`, `--min-score`,
`--min-severity`, `--score`, `--trend`, `--save-snapshot`, `--coverage`,
`--coverage-gaps`, `--explain`, `--output-file`, `--sarif-file`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No enforced gate failed. |
| 1 | An enforced gate failed (an error-severity finding, a threshold, or a failed audit verdict) — not a tool error. |
| 2 | Invalid input or a tool error (bad flag, unreadable config, unresolvable base ref). |

`audit` additionally returns verdict `warn` as a signal with exit 0 (warn-tier
findings only) so a job can surface them without going red.

## Suppressing findings

```go
// goose-ignore-next-line unused-export -- rationale here
func KeepEvenThoughUnused() {}

// goose-ignore-file unused-file
// goose-ignore-start unused-field ... goose-ignore-end
```

Unused markers are themselves reported under `stale-suppressions`.

## Configuration

Goose looks for `.gooserc.json`, `goose.json`, or `goose.toml` (the fallow
spellings are still read). It supports `extends` chains, per-rule severities,
path `overrides`, boundaries zones/`rulePacks`, and health thresholds:

```jsonc
{
  "rules": { "duplicate-exports": "off", "unused-fields": "warn" },
  "overrides": [{ "files": ["internal/generated/**"], "rules": { "*": "off" } }],
  "boundaries": {
    "preset": "layered",
    "rules": [{ "from": "domain", "allow": ["domain"] }]
  },
  "rulePacks": ["policies/team.jsonc"],
  "health": { "maxCyclomatic": 20, "coverage": "coverage.out" }
}
```

Rule packs are declarative JSON files: `banned-call` (callee patterns like
`os.Exit` or `fmt.*`), `banned-import` (module specifiers, with optional
`allowNames`), and `banned-export` (declared names), each optionally scoped to
a boundary `zone`, with a per-rule `severity`. They are pure data; loading one
never executes project code. A missing or invalid pack fails the run with exit
2 (`banned-effect` needs a JS dependency catalogue and is rejected for Go).

`goose init` writes a starter `.gooserc.json`.

## How the analysis works

1. **Load** — `go/packages` yields the type-checked snapshot and full syntax.
2. **Facts** — every declared symbol becomes an entity; every identifier,
   field read, method call, interface satisfaction, and reflected marshal
   becomes a use. Reflection (`json`/`xml`/`fmt.Stringer`, …) and stdlib
   interface implementations credit the symbols they keep alive, so they are
   never falsely reported dead.
3. **Graph** — package imports give reachability from entry points, dead
   packages, and import cycles.
4. **Analyses** — dead-code, health, dupes, architecture, audit read the
   shared snapshot; suppression markers, baselines, and rule severities
   filter the findings; one report model renders every format.

## Development

```sh
go build ./...        # compile
go test ./...         # unit + integration tests
go vet ./...          # static checks
gofmt -l cmd internal # formatting must be clean
```
