# AGENTS.md

Monorepo for the Agent Receipts protocol — cryptographically signed audit trails for AI agent actions. Contains the protocol spec, SDKs in three languages, an MCP proxy, and the documentation site.

## Monorepo layout

```
spec/          # Protocol specification and JSON schemas
sdk/go/        # Go SDK (receipt, store, taxonomy)
sdk/ts/        # TypeScript SDK (@obsigna/sdk-ts)
sdk/py/        # Python SDK (obsigna)
mcp-proxy/     # MCP STDIO proxy with audit, policy, and receipts (Go)
hook/          # PostToolUse hook binary for Claude Code and other runtimes (Go)
integrations/  # Per-agent-runtime adapters (e.g. opencode-plugin; hook to migrate here)
site/          # Documentation site (Astro)
cross-sdk-tests/  # Cross-language receipt verification tests
formal/        # Formal models (Alloy) machine-checking protocol properties
```

Each subdirectory has its own AGENTS.md with project-specific details.

## Quick reference

| Component | Language | Test command | Build command |
|-----------|----------|-------------|---------------|
| sdk/go | Go | `go test ./...` | `go build ./...` |
| sdk/ts | TypeScript | `pnpm test` | `pnpm build` |
| sdk/py | Python | `uv run pytest` | `uv build` |
| mcp-proxy | Go | `go test ./...` | `go build ./cmd/...` (obsigna-mcp + mcp-proxy shim) |
| hook | Go | `go test ./...` | `go build ./cmd/...` (obsigna-hook + agent-receipts-hook shim) |
| site | TypeScript | — | `pnpm build` |
| spec | — | — | JSON schema validation |

## Operational state

Operational state lives at `docs/operations/current.md`. Read this first when starting a session. Update it when nodes change state.

## Conventions

- All changes go through pull requests — never push directly to main
- CI is path-filtered: changes to `sdk/go/` only trigger Go SDK CI
- mcp-proxy CI also triggers on `sdk/go/` changes (dependency)
- hook CI also triggers on `sdk/go/` changes (dependency)
- Site deploys on `site/**` or `spec/**` changes
- Go modules share a repo-root `go.work` (see [Go workspace](#go-workspace)); never add a local `replace` directive in any published `go.mod`
- Run language-specific linters before committing (go vet, biome, ruff)

## Dependencies

```
spec (protocol definition)
  ↓
sdk/go ← mcp-proxy (linked locally via repo-root go.work)
sdk/go ← hook (linked locally via repo-root go.work)
sdk/go ← cross-sdk-tests (linked locally via repo-root go.work)
sdk/ts
sdk/py
```

SDKs are independent implementations of the same spec. They do not depend on each other but must produce compatible receipts (same canonical JSON, same signature encoding, same hash format).

## Go workspace

The repo-root `go.work` lists `./sdk/go`, `./mcp-proxy`, `./hook`, `./daemon`, and `./cross-sdk-tests`. It is committed so that:

- Local builds and tests of `mcp-proxy` and `hook` exercise the in-tree `sdk/go` (not the published version).
- CI does the same — `mcp-proxy` and `hook` PR checks catch breakage from `sdk/go` changes in the same PR, closing the gap where two passing per-module workflows could still ship a broken integration.
- Published `go.mod` files stay free of local `replace` directives — `publish-go.yml` rejects those at release time. Use `go.work` for monorepo wiring instead.

After cloning, no extra setup is required: `go build`, `go test`, and `go vet` from any module directory will pick up the workspace automatically.

## Security

- Never commit real private keys. Test fixtures use well-known test keys only (see each SDK's test helpers).
- Never store plaintext secrets in receipts — parameters must be hashed before inclusion.
- Ed25519 is the only supported signing algorithm. Do not introduce alternative or weaker schemes.
- Validate all inputs at trust boundaries (function parameters, environment variables, stored data). Crypto code must reject invalid inputs explicitly, not silently degrade.
- Report vulnerabilities via [GitHub Security Advisories](https://github.com/agent-receipts/obsigna/security/advisories/new), not public issues. See [SECURITY.md](SECURITY.md).

## Mindset

- Think before acting. Understand the problem before writing code.
- Work like a craftsman — do the better fix, not the quickest fix.
- Fix from first principles, not bandaids.
- Write idiomatic, simple, maintainable code.
- Delete unused code ruthlessly. No breadcrumb comments ("moved to X", "removed").
- Leave the repo better than you found it.

## Papercut rule

- Fix small issues you notice while working (typos, dead imports, minor inconsistencies).
- Raise larger cleanups with the user before expanding scope.

## Timeout handling

- If a command runs longer than 35 minutes, stop it, capture logs/context, and check with the user.
- Do not wait indefinitely for hung processes.

## Adding dependencies

- Research before adding — prefer well-maintained, widely-used packages with good APIs.
- Avoid unmaintained dependencies (check last commit date, open issues, bus factor).
- Prefer the standard library when it covers the use case adequately.
- New dependencies require justification in the PR description.
- For Go: check pkg.go.dev for import counts and maintenance signals.
- For Python: check PyPI download stats and last release date.
- For TypeScript: check npm weekly downloads and maintenance status.
- Supply chain security matters for a cryptographic protocol project — evaluate carefully.

## Completing work

Before marking work as complete:

1. Confirm all touched tests and linters pass.
2. Re-read your full diff — check for mistakes, consistency, and completeness.
3. Summarise changes with file and line references.
4. Mention any opportunistic papercut fixes made along the way.
5. Call out TODOs, follow-up work, or uncertainties.
6. If opening a PR, verify the description accurately reflects the changes.

## Agent safety rules

When working in this repo as an AI coding agent, these rules apply in addition to the conventions above:

- **Never modify CI/CD workflows** (`.github/workflows/`) without explicit human review
- **Never weaken cryptographic parameters** — do not change key sizes, hash algorithms, or signature schemes
- **Never skip or delete existing tests** — add tests, don't remove them
- **Never generate real cryptographic keys** — always use test fixtures from each SDK's test helpers
- **Never modify the protocol spec** (`spec/`) without explicit human approval
- **Always run the full test suite** for any SDK you change before proposing a PR
- **Cross-SDK changes require cross-language test verification** — if you change receipt format in one SDK, verify the cross-language tests still pass
- **Write tests first** — new functions must have test coverage before pushing; writing tests first forces you to think about edge cases (nil inputs, corruption, concurrency)
- **Use git worktrees** for new work — do not edit directly on main or shared branches, to avoid conflicts with other agents or in-progress work. Once the worktree exists, switch your session's working directory *into* it (Claude Code: the `EnterWorktree` tool, or `EnterWorktree` with the worktree `path`) and run commands from there. Do **not** prefix every shell command with `cd <worktree> && …`: the shell resets to the session's primary directory between calls, so a per-command `cd` re-triggers a permission prompt on every single invocation.
- **Self-review before committing** — follow the Completing work checklist above
