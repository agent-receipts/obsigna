# Doc e2e personas

The adopter journeys the documentation fleet walks. Each persona is run by the
`doc-e2e-runner` subagent, one invocation per persona. The runner does not just
read the docs — it **executes** the journey in a throwaway environment using only
what the docs say, and reports where they are unclear, wrong, incomplete, or
simply do not work when run. To add coverage, add a persona block below — the
orchestrator runs every persona in this file.

Each block gives the runner: who the user is, the goal that defines success, a
platform preference, and the ordered journey of doc pages (mapped to
`site/src/content/docs/<path>.mdx`). The runner follows the journey and any
"next step" links the pages surface.

**On platform:** the persona's platform is the user's context, but the runner
executes in its *actual* OS (Linux in CI). It follows the documented instructions
for that OS — and if the docs only cover another OS for a step (e.g. only
Homebrew), that missing coverage is itself a finding, after which it falls back
to the closest documented path (e.g. "from source") to keep the journey going.

---

## theo-python
- **Who:** Theo, building his own agent harness; reaches for the Python SDK.
- **Platform:** macOS.
- **Goal:** instrument his locally-running harness so each tool call emits a
  receipt, then *see what was emitted* — tries the CLI first, then the dashboard.
- **Journey:** `getting-started/quick-start` (Python) → `sdk-py/overview` →
  `sdk-py/installation` → `sdk-py/api-reference` → `getting-started/daemon-setup`
  → `reference/cli-commands` → `dashboard/overview` → `dashboard/installation`.
- **Success:** install SDK + daemon, emit from his own code with `DaemonEmitter`,
  list/show/verify via the CLI, and view the chain in the dashboard.

## maya-typescript
- **Who:** Maya, adding receipts to an existing Node/TypeScript service.
- **Platform:** macOS (Node 24).
- **Goal:** emit a receipt from app code, then verify the chain from the CLI.
- **Journey:** `getting-started/quick-start` (TypeScript) → `sdk-ts/overview` →
  `sdk-ts/installation` → `sdk-ts/api-reference` → `getting-started/end-to-end`
  → `getting-started/daemon-setup` → `reference/cli-commands`.
- **Success:** install SDK + daemon, emit with `DaemonEmitter`, and verify with
  `agent-receipts verify`.

## raj-go
- **Who:** Raj, instrumenting a Go backend service.
- **Platform:** Linux.
- **Goal:** emit receipts from a Go service and verify them.
- **Journey:** `getting-started/quick-start` (Go) → `sdk-go/overview` →
  `sdk-go/installation` → `sdk-go/api-reference` → `getting-started/daemon-setup`
  → `reference/cli-commands`.
- **Success:** `go get` the SDK, emit with the daemon emitter, and verify the
  chain. Pay attention to Linux socket-path guidance.

## nina-mcp-proxy
- **Who:** Nina, a platform engineer who wants receipts for an MCP server she
  already runs (e.g. GitHub MCP) without changing client or server code.
- **Platform:** macOS, using Claude Desktop.
- **Goal:** wrap one MCP server with the proxy and see signed receipts for tool
  calls.
- **Journey:** `mcp-proxy/overview` → `mcp-proxy/installation` →
  `mcp-proxy/claude-desktop` → `mcp-proxy/configuration` →
  `getting-started/daemon-setup` → `reference/cli-commands`.
- **Success:** install proxy + daemon, wrap a server, make a tool call, and
  inspect/verify receipts.

## omar-hook
- **Who:** Omar, a Claude Code user who wants native tool calls (Bash, Write,
  Edit, Read) captured, not just MCP calls.
- **Platform:** macOS.
- **Goal:** wire the PostToolUse hook so native tool calls produce receipts.
- **Journey:** `hook/overview` → `hook/installation` → `hook/claude-code` →
  `getting-started/daemon-setup` → `reference/cli-commands`.
- **Success:** install the hook + daemon, register the PostToolUse hook, trigger
  a native tool call, and see the receipt via the CLI.

## priya-dashboard
- **Who:** Priya, a security reviewer handed a `receipts.db` from a colleague.
- **Platform:** macOS.
- **Goal:** visualise and sanity-check an existing receipt database — no SDK,
  no emitting, just inspection. She also expects to read encrypted parameter
  previews and review multi-agent attribution when the data supports it.
- **Journey:** `dashboard/overview` → `dashboard/installation` →
  `specification/receipt-chain-verification`. The site pages link out to the
  dashboard README for the full feature set, the forensic-decryption details,
  and the HTTP API — follow those links and hold the README to the same bar.
- **Success:** install and run the dashboard against a database; browse the
  chain; verify both modes (structural, and with a public key for signatures);
  exercise **forensic decryption** — confirm the documented auto-load from the
  default key path (`~/.local/share/agent-receipts/forensic.key`) on a loopback
  bind, and that encrypted parameter previews decrypt on the fly; and open the
  **session attribution** view for a multi-agent store. Understand what
  verification the dashboard does (and doesn't) do, and the loopback-only
  security model around forensic keys.
- **Note:** forensic decryption needs receipts with encrypted disclosures plus a
  matching forensic key, and attribution needs a multi-agent session. If the
  handed-over database (or any the docs tell her how to obtain) lacks these,
  record it as `environment-limited` for that step rather than a doc defect —
  but a doc that never explains how to get such data *is* a finding.
