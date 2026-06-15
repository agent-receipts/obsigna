#!/usr/bin/env bash
# demo.sh — obsigna + sbx side-by-side audit demo
#
# Shows two non-overlapping audit layers:
#   sbx policy log  → what the infrastructure allowed / blocked
#   obsigna verify  → what the agent actually did (signed receipts, outside the VM)
#
# Prerequisites: obsigna-daemon, obsigna, sbx (authenticated), ollama running locally
# Usage: ./demo.sh [MODEL]
#   MODEL defaults to openai-compatible/devstral-small-2:latest

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$DEMO_DIR/workspace"
SOCKET_PATH="$WORKSPACE/obsigna.sock"
DB_PATH="$WORKSPACE/receipts.db"
KEY_PATH="$WORKSPACE/signing.key"
SANDBOX_NAME="obsigna-sbx-demo"
MODEL="${1:-openai-compatible/devstral-small-2:latest}"

BOLD=$'\033[1m'
GREEN=$'\033[0;32m'
BLUE=$'\033[0;34m'
YELLOW=$'\033[1;33m'
RED=$'\033[0;31m'
NC=$'\033[0m'

DAEMON_PID=""

cleanup() {
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
  sbx rm -f "$SANDBOX_NAME" 2>/dev/null || true
  rm -f "$SOCKET_PATH"
}
trap cleanup EXIT

# ── preflight ──────────────────────────────────────────────────────────────────

echo "${BOLD}obsigna + sbx demo${NC}"
echo

missing=0
for cmd in obsigna-daemon obsigna sbx; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "${RED}missing: $cmd${NC}"; missing=1; }
done
if ! sbx ls >/dev/null 2>&1; then
  echo "${RED}sbx not authenticated — run: sbx login${NC}"; missing=1
fi
if ! curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo "${RED}ollama not reachable at localhost:11434${NC}"; missing=1
fi
[ "$missing" -eq 0 ] || { echo "Fix the above and re-run."; exit 1; }

# ── plugin bundle ──────────────────────────────────────────────────────────────

PLUGIN_PATH="$WORKSPACE/.opencode/plugins/agent-receipts.js"
if [ ! -f "$PLUGIN_PATH" ]; then
  echo "${BLUE}==> Building opencode plugin from PR #766...${NC}"
  BUILD_DIR="$(mktemp -d)"
  trap 'rm -rf "$BUILD_DIR"; cleanup' EXIT

  REPO_ROOT="$(cd "$DEMO_DIR/.." && pwd)"
  git -C "$REPO_ROOT" archive pr-766 -- integrations/opencode-plugin/src integrations/opencode-plugin/package.json | tar -x -C "$BUILD_DIR"
  mkdir -p "$BUILD_DIR/sdk/ts"
  # Use the in-tree sdk/ts (already built)
  cp -r "$REPO_ROOT/sdk/ts/dist" "$BUILD_DIR/sdk/ts/dist"
  cp "$REPO_ROOT/sdk/ts/package.json" "$BUILD_DIR/sdk/ts/package.json"

  node -e "
    const fs = require('fs');
    const p = '$BUILD_DIR/integrations/opencode-plugin/package.json';
    const pkg = JSON.parse(fs.readFileSync(p, 'utf8'));
    pkg.dependencies['@agnt-rcpt/sdk-ts'] = 'file:../../sdk/ts';
    fs.writeFileSync(p, JSON.stringify(pkg, null, 2));
  "

  cd "$BUILD_DIR/integrations/opencode-plugin"
  pnpm install --no-frozen-lockfile --silent

  mkdir -p "$(dirname "$PLUGIN_PATH")"
  npx esbuild src/plugin.ts \
    --bundle \
    --format=esm \
    --platform=node \
    --external:@opencode-ai/plugin \
    --outfile="$PLUGIN_PATH" \
    --log-level=warning

  cd "$DEMO_DIR"
  echo "   plugin → $PLUGIN_PATH ($(wc -c < "$PLUGIN_PATH" | tr -d ' ') bytes)"
else
  echo "${BLUE}==> Plugin bundle already built, skipping.${NC}"
fi

# ── signing key ────────────────────────────────────────────────────────────────

if [ ! -f "$KEY_PATH" ]; then
  echo "${BLUE}==> Generating signing key...${NC}"
  obsigna keys generate --key "$KEY_PATH"
fi

# ── daemon (host side, outside the VM) ────────────────────────────────────────

rm -f "$SOCKET_PATH" "$DB_PATH"
echo "${BLUE}==> Starting obsigna-daemon on host (outside the VM)...${NC}"
obsigna-daemon \
  --socket "$SOCKET_PATH" \
  --db "$DB_PATH" \
  --key "$KEY_PATH" \
  --issuer-id "did:user:${USER}@local" \
  --unsafe-socket-path \
  2>/dev/null &
DAEMON_PID=$!

# Wait for socket to become ready
for _ in $(seq 1 40); do
  [ -S "$SOCKET_PATH" ] && break
  sleep 0.25
done
[ -S "$SOCKET_PATH" ] || { echo "${RED}daemon failed to create socket${NC}"; exit 1; }
echo "   daemon PID=$DAEMON_PID  socket=$(basename "$SOCKET_PATH")"

# ── sbx network policy ─────────────────────────────────────────────────────────

echo "${BLUE}==> Configuring sbx network policy (allow ollama on host)...${NC}"
sbx policy allow network host.docker.internal:11434 2>/dev/null || true

# ── sandbox ────────────────────────────────────────────────────────────────────

sbx rm -f "$SANDBOX_NAME" 2>/dev/null || true
echo "${BLUE}==> Creating sbx sandbox...${NC}"
sbx create opencode "$WORKSPACE" \
  --name "$SANDBOX_NAME" \
  --quiet

# ── agent task ─────────────────────────────────────────────────────────────────

TASK="Complete these steps in order without asking questions:
1. Write a Python script to work/fibonacci.py that prints the first 10 Fibonacci numbers.
2. Run it with bash and show the output.
3. Run this exact command and show the output: curl -s --max-time 3 https://worldtimeapi.org/api/timezone/UTC || echo '[blocked by network policy]'"

echo "${BLUE}==> Running opencode agent inside sbx (model: $MODEL)...${NC}"
echo "${YELLOW}    Task: write fibonacci.py → run it → attempt outbound network call${NC}"
echo

sbx exec "$SANDBOX_NAME" -- \
  sh -c "AGENTRECEIPTS_SOCKET='$SOCKET_PATH' opencode run --model '$MODEL' '$TASK'"

# ── output ─────────────────────────────────────────────────────────────────────

echo
echo "${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo "${YELLOW}${BOLD}  sbx policy log — what the infrastructure allowed / blocked${NC}"
echo "${BOLD}══════════════════════════════════════════════════════════════${NC}"
sbx policy log "$SANDBOX_NAME"

echo
echo "${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo "${GREEN}${BOLD}  obsigna receipt list — what the agent actually did${NC}"
echo "${BOLD}══════════════════════════════════════════════════════════════${NC}"
obsigna receipt list --db "$DB_PATH"

echo
echo "${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo "${GREEN}${BOLD}  obsigna verify — chain integrity${NC}"
echo "${BOLD}══════════════════════════════════════════════════════════════${NC}"
obsigna verify --db "$DB_PATH"

echo
echo "${GREEN}${BOLD}Done.${NC} Receipts stored at: $DB_PATH"
echo "To inspect a receipt: obsigna receipt show --db $DB_PATH --seq 1"
