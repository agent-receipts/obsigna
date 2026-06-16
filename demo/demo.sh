#!/usr/bin/env bash
# demo.sh — obsigna + sbx side-by-side audit demo
#
# Shows two non-overlapping audit layers:
#   sbx policy log  → what the infrastructure allowed / blocked
#   obsigna verify  → what the agent actually did (signed receipts, outside the VM)
#
# Architecture:
#   obsigna-daemon runs on the HOST (signing key never enters the VM).
#   On macOS, host Unix sockets can't be connected to from inside a Linux
#   container, so we use a socat TCP tunnel:
#
#     plugin (container) → /tmp/obsigna.sock (Linux)
#       → socat (container) → host.docker.internal:3923 (TCP)
#         → socat (host) → /tmp/obsigna-sbx/obsigna.sock (macOS)
#           → obsigna-daemon (host)
#
# Prerequisites: obsigna-daemon, obsigna, sbx (authenticated), socat, ollama
# Usage: ./demo.sh [MODEL]
#   MODEL defaults to openai-compatible/devstral-demo:latest
#   (devstral-demo is a devstral-small-2 variant with 32K context window)

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE=/tmp/obsigna-sbx
SOCKET_PATH="$WORKSPACE/obsigna.sock"
TCP_PORT=3923
CONTAINER_SOCKET=/tmp/obsigna.sock
DB_PATH="$WORKSPACE/receipts.db"
KEY_PATH="$WORKSPACE/signing.key"
SANDBOX_NAME="obsigna-sbx-demo"
MODEL="${1:-openai-compatible/devstral-demo:latest}"

BOLD=$'\033[1m'
GREEN=$'\033[0;32m'
BLUE=$'\033[0;34m'
YELLOW=$'\033[1;33m'
RED=$'\033[0;31m'
NC=$'\033[0m'

DAEMON_PID=""
SOCAT_PID=""

cleanup() {
  [ -n "$SOCAT_PID" ] && kill "$SOCAT_PID" 2>/dev/null || true
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
  sbx rm -f "$SANDBOX_NAME" 2>/dev/null || true
  rm -f "$SOCKET_PATH"
}
trap cleanup EXIT

# ── preflight ──────────────────────────────────────────────────────────────────

echo "${BOLD}obsigna + sbx demo${NC}"
echo

missing=0
for cmd in obsigna-daemon obsigna sbx socat; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "${RED}missing: $cmd${NC}"; missing=1; }
done
if ! sbx ls >/dev/null 2>&1; then
  echo "${RED}sbx not authenticated — run: sbx login${NC}"; missing=1
fi
if ! curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo "${RED}ollama not reachable at localhost:11434${NC}"; missing=1
fi
# Check that devstral-demo exists in ollama (one-time setup: ollama create devstral-demo)
if ! curl -sf http://localhost:11434/api/show -d '{"name":"devstral-demo:latest"}' >/dev/null 2>&1; then
  echo "${YELLOW}devstral-demo not found in ollama — creating it (32K context window)...${NC}"
  cat > /tmp/devstral-demo.modelfile << 'EOF'
FROM devstral-small-2:latest
PARAMETER num_ctx 32768
EOF
  ollama create devstral-demo -f /tmp/devstral-demo.modelfile || { echo "${RED}failed to create devstral-demo${NC}"; missing=1; }
fi
[ "$missing" -eq 0 ] || { echo "Fix the above and re-run."; exit 1; }

# ── workspace setup ────────────────────────────────────────────────────────────

mkdir -p "$WORKSPACE/.opencode/plugins" "$WORKSPACE/work"
cp "$DEMO_DIR/workspace/.opencode/opencode.json" "$WORKSPACE/.opencode/opencode.json"

# ── plugin bundle ──────────────────────────────────────────────────────────────

SRC_PLUGIN="$DEMO_DIR/workspace/.opencode/plugins/agent-receipts.js"
PLUGIN_PATH="$WORKSPACE/.opencode/plugins/agent-receipts.js"

if [ ! -f "$SRC_PLUGIN" ]; then
  echo "${BLUE}==> Building opencode plugin from PR #766...${NC}"
  BUILD_DIR="$(mktemp -d)"
  trap 'rm -rf "$BUILD_DIR"; cleanup' EXIT

  REPO_ROOT="$(cd "$DEMO_DIR/.." && pwd)"
  git -C "$REPO_ROOT" archive pr-766 -- integrations/opencode-plugin/src integrations/opencode-plugin/package.json | tar -x -C "$BUILD_DIR"
  # Build the TS SDK if dist/ is missing (e.g. in a fresh worktree)
  if [ ! -d "$REPO_ROOT/sdk/ts/dist" ]; then
    echo "   building sdk/ts..."
    (cd "$REPO_ROOT/sdk/ts" && pnpm install --frozen-lockfile --silent && pnpm build)
  fi
  mkdir -p "$BUILD_DIR/sdk/ts"
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

  # The SDK's index.js re-exports store/store.js which has a static
  # `import { DatabaseSync } from "node:sqlite"`. Strip those exports so
  # esbuild doesn't bundle the store (the plugin only uses DaemonEmitter).
  SDK_INDEX="$BUILD_DIR/integrations/opencode-plugin/node_modules/@agnt-rcpt/sdk-ts/dist/index.js"
  cp -r "$REPO_ROOT/sdk/ts/dist" "$BUILD_DIR/integrations/opencode-plugin/node_modules/@agnt-rcpt/sdk-ts/dist"
  sed -i.bak \
    -e 's|export { openStore, openStoreReadOnly, ReceiptStore, } from "./store/store.js";||' \
    -e 's|export { verifyStoredChain } from "./store/verify.js";||' \
    "$SDK_INDEX"

  # undici (an SDK dep) uses webidl internals that fail in the opencode runtime;
  # replace it with a stub since HttpEmitter is never used by this plugin.
  npx esbuild src/plugin.ts \
    --bundle \
    --format=esm \
    --platform=node \
    --external:@opencode-ai/plugin \
    --external:node:sqlite \
    --alias:undici="$DEMO_DIR/undici-stub.mjs" \
    --outfile="$SRC_PLUGIN" \
    --log-level=warning
  cd "$DEMO_DIR"
  echo "   built → $SRC_PLUGIN"
fi
cp "$SRC_PLUGIN" "$PLUGIN_PATH"

# ── signing key ────────────────────────────────────────────────────────────────

if [ ! -f "$KEY_PATH" ]; then
  echo "${BLUE}==> Generating signing key...${NC}"
  obsigna keys generate --key "$KEY_PATH"
fi

# ── daemon (host side, outside the VM) ────────────────────────────────────────

CHAIN_ID="$(date -u +%Y-%m-%d)"
rm -f "$SOCKET_PATH" "$DB_PATH"
echo "${BLUE}==> Starting obsigna-daemon on host (outside the VM)...${NC}"
obsigna-daemon \
  --socket "$SOCKET_PATH" \
  --db "$DB_PATH" \
  --key "$KEY_PATH" \
  --issuer-id "did:user:${USER}@local" \
  --chain-id "$CHAIN_ID" \
  --unsafe-socket-path \
  2>/dev/null &
DAEMON_PID=$!

for _ in $(seq 1 40); do
  [ -S "$SOCKET_PATH" ] && break
  sleep 0.25
done
[ -S "$SOCKET_PATH" ] || { echo "${RED}daemon failed to create socket${NC}"; exit 1; }
echo "   daemon PID=$DAEMON_PID  socket=$(basename "$SOCKET_PATH")"

# ── socat TCP bridge (host side) ───────────────────────────────────────────────
# On macOS, host Unix sockets can't be connected to from inside a Linux
# container via bind-mount. Bridge: TCP port → Unix socket.

echo "${BLUE}==> Starting socat TCP bridge (host.docker.internal:$TCP_PORT → daemon)...${NC}"
socat TCP4-LISTEN:"$TCP_PORT",fork,reuseaddr UNIX-CONNECT:"$SOCKET_PATH" &
SOCAT_PID=$!
sleep 0.3
echo "   socat PID=$SOCAT_PID  port=$TCP_PORT"

# ── sbx network policy ─────────────────────────────────────────────────────────

echo "${BLUE}==> Configuring sbx network policy...${NC}"
# host.docker.internal resolves to fe80::1 inside sbx, which sbx classifies as localhost
sbx policy allow network localhost:11434 2>/dev/null || true   # ollama
sbx policy allow network localhost:"$TCP_PORT" 2>/dev/null || true  # obsigna tunnel

# ── sandbox ────────────────────────────────────────────────────────────────────

sbx rm -f "$SANDBOX_NAME" 2>/dev/null || true
echo "${BLUE}==> Creating sbx sandbox...${NC}"
sbx create opencode "$WORKSPACE" \
  --name "$SANDBOX_NAME" \
  --quiet

# ── agent task ─────────────────────────────────────────────────────────────────

TASK="Complete these steps in order without asking questions:
1. Write a Python script to work/fibonacci.py that prints the first 10 Fibonacci numbers (no user input, hardcoded to 10).
2. Run it with python3 and show the output.
3. Run this exact command and show the output: curl -s --max-time 3 https://worldtimeapi.org/api/timezone/UTC || echo '[blocked by network policy]'"

echo "${BLUE}==> Running opencode agent inside sbx (model: $MODEL)...${NC}"
echo "${YELLOW}    Task: write fibonacci.py → run it → attempt outbound network call${NC}"
echo

# The container-side socat bridges the plugin's Unix socket to the host via TCP.
# Container: /tmp/obsigna.sock → host.docker.internal:TCP_PORT → daemon socket
CONTAINER_SOCAT_CMD="rm -f $CONTAINER_SOCKET; socat UNIX-LISTEN:$CONTAINER_SOCKET,fork,reuseaddr TCP4:host.docker.internal:$TCP_PORT &"
WAIT_FOR_SOCK="for i in \$(seq 1 20); do [ -S $CONTAINER_SOCKET ] && break; sleep 0.25; done"

sbx exec "$SANDBOX_NAME" -- \
  sh -c "$CONTAINER_SOCAT_CMD $WAIT_FOR_SOCK && AGENTRECEIPTS_SOCKET='$CONTAINER_SOCKET' OPENCODE_CONFIG_DIR='$WORKSPACE/.opencode' opencode run --model '$MODEL' '$TASK'"

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
obsigna verify --db "$DB_PATH" --public-key "${KEY_PATH}.pub" --chain-id "$CHAIN_ID"

echo
echo "${GREEN}${BOLD}Done.${NC} Receipts stored at: $DB_PATH"
echo "To inspect: obsigna receipt show 1 --db $DB_PATH --chain-id $CHAIN_ID"
