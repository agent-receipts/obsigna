#!/usr/bin/env bash
#
# One command: build everything from THIS checkout, run a real OpenCode session
# through the documented opencode -> daemon -> checkpoint path, prove the agent
# UID cannot touch the anchor, then verify the chain against its anchor (green).
#
# This runs the SHIPPED code end to end: the obsigna daemon, the
# @obsigna/opencode-plugin, the real `opencode` binary, Ed25519 signing, the git
# checkpoint anchor, and `obsigna verify`. The ONLY stub is the LLM (a local,
# offline mock model) so the run is deterministic and free — see mock-model.mjs
# and the README. The model is outside the integrity boundary being proven.
#
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_root
require_tool go    "install Go 1.26+"
require_tool node  "install Node 20+"
require_tool npm   "ships with Node"
require_tool pnpm  "npm install -g pnpm  (or: corepack enable)"
require_tool git   "install git"

step "Ensure OpenCode is installed"
if command -v opencode >/dev/null 2>&1; then
	ok "opencode $(opencode --version 2>/dev/null | head -1)"
else
	info "installing opencode-ai globally…"
	npm install -g opencode-ai >/dev/null 2>&1
	ok "opencode $(opencode --version 2>/dev/null | head -1)"
fi

step "Create the two OS principals (the boundary under test)"
ensure_principals
ok "daemon principal: $DAEMON_USER (uid $(id -u "$DAEMON_USER"))  — owns the anchor"
ok "agent  principal: $AGENT_USER (uid $(id -u "$AGENT_USER"))  — only emits"

step "Build daemon + CLI from this checkout"
mkdir -p "$BIN_DIR"
( cd "$REPO_ROOT/daemon" && go build -o "$BIN_DIR/obsigna-daemon" ./cmd/obsigna-daemon && go build -o "$BIN_DIR/obsigna" ./cmd/obsigna )
chmod 0755 "$BIN_DIR"/*
ok "built obsigna-daemon + obsigna"

step "Build + pack @obsigna/opencode-plugin from this checkout"
( cd "$REPO_ROOT/integrations/opencode-plugin" && pnpm install --silent && pnpm build >/dev/null )
TGZ_NAME="$(cd "$REPO_ROOT/integrations/opencode-plugin" && npm pack --pack-destination "$DEMO_HOME" 2>/dev/null | tail -1)"
TGZ="$DEMO_HOME/$TGZ_NAME"
[ -f "$TGZ" ] || { bad "plugin pack failed"; exit 1; }
ok "packed in-tree plugin: $TGZ_NAME"

step "Lay out daemon state (anchor, key, store)"
rm -rf "$DAEMON_STATE" "$WORKSPACE" "$LOG_DIR"
mkdir -p "$DAEMON_STATE" "$LOG_DIR"
"$BIN_DIR/obsigna-daemon" --init --key "$KEY" >/dev/null
chown -R "$DAEMON_USER:$GROUP" "$DAEMON_STATE"
chmod 0750 "$DAEMON_STATE"
ok "signing key generated; state owned by $DAEMON_USER"

step "Lay out the shared socket dir (setgid → socket inherits group $GROUP)"
rm -rf "$SOCK_DIR"; mkdir -p "$SOCK_DIR"
chown "$DAEMON_USER:$GROUP" "$SOCK_DIR"
chmod 2750 "$SOCK_DIR"
ok "$SOCK_DIR  (2750 $DAEMON_USER:$GROUP)"

step "Prepare the agent workspace, then hand it to $AGENT_USER"
mkdir -p "$WORKSPACE"
cp -r "$DEMO_DIR/workspace/." "$WORKSPACE/"
( cd "$WORKSPACE" && npm install "$TGZ" >"$LOG_DIR/npm-install.log" 2>&1 ) \
	|| { bad "workspace npm install failed"; tail "$LOG_DIR/npm-install.log"; exit 1; }
chown -R "$AGENT_USER:$AGENT_USER" "$WORKSPACE"
ok "in-tree plugin installed into the workspace the documented way (.opencode/plugin/)"

# --- bring up the offline model + the daemon ------------------------------
step "Start the offline mock model + the daemon"
MOCK_PORT="$MOCK_PORT" MOCK_TOOLCALLS="$TOOLCALLS" node "$DEMO_DIR/mock-model.mjs" \
	>"$LOG_DIR/mock-model.log" 2>&1 &
MOCK_PID=$!
as_daemon AGENTRECEIPTS_CHAIN_ID="$CHAIN_ID" \
	"$BIN_DIR/obsigna-daemon" --key "$KEY" --db "$DB" --socket "$SOCK" \
		--chain-id "$CHAIN_ID" --checkpoint-anchor "git:$ANCHOR_DIR" --checkpoint-cadence 1 \
	>"$LOG_DIR/daemon.log" 2>&1 &
DAEMON_PID=$!

cleanup() { kill "$MOCK_PID" 2>/dev/null || true; sudo kill "$DAEMON_PID" 2>/dev/null || true; }
trap cleanup EXIT

for _ in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { bad "daemon socket never appeared"; cat "$LOG_DIR/daemon.log"; exit 1; }
ok "daemon up; socket $(stat -c '%A %U:%G' "$SOCK") $SOCK"
info "anchor dir $(stat -c '%A %U:%G' "$ANCHOR_DIR") $ANCHOR_DIR"

# --- the permission boundary ---------------------------------------------
step "Prove it: the AGENT UID cannot write the checkpoint dir"
if as_agent bash -c "echo tamper >> '$ANCHOR_LOG'" 2>"$LOG_DIR/boundary.err"; then
	bad "agent WROTE the anchor — boundary FAILED (this must never happen)"
	exit 1
fi
ok "agent write to anchor rejected:"
info "$(cat "$LOG_DIR/boundary.err")"

# --- the real session -----------------------------------------------------
step "Run a REAL OpenCode session as $AGENT_USER ($TOOLCALLS native tool calls)"
as_agent AGENTRECEIPTS_SOCKET="$SOCK" AGENT_RECEIPTS_CHANNEL=opencode \
	bash -c "cd '$WORKSPACE' && timeout 180 opencode run -m mock/mock-model 'Run the demo commands.'" \
	>"$LOG_DIR/opencode.log" 2>&1 || { bad "opencode session failed (exit $?)"; tail -20 "$LOG_DIR/opencode.log"; exit 1; }
ok "session complete (full transcript: $LOG_DIR/opencode.log)"

step "Stop the daemon (graceful shutdown flushes a final checkpoint)"
sudo kill -TERM "$DAEMON_PID" 2>/dev/null || true
for _ in $(seq 1 50); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.1; done
kill "$MOCK_PID" 2>/dev/null || true
trap - EXIT
ok "daemon stopped; state persisted under $DEMO_HOME"

# --- show the result ------------------------------------------------------
step "Receipts written by the real session"
"$BIN_DIR/obsigna" receipt list --db "$DB" --limit 50 2>/dev/null || true

step "Checkpoint anchor (git commit chain = the tamper-evident structure)"
# Read the repo as its owner — git refuses a repo owned by another UID
# (safe.directory), which is itself a sign of the ownership boundary.
as_daemon git -C "$ANCHOR_DIR" --no-pager log --oneline 2>/dev/null | sed 's/^/  /' || true

step "verify --against-anchor  (expect GREEN)"
if "$BIN_DIR/obsigna" receipt verify --db "$DB" --public-key "$PUB" \
		--chain-id "$CHAIN_ID" --against-anchor "$ANCHOR_LOG"; then
	ok "chain verifies and matches its anchor"
else
	bad "verify failed unexpectedly"; exit 1
fi

cat <<EOF

$(bold "Done.")  Next:
  sudo -E ./verify.sh    # re-run the green verification any time
  sudo -E ./attack.sh    # drop the store tail and watch verify go RED
EOF
