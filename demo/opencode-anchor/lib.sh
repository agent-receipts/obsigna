# Shared configuration and helpers for the opencode -> daemon -> checkpoint demo.
# Sourced by start.sh / verify.sh / attack.sh / clean.sh. Not executable on its own.

set -euo pipefail

# --- repo + demo locations ------------------------------------------------
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DEMO_DIR/../.." && pwd)"

# All mutable demo state lives outside the repo so a run never dirties the
# working tree with root/agent-owned files. Override with DEMO_HOME=...
DEMO_HOME="${DEMO_HOME:-/tmp/obsigna-anchor-demo}"
BIN_DIR="$DEMO_HOME/bin"
DAEMON_STATE="$DEMO_HOME/daemon"        # owned by the daemon principal (0750)
ANCHOR_DIR="$DAEMON_STATE/anchor"       # the git checkpoint anchor (daemon creates it 0700)
ANCHOR_LOG="$ANCHOR_DIR/anchor.ndjson"  # the tracked NDJSON log verify reads
KEY="$DAEMON_STATE/signing.key"
PUB="$KEY.pub"
DB="$DAEMON_STATE/receipts.db"
WORKSPACE="$DEMO_HOME/workspace"        # owned by the agent principal
LOG_DIR="$DEMO_HOME/logs"

# The two OS principals — this is the whole point of the demo. The daemon owns
# the witness (anchor); the agent only emits. They share a group so the agent
# can reach the daemon socket, yet the anchor dir is 0700 (owner-only).
GROUP="${DEMO_GROUP:-obsigna}"
DAEMON_USER="${DEMO_DAEMON_USER:-obsigna-daemon}"
AGENT_USER="${DEMO_AGENT_USER:-obsigna-agent}"

# Socket lives in a setgid dir so the socket file inherits group $GROUP and the
# agent (a group member) can connect; a system path under /run, not /tmp.
SOCK_DIR="${DEMO_SOCK_DIR:-/run/obsigna-demo}"
SOCK="$SOCK_DIR/events.sock"

CHAIN_ID="${DEMO_CHAIN_ID:-demo-chain}"
TOOLCALLS="${DEMO_TOOLCALLS:-5}"        # native tool calls the mock model drives
MOCK_PORT="${DEMO_MOCK_PORT:-11434}"

ARTIFACTS="$DEMO_DIR/artifacts"

# Point Node at the OS trust store so npm / opencode work behind a
# TLS-intercepting proxy (CI runners, corp networks). No-op on a normal box —
# NODE_EXTRA_CA_CERTS only ADDS to Node's bundled CAs. If already set, respect it.
if [ -z "${NODE_EXTRA_CA_CERTS:-}" ] && [ -f /etc/ssl/certs/ca-certificates.crt ]; then
	export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
fi
# Env vars to forward into the unprivileged agent (sudo strips the environment).
CA_FORWARD=()
[ -n "${NODE_EXTRA_CA_CERTS:-}" ] && CA_FORWARD+=("NODE_EXTRA_CA_CERTS=$NODE_EXTRA_CA_CERTS")
[ -n "${SSL_CERT_FILE:-}" ] && CA_FORWARD+=("SSL_CERT_FILE=$SSL_CERT_FILE")

# --- pretty output --------------------------------------------------------
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
bad()  { printf '\033[1;31m✗ %s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }

require_root() {
	if [ "$(id -u)" -ne 0 ]; then
		bad "This demo needs root: it creates two OS users to prove a UID boundary."
		info "Re-run with:  sudo -E ./$(basename "$0")    (-E keeps your proxy CA env, if any)"
		exit 1
	fi
}

require_tool() {
	command -v "$1" >/dev/null 2>&1 || { bad "missing required tool: $1"; info "$2"; exit 1; }
}

ensure_principals() {
	getent group "$GROUP" >/dev/null || groupadd "$GROUP"
	id "$DAEMON_USER" >/dev/null 2>&1 || useradd -m -G "$GROUP" -s /bin/bash "$DAEMON_USER"
	id "$AGENT_USER"  >/dev/null 2>&1 || useradd -m -G "$GROUP" -s /bin/bash "$AGENT_USER"
	# Make sure both are in the shared group even if they pre-existed.
	usermod -aG "$GROUP" "$DAEMON_USER"; usermod -aG "$GROUP" "$AGENT_USER"
}

# Run a command as the daemon / agent principal with a clean, explicit env.
# The ${arr[@]+"${arr[@]}"} form expands to nothing when CA_FORWARD is empty,
# safe under `set -u` on every bash (vs "${arr[@]}" which trips older bashes).
as_daemon() { sudo -u "$DAEMON_USER" -H env "PATH=$PATH" "$@"; }
as_agent()  { sudo -u "$AGENT_USER"  -H env "PATH=$PATH" ${CA_FORWARD[@]+"${CA_FORWARD[@]}"} "$@"; }
