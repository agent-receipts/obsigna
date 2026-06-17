#!/usr/bin/env bash
#
# Tear the demo down: stop any leftover processes and remove all state. Pass
# --users to also delete the two demo OS users (and the shared group).
#
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
require_root

step "Stop leftover demo processes"
pkill -f "$BIN_DIR/obsigna-daemon" 2>/dev/null && ok "stopped daemon" || info "no daemon running"
pkill -f "$DEMO_DIR/mock-model.mjs" 2>/dev/null && ok "stopped mock model" || info "no mock model running"

step "Remove state"
rm -rf "$DEMO_HOME" "$SOCK_DIR"
ok "removed $DEMO_HOME and $SOCK_DIR"

if [ "${1:-}" = "--users" ]; then
	step "Remove demo principals"
	userdel -r "$AGENT_USER"  2>/dev/null && ok "removed $AGENT_USER"  || info "no $AGENT_USER"
	userdel -r "$DAEMON_USER" 2>/dev/null && ok "removed $DAEMON_USER" || info "no $DAEMON_USER"
	groupdel "$GROUP" 2>/dev/null && ok "removed group $GROUP" || info "group $GROUP kept (still in use or absent)"
fi
