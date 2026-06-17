#!/usr/bin/env bash
#
# One command: verify the persisted chain against its checkpoint anchor.
# Green = the store HEAD matches the latest signed, out-of-band checkpoint.
# Re-runnable; reads the state start.sh left under $DEMO_HOME.
#
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

[ -f "$DB" ] && [ -f "$ANCHOR_LOG" ] || {
	bad "no demo state at $DEMO_HOME — run ./start.sh first"; exit 1
}

step "verify --against-anchor"
"$BIN_DIR/obsigna" receipt verify --db "$DB" --public-key "$PUB" \
	--chain-id "$CHAIN_ID" --against-anchor "$ANCHOR_LOG"
code=$?
echo
if [ "$code" -eq 0 ]; then ok "GREEN (exit 0)"; else bad "exit $code"; fi
exit "$code"
