#!/usr/bin/env bash
#
# The attack: drop the tail of the receipt store, the way a compromised host
# would quietly delete the last few actions. Then show the two verdicts:
#
#   plain  `verify`                -> still VALID  (truncation is invisible)
#   `verify --against-anchor`      -> FAIL (truncation)   <-- the defence
#
# We truncate a COPY of the store so the demo stays re-runnable; the copy is the
# store "as the attacker left it". The anchor is untouched — it lives in a
# different fate-sharing domain (a dir the attacker's UID cannot write), which is
# exactly why it still pins the head the store no longer has.
#
# Captures the red verdict to artifacts/red-verify.txt — the HN screenshot.
#
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

[ -f "$DB" ] && [ -f "$ANCHOR_LOG" ] || {
	bad "no demo state at $DEMO_HOME — run ./start.sh first"; exit 1
}

KEEP="${DEMO_KEEP:-3}"   # receipts to leave behind after truncation
ATTACKED="$DEMO_HOME/receipts.attacked.db"

step "Snapshot the store, then drop every receipt after seq $KEEP"
rm -f "$ATTACKED" "$ATTACKED-wal" "$ATTACKED-shm"
NODE_NO_WARNINGS=1 node --experimental-sqlite "$DEMO_DIR/truncate.mjs" \
	"$DB" "$ATTACKED" "$CHAIN_ID" "$KEEP"
ok "tail truncated"

step "Plain verify of the truncated store (no anchor) — the gap ADR-0008 names"
"$BIN_DIR/obsigna" receipt verify --db "$ATTACKED" --public-key "$PUB" --chain-id "$CHAIN_ID" \
	&& ok "still reports VALID — truncation is invisible to chain verification alone"

step "verify --against-anchor of the truncated store — the defence"
mkdir -p "$ARTIFACTS"
set +e
"$BIN_DIR/obsigna" receipt verify --db "$ATTACKED" --public-key "$PUB" \
	--chain-id "$CHAIN_ID" --against-anchor "$ANCHOR_LOG" | tee "$ARTIFACTS/red-verify.txt"
code="${PIPESTATUS[0]}"
set -e
echo
if [ "$code" -ne 0 ] && grep -qi "truncat" "$ARTIFACTS/red-verify.txt"; then
	bad "RED (exit $code) — the dropped tail was caught"
	ok "artifact saved: $ARTIFACTS/red-verify.txt"
else
	bad "expected a truncation failure but verify exited $code — see above"
	exit 1
fi
