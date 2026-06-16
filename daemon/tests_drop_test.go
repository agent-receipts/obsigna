//go:build integration && (linux || darwin)

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/agent-receipts/ar/sdk/go/emitter"
	"github.com/agent-receipts/ar/sdk/go/receipt"
)

// actionTypeEventsDropped mirrors the daemon-internal constant of the same name
// (pipeline.actionTypeEventsDropped). It is unexported there, so the value is
// duplicated here for the integration assertion; if the pipeline ever changes
// the action type this test fails loudly, which is the intended coupling.
const actionTypeEventsDropped = "agent_receipts.events_dropped"

// TestEmitterDropsSurfaceAsEventsDroppedReceipt pins the drop-accounting seam
// end to end through a live daemon. An emitter that loses frames while the
// daemon is unreachable accumulates a drop count; the next successful emit
// carries that count to the daemon, which records a synthetic events_dropped
// receipt immediately ahead of the live receipt without breaking the chain.
//
// The two halves of this path are unit-tested in isolation — the emitter's drop
// counter in sdk/go/emitter (TestEmit_DropCounterIncrementsOnFailure) and the
// daemon's events_dropped synthesis in daemon/internal/pipeline
// (TestProcess_DropCountInsertsEventsDroppedReceipt). This test guards the
// integration between them: a real emitter over a real AF_UNIX socket into a
// real daemon and SQLite store. It is the regression that would have caught the
// v0.8.0-alpha.2 soak-test bug, where dropped frames left no signal.
func TestEmitterDropsSurfaceAsEventsDroppedReceipt(t *testing.T) {
	const drops = 3

	// Build a daemon config but do NOT start it: the socket path is absent, so
	// the emitter's first sends fail their dial and accumulate the drop count.
	cfg, pubPEM := newDaemonConfig(t, 0)

	// Surface-error mode (not best-effort): the down-phase sends must fail
	// visibly so we can assert each one dropped, and the recovery send must
	// fail loudly rather than silently swallow a missed delivery — best-effort
	// would turn a dropped recovery frame into a nil return and bump the drop
	// counter instead, which would later surface only as a confusing
	// WaitForReceiptCount timeout.
	em, err := emitter.NewDaemon(
		emitter.WithSocketPath(cfg.SocketPath),
		emitter.WithSessionID("drop-session"),
	)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	defer em.Close()

	ev := emitter.Event{
		Channel:  "sdk",
		Tool:     emitter.Tool{Name: "test-tool"},
		Decision: "allowed",
	}

	// Daemon is down: every send must fail its dial and bump the drop counter.
	// Asserting the error confirms the frame really dropped (and so feeds the
	// accumulated count), rather than silently succeeding against a stale socket.
	for i := 0; i < drops; i++ {
		if err := em.Emit(context.Background(), ev); err == nil {
			t.Fatalf("emit %d to down daemon: got nil, want a transport error (frame should have dropped)", i)
		}
	}

	// Bring the daemon up at the same socket path.
	fix := StartDaemonFromConfig(t, cfg, pubPEM)

	// First send after the daemon is up re-dials and carries the accumulated
	// drop count. StartDaemonFromConfig already confirmed the socket is
	// accepting, so this dial should succeed first try; a failure here returns a
	// real error (not best-effort) so it is reported directly instead of as a
	// downstream receipt-count timeout.
	if err := em.Emit(context.Background(), ev); err != nil {
		t.Fatalf("recovery emit: %v", err)
	}

	// A frame with drop_count > 0 makes the daemon allocate a PAIR: a synthetic
	// events_dropped receipt (seq 1) followed by the live receipt (seq 2).
	receipts := fix.WaitForReceiptCount(t, 2, 5*time.Second)
	if len(receipts) != 2 {
		t.Fatalf("expected 2 receipts (events_dropped + live), got %d\ntrace:\n%s",
			len(receipts), fix.Trace())
	}

	// GetChain returns rows in sequence order (ORDER BY sequence ASC), so the
	// synthetic (seq 1) precedes the live receipt (seq 2); assert the sequence
	// values explicitly rather than relying on positional ordering.
	synthetic, live := receipts[0], receipts[1]
	if synthetic.CredentialSubject.Chain.Sequence != 1 {
		t.Fatalf("synthetic seq = %d, want 1", synthetic.CredentialSubject.Chain.Sequence)
	}
	if live.CredentialSubject.Chain.Sequence != 2 {
		t.Fatalf("live seq = %d, want 2", live.CredentialSubject.Chain.Sequence)
	}

	// The synthetic receipt records the gap.
	if got := synthetic.CredentialSubject.Action.Type; got != actionTypeEventsDropped {
		t.Errorf("synthetic action.type = %q, want %q", got, actionTypeEventsDropped)
	}
	if got := synthetic.CredentialSubject.Action.ToolName; got != "events_dropped" {
		t.Errorf("synthetic tool_name = %q, want events_dropped", got)
	}
	md := synthetic.CredentialSubject.Action.EmitterMetadata
	if md == nil {
		t.Fatal("synthetic events_dropped receipt missing emitter_metadata")
	}
	if md.DropCount != drops {
		t.Errorf("synthetic emitter_metadata.drop_count = %d, want %d", md.DropCount, drops)
	}

	// The live receipt is the recovery frame the caller actually emitted.
	if got := live.CredentialSubject.Action.ToolName; got != "test-tool" {
		t.Errorf("live tool_name = %q, want test-tool", got)
	}

	// Chain integrity across the pair: synthetic is first (no prev), live links
	// to the synthetic's hash, and both verify.
	if synthetic.CredentialSubject.Chain.PreviousReceiptHash != nil {
		t.Errorf("synthetic prev_hash = %v, want nil (first in chain)",
			synthetic.CredentialSubject.Chain.PreviousReceiptHash)
	}
	wantPrev, err := receipt.HashReceipt(synthetic)
	if err != nil {
		t.Fatalf("hash synthetic: %v", err)
	}
	gotPrev := live.CredentialSubject.Chain.PreviousReceiptHash
	if gotPrev == nil || *gotPrev != wantPrev {
		t.Errorf("live prev_hash = %v, want %s (hash of synthetic)", gotPrev, wantPrev)
	}
	for i, r := range receipts {
		ok, err := receipt.Verify(r, pubPEM)
		if err != nil || !ok {
			t.Errorf("receipt %d verify: ok=%v err=%v", i, ok, err)
		}
	}
}
