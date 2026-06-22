//go:build integration && (linux || darwin)

package daemon

import (
	"testing"
	"time"

	"obsigna.dev/sdk/go/receipt"
)

// TestSDKEmitterSingleFrame verifies the daemon processes a single frame
// from each Phase 1 SDK emitter (Go, TypeScript, Python) and produces a
// verifiable receipt at sequence 1. The cases are run as subtests of one
// parent so each emitter still gets a fresh daemon (no cross-emitter chain
// interference) and reports independently in test output. Phase 1 covers Go,
// TS, and Python SDKs only; mcp-proxy and openclaw emitters are covered in
// Phase 2+ tests.
func TestSDKEmitterSingleFrame(t *testing.T) {
	cases := []struct {
		name      string
		sessionID string
		emit      func(t *testing.T, f *DaemonFixture, sessionID string) error
	}{
		{
			name:      "go",
			sessionID: "go-test-session",
			emit: func(t *testing.T, f *DaemonFixture, sessionID string) error {
				return f.EmitGoFrame(t, sessionID, "sdk", "test-tool", "", "allowed")
			},
		},
		{
			name:      "ts",
			sessionID: "ts-test-session",
			emit: func(t *testing.T, f *DaemonFixture, sessionID string) error {
				return f.EmitTSFrame(t, sessionID, "sdk", "test-tool", "allowed")
			},
		},
		{
			name:      "python",
			sessionID: "py-test-session",
			emit: func(t *testing.T, f *DaemonFixture, sessionID string) error {
				return f.EmitPythonFrame(t, sessionID, "sdk", "test-tool", "allowed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := StartDaemon(t)

			if err := tc.emit(t, f, tc.sessionID); err != nil {
				t.Fatalf("emit failed: %v", err)
			}

			receipts := f.WaitForReceiptCount(t, 1, 5*time.Second)

			if len(receipts) != 1 {
				t.Fatalf("expected 1 receipt, got %d\ntrace:\n%s", len(receipts), f.Trace())
			}

			r := receipts[0]

			if r.CredentialSubject.Chain.Sequence != 1 {
				t.Errorf("sequence = %d, want 1", r.CredentialSubject.Chain.Sequence)
			}

			ok, err := receipt.Verify(r, f.PublicKey)
			if err != nil || !ok {
				t.Errorf("receipt verify failed: ok=%v err=%v", ok, err)
			}
		})
	}
}
