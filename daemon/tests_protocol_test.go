//go:build integration && (linux || darwin)

package daemon

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"obsigna.dev/daemon/internal/pipeline"
	"obsigna.dev/daemon/internal/socket"
	"obsigna.dev/sdk/go/receipt"
	"obsigna.dev/sdk/go/store"
)

// assertReceiptCountStays0 polls the store repeatedly for the duration and fails if receipts appear.
// Unlike WaitForReceiptCount(t, 0, timeout) which returns immediately on 0 receipts,
// this actively waits to catch any receipts created during the timeout period.
func assertReceiptCountStays0(t *testing.T, f *DaemonFixture, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s, err := store.OpenReadOnly(f.Config.DBPath)
			if err != nil {
				t.Fatalf("open store: %v\ntrace:\n%s", err, f.Trace())
			}
			got, err := s.GetChain(f.Config.ChainID)
			if closeErr := s.Close(); closeErr != nil {
				t.Logf("close store: %v", closeErr)
			}

			if err != nil {
				t.Fatalf("get chain: %v\ntrace:\n%s", err, f.Trace())
			}
			if len(got) > 0 {
				t.Errorf("expected no receipts but got %d (trace:\n%s)", len(got), f.Trace())
				return
			}

			if time.Now().After(deadline) {
				return
			}
		}
	}
}

// writeRaw dials the socket and writes raw bytes without framing.
// Used to test malformed frame headers and other protocol violations.
func writeRaw(t *testing.T, socketPath string, data []byte) {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial %s: %v", socketPath, err)
	}
	defer conn.Close()
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write raw: %v", err)
	}
}

// emitFrameRaw marshals a pipeline.EmitterFrame, writes it via socket.WriteFrame,
// and synchronizes with the daemon. Mirrors integration_test.go's emitFrame pattern.
func emitFrameRaw(t *testing.T, socketPath string, frame pipeline.EmitterFrame) {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial %s: %v", socketPath, err)
	}
	defer conn.Close()
	body, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := socket.WriteFrame(conn, body); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	// Sync: half-close write and drain to ensure daemon finished processing
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	_, _ = io.Copy(io.Discard, conn)
}

// TestMalformedFrameDoesNotAdvanceChain verifies that each invalid frame variant
// is rejected and does not advance the chain. After each rejection, a valid frame
// confirms the daemon is still live.
func TestMalformedFrameDoesNotAdvanceChain(t *testing.T) {
	cases := []struct {
		name  string
		frame pipeline.EmitterFrame
	}{
		{
			name:  "missing_v",
			frame: pipeline.EmitterFrame{TsEmit: "2026-05-03T00:00:00Z", SessionID: "s", Channel: "sdk", Tool: pipeline.EmitterTool{Name: "t"}, Decision: "allowed"},
		},
		{
			name: "unsupported_v",
			frame: pipeline.EmitterFrame{Version: "2", TsEmit: "2026-05-03T00:00:00Z", SessionID: "s", Channel: "sdk", Tool: pipeline.EmitterTool{Name: "t"}, Decision: "allowed"},
		},
		{
			name:  "missing_session_id",
			frame: pipeline.EmitterFrame{Version: "1", TsEmit: "2026-05-03T00:00:00Z", Channel: "sdk", Tool: pipeline.EmitterTool{Name: "t"}, Decision: "allowed"},
		},
		{
			name:  "missing_ts_emit",
			frame: pipeline.EmitterFrame{Version: "1", SessionID: "s", Channel: "sdk", Tool: pipeline.EmitterTool{Name: "t"}, Decision: "allowed"},
		},
		{
			name:  "bad_ts_emit",
			frame: pipeline.EmitterFrame{Version: "1", TsEmit: "not-a-timestamp", SessionID: "s", Channel: "sdk", Tool: pipeline.EmitterTool{Name: "t"}, Decision: "allowed"},
		},
		{
			name:  "missing_tool_name",
			frame: pipeline.EmitterFrame{Version: "1", TsEmit: "2026-05-03T00:00:00Z", SessionID: "s", Channel: "sdk", Tool: pipeline.EmitterTool{}, Decision: "allowed"},
		},
		{
			name:  "missing_decision",
			frame: pipeline.EmitterFrame{Version: "1", TsEmit: "2026-05-03T00:00:00Z", SessionID: "s", Channel: "sdk", Tool: pipeline.EmitterTool{Name: "t"}},
		},
		{
			name:  "unknown_decision",
			frame: pipeline.EmitterFrame{Version: "1", TsEmit: "2026-05-03T00:00:00Z", SessionID: "s", Channel: "sdk", Tool: pipeline.EmitterTool{Name: "t"}, Decision: "maybe"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fix := StartDaemon(t)

			// Send malformed frame; should not create any receipt
			emitFrameRaw(t, fix.Config.SocketPath, tc.frame)

			// Verify no receipt was created
			assertReceiptCountStays0(t, fix, 500*time.Millisecond)

			// Confirm daemon is still live: send a valid frame and wait for it
			validFrame := pipeline.EmitterFrame{
				Version:   "1",
				TsEmit:    "2026-05-03T00:00:00Z",
				SessionID: "s",
				Channel:   "sdk",
				Tool:      pipeline.EmitterTool{Name: "test-tool"},
				Decision:  "allowed",
			}
			emitFrameRaw(t, fix.Config.SocketPath, validFrame)
			receipts := fix.WaitForReceiptCount(t, 1, 2*time.Second)
			if len(receipts) != 1 {
				t.Errorf("daemon did not recover: expected 1 receipt after valid frame, got %d",
					len(receipts))
			}
			// Verify malformed frame didn't consume a sequence number
			if receipts[0].CredentialSubject.Chain.Sequence != 1 {
				t.Errorf("expected sequence 1, got %d (malformed frame consumed sequence)",
					receipts[0].CredentialSubject.Chain.Sequence)
			}
			if receipts[0].CredentialSubject.Chain.PreviousReceiptHash != nil {
				t.Errorf("expected prev_hash nil, got %v (first receipt in chain)",
					receipts[0].CredentialSubject.Chain.PreviousReceiptHash)
			}
		})
	}
}

// TestOversizedFrameHeader verifies that a frame header claiming more than
// MaxFrameSize bytes is rejected and the daemon stays live.
func TestOversizedFrameHeader(t *testing.T) {
	fix := StartDaemon(t)

	// Write a header claiming MaxFrameSize + 1 bytes (daemon will reject as too large)
	oversizeBytes := socket.MaxFrameSize + 1
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(oversizeBytes))

	writeRaw(t, fix.Config.SocketPath, hdr)

	// No receipt should be created
	assertReceiptCountStays0(t, fix, 500*time.Millisecond)

	// Daemon still alive: send valid frame
	validFrame := pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "test-tool"},
		Decision:  "allowed",
	}
	emitFrameRaw(t, fix.Config.SocketPath, validFrame)
	receipts := fix.WaitForReceiptCount(t, 1, 2*time.Second)
	if len(receipts) != 1 {
		t.Errorf("daemon did not recover from oversized frame: got %d receipts", len(receipts))
	}
	// Verify oversized frame didn't consume a sequence number
	if receipts[0].CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("expected sequence 1, got %d (oversized frame consumed sequence)",
			receipts[0].CredentialSubject.Chain.Sequence)
	}
	if receipts[0].CredentialSubject.Chain.PreviousReceiptHash != nil {
		t.Errorf("expected prev_hash nil, got %v (first receipt in chain)",
			receipts[0].CredentialSubject.Chain.PreviousReceiptHash)
	}
}

// TestZeroLengthFrameHeader verifies that a frame header of all zeros is rejected.
func TestZeroLengthFrameHeader(t *testing.T) {
	fix := StartDaemon(t)

	// Write 4 zero bytes
	writeRaw(t, fix.Config.SocketPath, make([]byte, 4))

	// No receipt created
	assertReceiptCountStays0(t, fix, 500*time.Millisecond)

	// Daemon still alive
	validFrame := pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "test-tool"},
		Decision:  "allowed",
	}
	emitFrameRaw(t, fix.Config.SocketPath, validFrame)
	receipts := fix.WaitForReceiptCount(t, 1, 2*time.Second)
	if len(receipts) != 1 {
		t.Errorf("daemon did not recover: got %d receipts", len(receipts))
	}
}

// TestPartialHeaderDrop verifies that a partial frame header (fewer than 4 bytes)
// causes the connection to close without advancing the chain.
func TestPartialHeaderDrop(t *testing.T) {
	fix := StartDaemon(t)

	// Write only 2 bytes of the 4-byte header, then close
	writeRaw(t, fix.Config.SocketPath, []byte{0x00, 0x00})

	// No receipt created
	assertReceiptCountStays0(t, fix, 500*time.Millisecond)

	// Daemon still alive: new connection with valid frame
	validFrame := pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "test-tool"},
		Decision:  "allowed",
	}
	emitFrameRaw(t, fix.Config.SocketPath, validFrame)
	receipts := fix.WaitForReceiptCount(t, 1, 2*time.Second)
	if len(receipts) != 1 {
		t.Errorf("daemon did not recover: got %d receipts", len(receipts))
	}
}

// TestPartialBodyDrop verifies that a frame header claiming N bytes but providing
// fewer causes the daemon to close the connection without advancing the chain.
func TestPartialBodyDrop(t *testing.T) {
	fix := StartDaemon(t)

	conn, err := net.Dial("unix", fix.Config.SocketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Write header claiming 100 bytes, then only 50 bytes of body
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 100)
	if _, err := conn.Write(hdr); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := conn.Write(make([]byte, 50)); err != nil {
		t.Fatalf("write partial body: %v", err)
	}
	conn.Close()

	// No receipt created
	assertReceiptCountStays0(t, fix, 500*time.Millisecond)

	// Daemon still alive
	validFrame := pipeline.EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      pipeline.EmitterTool{Name: "test-tool"},
		Decision:  "allowed",
	}
	emitFrameRaw(t, fix.Config.SocketPath, validFrame)
	receipts := fix.WaitForReceiptCount(t, 1, 2*time.Second)
	if len(receipts) != 1 {
		t.Errorf("daemon did not recover: got %d receipts", len(receipts))
	}
}

// TestDecisionVariants verifies that all three decision values produce receipts
// with the correct outcome status (denied and allowed+error → Failure, pending → Pending, allowed → Success).
func TestDecisionVariants(t *testing.T) {
	cases := []struct {
		name           string
		decision       string
		errorStr       string
		expectedStatus receipt.OutcomeStatus
	}{
		{
			name:           "denied",
			decision:       "denied",
			errorStr:       "",
			expectedStatus: receipt.StatusFailure,
		},
		{
			name:           "pending",
			decision:       "pending",
			errorStr:       "",
			expectedStatus: receipt.StatusPending,
		},
		{
			name:           "allowed",
			decision:       "allowed",
			errorStr:       "",
			expectedStatus: receipt.StatusSuccess,
		},
		{
			name:           "allowed_with_error",
			decision:       "allowed",
			errorStr:       "some error occurred",
			expectedStatus: receipt.StatusFailure,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fix := StartDaemon(t)

			frame := pipeline.EmitterFrame{
				Version:   "1",
				TsEmit:    "2026-05-03T00:00:00Z",
				SessionID: "s",
				Channel:   "sdk",
				Tool:      pipeline.EmitterTool{Name: "test-tool"},
				Decision:  tc.decision,
				Error:     tc.errorStr,
			}
			emitFrameRaw(t, fix.Config.SocketPath, frame)

			receipts := fix.WaitForReceiptCount(t, 1, 2*time.Second)
			if len(receipts) != 1 {
				t.Fatalf("expected 1 receipt, got %d", len(receipts))
			}

			r := receipts[0]
			ok, err := receipt.Verify(r, fix.PublicKey)
			if !ok || err != nil {
				t.Errorf("verify failed: ok=%v err=%v", ok, err)
			}

			// Check outcome status
			if r.CredentialSubject.Outcome.Status != tc.expectedStatus {
				t.Errorf("expected status %s, got %s",
					tc.expectedStatus, r.CredentialSubject.Outcome.Status)
			}
		})
	}
}
