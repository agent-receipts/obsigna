package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/agent-receipts/ar/mcp-proxy/internal/audit"
)

// waitAccepting blocks until the approval server on addr accepts a TCP
// connection, or fails the test after 2s. Confirms the listener is live before
// a test drives shutdown.
func waitAccepting(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not accept connections within 2s: %v", dialErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestServeApprovalsGracefulShutdown drives the real serveApprovals helper: it
// starts the approval server on an ephemeral port, confirms it accepts, cancels
// the context, and asserts the done channel closes (Serve returned via the
// ErrServerClosed clean-exit path) and the listener is closed afterwards.
func TestServeApprovalsGracefulShutdown(t *testing.T) {
	token := generateToken(16)
	approvals := audit.NewApprovalManager()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	srv := serveApprovals(ctx, ln, buildApprovalMux(approvals, token))

	// Confirm the server is actually accepting before shutting it down.
	waitAccepting(t, ln.Addr().String())

	// Cancelling the context drives Shutdown; done closes once Serve returns.
	cancel()
	if err := waitForHTTPShutdown(srv); err != nil {
		t.Fatalf("clean ErrServerClosed shutdown must surface nil, got %v", err)
	}

	// The listener must be closed: a fresh Accept on it fails immediately.
	if _, err := ln.Accept(); err == nil {
		t.Fatal("expected listener to be closed after shutdown")
	}
}

// TestServeApprovalsCleanCancelShutsDown verifies that on the clean stdin-EOF
// path the proxy cancels a dedicated approval-server context (derived from the
// signal ctx) WITHOUT any OS signal. Cancelling that context alone must drive
// graceful shutdown — the done channel closes and the listener is torn down —
// so serve() never falls through while the HTTP goroutine is still accepting
// and racing the deferred emitter Close().
func TestServeApprovalsCleanCancelShutsDown(t *testing.T) {
	token := generateToken(16)
	approvals := audit.NewApprovalManager()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// httpCtx models serve()'s dedicated approval-server context. The parent is
	// a plain Background context (no signal wiring), so the only thing that can
	// trigger shutdown here is httpCancel — exactly the clean-EOF path.
	httpCtx, httpCancel := context.WithCancel(context.Background())
	srv := serveApprovals(httpCtx, ln, buildApprovalMux(approvals, token))
	waitAccepting(t, ln.Addr().String())

	// The clean-path trigger: cancel the dedicated context, then await teardown.
	httpCancel()
	if err := waitForHTTPShutdown(srv); err != nil {
		t.Fatalf("clean-path shutdown must surface nil, got %v", err)
	}

	if _, err := ln.Accept(); err == nil {
		t.Fatal("expected listener to be closed after clean-path shutdown")
	}
}

// TestAwaitSessionEndFailsFastOnServerDeath verifies the fail-fast behaviour
// from #691: when the approval HTTP server dies mid-session — a
// non-ErrServerClosed Serve error while the proxy run loop is still blocked —
// awaitSessionEnd must NOT wait for an independent session end. It must cancel
// the session (via stopSession) so Run unblocks promptly, then surface the
// wrapped Serve error with serverDied set.
//
// We model the live session with a runErrCh that stays empty until the session
// context is cancelled; a real serveApprovals server is then killed by closing
// its listener WITHOUT cancelling the session. If awaitSessionEnd waited for an
// unrelated end the test would hang; instead it returns promptly with the
// propagated error.
func TestAwaitSessionEndFailsFastOnServerDeath(t *testing.T) {
	token := generateToken(16)
	approvals := audit.NewApprovalManager()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// httpCtx is the approval server's own context; sessionCtx models p.Run's
	// context. Neither is cancelled by the test — only awaitSessionEnd's
	// stopSession (the death path) may cancel sessionCtx.
	httpCtx, httpCancel := context.WithCancel(context.Background())
	defer httpCancel()
	sessionCtx, stopSession := context.WithCancel(context.Background())
	defer stopSession()

	srv := serveApprovals(httpCtx, ln, buildApprovalMux(approvals, token))
	waitAccepting(t, ln.Addr().String())

	// The proxy run loop only ends once the session context is cancelled; until
	// then runErrCh is empty, mirroring a live session blocked in p.Run.
	runErrCh := make(chan error, 1)
	go func() {
		<-sessionCtx.Done()
		runErrCh <- sessionCtx.Err()
	}()

	// Kill the approval server out from under the session, without cancelling
	// the session context. awaitSessionEnd must detect this and tear down.
	_ = ln.Close()

	outcomeCh := make(chan shutdownOutcome, 1)
	go func() {
		outcomeCh <- awaitSessionEnd(runErrCh, srv, stopSession, httpCancel)
	}()

	select {
	case outcome := <-outcomeCh:
		if !outcome.serverDied {
			t.Fatalf("expected serverDied=true on a mid-session approval-server failure, got %+v", outcome)
		}
		if outcome.httpErr == nil {
			t.Fatal("expected the wrapped Serve error to be surfaced, got nil")
		}
		if errors.Is(outcome.httpErr, http.ErrServerClosed) {
			t.Fatalf("ErrServerClosed must not be treated as a mid-session death: %v", outcome.httpErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("awaitSessionEnd did not fail fast on approval-server death; it waited for an independent session end")
	}
}

// TestAwaitSessionEndNormalCompletion verifies the non-error path is unchanged:
// when the proxy run loop completes first (signal or stdin-EOF) and the
// approval server stops cleanly, awaitSessionEnd reports no error and does not
// flag serverDied. The run result is threaded back unchanged.
func TestAwaitSessionEndNormalCompletion(t *testing.T) {
	token := generateToken(16)
	approvals := audit.NewApprovalManager()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	httpCtx, httpCancel := context.WithCancel(context.Background())
	defer httpCancel()
	_, stopSession := context.WithCancel(context.Background())
	defer stopSession()

	srv := serveApprovals(httpCtx, ln, buildApprovalMux(approvals, token))
	waitAccepting(t, ln.Addr().String())

	// Run completed normally (clean stdin-EOF: nil error) before any server
	// failure. awaitSessionEnd should drive the approval server's graceful
	// shutdown via httpCancel and surface a nil httpErr.
	runErrCh := make(chan error, 1)
	runErrCh <- nil

	outcome := awaitSessionEnd(runErrCh, srv, stopSession, httpCancel)
	if outcome.serverDied {
		t.Fatalf("normal completion must not flag serverDied: %+v", outcome)
	}
	if outcome.runErr != nil {
		t.Fatalf("expected runErr to be threaded through as nil, got %v", outcome.runErr)
	}
	if outcome.httpErr != nil {
		t.Fatalf("clean graceful shutdown must surface nil httpErr, got %v", outcome.httpErr)
	}

	if _, err := ln.Accept(); err == nil {
		t.Fatal("expected listener to be closed after graceful shutdown")
	}
}

// TestAwaitSessionEndNoApprovalServer verifies the -http-off flow: with a nil
// approval-server handle the run result is threaded straight through and the
// nil server-done channel never fires, so the helper neither blocks nor flags a
// death.
func TestAwaitSessionEndNoApprovalServer(t *testing.T) {
	_, stopSession := context.WithCancel(context.Background())
	defer stopSession()
	_, httpCancel := context.WithCancel(context.Background())
	defer httpCancel()

	sentinel := errors.New("run failure")
	runErrCh := make(chan error, 1)
	runErrCh <- sentinel

	outcome := awaitSessionEnd(runErrCh, nil, stopSession, httpCancel)
	if outcome.serverDied {
		t.Fatalf("nil approval server must never flag serverDied: %+v", outcome)
	}
	if !errors.Is(outcome.runErr, sentinel) {
		t.Fatalf("expected runErr to thread through unchanged, got %v", outcome.runErr)
	}
	if outcome.httpErr != nil {
		t.Fatalf("nil approval server must surface nil httpErr, got %v", outcome.httpErr)
	}
}

// TestServeApprovalsPropagatesServeError verifies that a non-ErrServerClosed
// Serve error is PROPAGATED back to the caller (via the handle's error channel,
// surfaced by waitForHTTPShutdown) rather than crashing the process with
// log.Fatalf, which would skip serve()'s deferred cleanup. We force Serve to
// fail by closing the listener out from under it before any shutdown is
// requested, then assert the error reaches the caller.
func TestServeApprovalsPropagatesServeError(t *testing.T) {
	token := generateToken(16)
	approvals := audit.NewApprovalManager()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Never cancel the context: this isolates the Serve-error path from the
	// graceful ErrServerClosed path. Closing the listener makes srv.Serve return
	// a non-ErrServerClosed accept error, which the goroutine must forward.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := serveApprovals(ctx, ln, buildApprovalMux(approvals, token))
	waitAccepting(t, ln.Addr().String())

	_ = ln.Close()

	serveErr := waitForHTTPShutdown(srv)
	if serveErr == nil {
		t.Fatal("expected serveApprovals to propagate the non-ErrServerClosed Serve error")
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		t.Fatalf("ErrServerClosed must be treated as clean, not propagated: %v", serveErr)
	}
}
