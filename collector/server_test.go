package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"obsigna.dev/sdk/go/receipt"
)

func newTestHandler(t *testing.T) (http.Handler, *InMemoryStore) {
	t.Helper()
	store := NewInMemoryStore()
	h, err := Handler(Config{
		Addr:   ":0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, store)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	return h, store
}

// signedTestReceipt produces a receipt whose JSON shape passes the
// collector's structural validator. The proof value is a placeholder — the
// collector does not verify signatures (per ADR-0020), so a real signature
// is not required for these tests.
func signedTestReceipt(id string) receipt.AgentReceipt {
	r := testReceipt(id)
	r.Proof = receipt.Proof{
		Type:       "Ed25519Signature2020",
		ProofValue: "u-placeholder",
	}
	return r
}

func postReceipt(t *testing.T, h http.Handler, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	switch v := body.(type) {
	case string:
		buf.WriteString(v)
	case []byte:
		buf.Write(v)
	default:
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/receipts", &buf)
	req.Header.Set("Content-Type", "application/ld+json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestServer_PostReceipt_201(t *testing.T) {
	h, store := newTestHandler(t)
	r := signedTestReceipt("urn:receipt:srv:1")

	rec := postReceipt(t, h, r)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var resp acceptResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode 201 body: %v", err)
	}
	if resp.ID != r.ID {
		t.Fatalf("response id = %q, want %q", resp.ID, r.ID)
	}
	if !strings.HasPrefix(resp.ReceiptHash, "sha256:") {
		t.Fatalf("response receipt_hash = %q, want sha256: prefix", resp.ReceiptHash)
	}

	stored, raw, hash, ok := store.Get(r.ID)
	if !ok {
		t.Fatalf("receipt not present in store after 201")
	}
	if stored.ID != r.ID {
		t.Fatalf("stored.ID = %q, want %q", stored.ID, r.ID)
	}
	if hash != resp.ReceiptHash {
		t.Fatalf("stored hash %q != response hash %q", hash, resp.ReceiptHash)
	}
	if len(raw) == 0 {
		t.Fatal("store did not receive raw bytes")
	}
}

func TestServer_PostReceipt_PreservesUnknownFields(t *testing.T) {
	// ADR-0020 requires the collector to be a dumb sink. If the SDK ships
	// a forward-compat additive field the Go struct does not know about,
	// the collector MUST accept the receipt AND persist the unknown field
	// verbatim so an auditor can later re-canonicalise the exact bytes the
	// agent signed over.
	h, store := newTestHandler(t)
	body := []byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2", "https://agentreceipts.ai/context/v1"],
		"id": "urn:receipt:srv:forward-compat",
		"type": ["VerifiableCredential", "AgentReceipt"],
		"version": "0.3.0",
		"issuer": {"id": "did:example:test"},
		"issuanceDate": "2026-05-22T00:00:00Z",
		"_future_field": "hello from a future SDK",
		"credentialSubject": {
			"principal": {"id": "did:example:user"},
			"action": {"id": "act_1", "type": "tool_call", "risk_level": "low", "timestamp": "2026-05-22T00:00:00Z"},
			"outcome": {"status": "success"},
			"chain": {"sequence": 0, "previous_receipt_hash": null, "chain_id": "fc-chain"}
		},
		"proof": {"type": "Ed25519Signature2020", "proofValue": "u-placeholder"}
	}`)

	rec := postReceipt(t, h, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}

	_, raw, _, ok := store.Get("urn:receipt:srv:forward-compat")
	if !ok {
		t.Fatal("receipt not present in store after 201")
	}
	if !bytes.Contains(raw, []byte(`"_future_field"`)) {
		t.Fatalf("stored raw bytes lost the unknown field; got: %s", raw)
	}

	// The receipt_hash returned to the client (and stored in the
	// receipt_hash column) MUST be derived from the raw bytes — including
	// the forward-compat field — so an auditor recomputing the hash from
	// the stored bytes gets the same value. If we hashed the Go struct
	// instead, _future_field would have been dropped and the two hashes
	// would diverge across collector SDK versions.
	var resp acceptResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode 201 body: %v", err)
	}
	want, err := receipt.HashRawReceipt(raw)
	if err != nil {
		t.Fatalf("HashRawReceipt(stored bytes): %v", err)
	}
	if resp.ReceiptHash != want {
		t.Fatalf("response receipt_hash = %s; auditor-computed = %s; want equal", resp.ReceiptHash, want)
	}
}

func TestServer_PostReceipt_409Duplicate(t *testing.T) {
	h, _ := newTestHandler(t)
	r := signedTestReceipt("urn:receipt:srv:dup")

	if rec := postReceipt(t, h, r); rec.Code != http.StatusCreated {
		t.Fatalf("first post status = %d, want 201", rec.Code)
	}
	rec := postReceipt(t, h, r)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate post status = %d, want 409; body = %s", rec.Code, rec.Body.String())
	}
}

func TestServer_PostReceipt_400MalformedJSON(t *testing.T) {
	h, store := newTestHandler(t)
	rec := postReceipt(t, h, "{not json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if store.Len() != 0 {
		t.Fatalf("store mutated on 400: %d entries", store.Len())
	}
}

func TestServer_PostReceipt_400EmptyBody(t *testing.T) {
	h, store := newTestHandler(t)
	rec := postReceipt(t, h, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "empty") {
		t.Fatalf("body %q does not mention 'empty'", rec.Body.String())
	}
	if store.Len() != 0 {
		t.Fatalf("store mutated on 400: %d entries", store.Len())
	}
}

func TestServer_PostReceipt_400TrailingData(t *testing.T) {
	h, store := newTestHandler(t)
	r := signedTestReceipt("urn:receipt:srv:trailing")
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Append a second JSON object after the receipt.
	body := append(encoded, []byte(`{"trailing":"data"}`)...)
	rec := postReceipt(t, h, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "exactly one") {
		t.Fatalf("body %q does not mention the trailing-data check", rec.Body.String())
	}
	if store.Len() != 0 {
		t.Fatalf("store mutated on 400: %d entries", store.Len())
	}
}

func TestServer_PostReceipt_400TrailingCloseBracket(t *testing.T) {
	// Regression: json.Decoder.More() returns false when the next
	// non-whitespace byte is ']' or '}', so a naive More-based trailing-data
	// guard accepts `{...receipt...} ]`. The Decode-until-io.EOF check
	// rejects it correctly.
	h, store := newTestHandler(t)
	r := signedTestReceipt("urn:receipt:srv:trailing-bracket")
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := append(encoded, []byte(` ]`)...)
	rec := postReceipt(t, h, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "exactly one") {
		t.Fatalf("body %q does not mention the trailing-data check", rec.Body.String())
	}
	if store.Len() != 0 {
		t.Fatalf("store mutated on 400: %d entries", store.Len())
	}
}

func TestServer_PostReceipt_400MissingFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*receipt.AgentReceipt)
		want   string
	}{
		{"empty id", func(r *receipt.AgentReceipt) { r.ID = "" }, "receipt id is required"},
		{"empty chain_id", func(r *receipt.AgentReceipt) { r.CredentialSubject.Chain.ChainID = "" }, "chain_id"},
		{"empty action.type", func(r *receipt.AgentReceipt) { r.CredentialSubject.Action.Type = "" }, "action.type"},
		{"empty proof", func(r *receipt.AgentReceipt) { r.Proof = receipt.Proof{} }, "proof.proofValue"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, store := newTestHandler(t)
			r := signedTestReceipt("urn:receipt:srv:missing-" + tc.name)
			tc.mutate(&r)
			rec := postReceipt(t, h, r)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("response body %q does not mention %q", rec.Body.String(), tc.want)
			}
			if store.Len() != 0 {
				t.Fatalf("store mutated on 400: %d entries", store.Len())
			}
		})
	}
}

func TestServer_NewServer_RejectsNegativeMaxBodyBytes(t *testing.T) {
	// A negative MaxBodyBytes would silently brick the server (every
	// request rejected by http.MaxBytesReader). NewServer must surface
	// the misconfiguration at startup rather than at first request.
	_, err := NewServer(Config{
		Addr:         ":0",
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBodyBytes: -1,
	}, NewInMemoryStore())
	if err == nil {
		t.Fatal("NewServer with negative MaxBodyBytes: err=nil, want rejection")
	}
	if !strings.Contains(err.Error(), "MaxBodyBytes") {
		t.Fatalf("error %q does not mention MaxBodyBytes", err.Error())
	}
}

func TestServer_PostReceipt_400BodyTooLarge(t *testing.T) {
	store := NewInMemoryStore()
	h, err := Handler(Config{
		Addr:         ":0",
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxBodyBytes: 64,
	}, store)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	r := signedTestReceipt("urn:receipt:srv:big")
	rec := postReceipt(t, h, r) // serialised form is well over 64 bytes
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if store.Len() != 0 {
		t.Fatalf("store mutated on oversized body: %d entries", store.Len())
	}
}

func TestServer_PostReceipt_405WrongMethod(t *testing.T) {
	h, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/receipts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestServer_PostReceipt_500StoreError(t *testing.T) {
	failing := &failingStore{err: errors.New("disk fire")}
	h, err := Handler(Config{
		Addr:   ":0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, failing)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	rec := postReceipt(t, h, signedTestReceipt("urn:receipt:srv:fail"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body = %s", rec.Code, rec.Body.String())
	}
}

func TestServer_Healthz_OK(t *testing.T) {
	h, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestServer_Healthz_StoreUnreachable(t *testing.T) {
	failing := &failingStore{err: errors.New("disk fire")}
	h, err := Handler(Config{
		Addr:   ":0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, failing)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// runWithListener swaps the server's Addr for a bound listener and calls
// Run with a cancellable context. The returned cancel triggers graceful
// shutdown; the returned channel surfaces Run's return value.
func runWithListener(t *testing.T, srv *http.Server) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	// Run calls ListenAndServe internally; swap to a Serve over our listener
	// by intercepting via srv.Serve in a goroutine and bypassing Run's own
	// ListenAndServe. To exercise Run itself we instead reset srv.Addr and
	// release the listener so Run can bind. There is an unavoidable bind
	// race but it's tight and we only run this once per test.
	ln.Close()
	srv.Addr = addr

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(t.Context())
	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, srv, 2*time.Second, logger)
	}()
	return addr, cancel, runErr
}

func TestServer_Run_GracefulShutdown(t *testing.T) {
	// Exercise the actual Run function: bind, accept a request, cancel ctx,
	// expect a clean shutdown returning nil within the drain timeout. This
	// is what cmd/collector wires up, and what was previously bypassed in
	// tests by calling srv.Serve/srv.Shutdown directly.
	store := NewInMemoryStore()
	srv, err := NewServer(Config{
		Addr:   "127.0.0.1:0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, store)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	addr, cancel, runErr := runWithListener(t, srv)

	// Wait for the server to be reachable (Run starts ListenAndServe in a
	// goroutine after a small bind window).
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("server never became reachable: %v", lastErr)
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of ctx cancel")
	}
}

func TestServer_Run_ListenError(t *testing.T) {
	// Run must surface a listen error rather than wedging indefinitely on
	// the errCh channel when the bind fails. We force a bind failure by
	// pre-binding the address we hand to Run.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	store := NewInMemoryStore()
	srv, err := NewServer(Config{
		Addr:   ln.Addr().String(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, store)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(t.Context(), srv, time.Second, logger)
	}()

	select {
	case err := <-runErr:
		if err == nil {
			t.Fatal("Run returned nil for a bound-address bind; expected listen error")
		}
		if !strings.Contains(err.Error(), "collector listen") {
			t.Fatalf("Run error = %v, want a listen-prefixed error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of listen failure")
	}
}

// failingStore is a Store that returns its err from every method. Used to
// exercise the 500 / 503 paths without contorting the in-memory impl.
type failingStore struct{ err error }

func (s *failingStore) Insert(_ receipt.AgentReceipt, _ []byte, _ string) error { return s.err }
func (s *failingStore) Exists(_ string) (bool, error)                           { return false, s.err }
func (s *failingStore) Close() error                                            { return nil }
