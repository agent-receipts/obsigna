package pipeline

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/chain"
	"github.com/agent-receipts/ar/daemon/internal/keysource"
	"github.com/agent-receipts/ar/daemon/internal/socket"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
)

func newTestKeySource(t *testing.T) keysource.KeySource {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	ks := keysource.NewFile(path, "did:agent-receipts-daemon:test#k1")
	if err := ks.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ks.Teardown() })
	return ks
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleFrame(t *testing.T) socket.Frame {
	t.Helper()
	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "sess-123",
		Channel:   "mcp_proxy",
		Tool:      EmitterTool{Server: "github", Name: "list_repos"},
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	return socket.Frame{
		Payload: body,
		Peer: socket.PeerCred{
			Platform: "linux",
			PID:      4242,
			UID:      1000,
			GID:      1000,
			ExePath:  "/usr/bin/mcp-proxy",
		},
	}
}

// TestBuildPeerCred covers the pointer-semantics of buildPeerCred: POSIX
// platforms must set UID/GID to non-nil pointers (including for zero/root),
// and non-POSIX platforms must leave both nil.
func TestBuildPeerCred(t *testing.T) {
	cases := []struct {
		name    string
		peer    socket.PeerCred
		wantUID *uint32
		wantGID *uint32
		wantNil bool
	}{
		{
			name:    "linux non-root",
			peer:    socket.PeerCred{Platform: "linux", PID: 42, UID: 1000, GID: 1000},
			wantUID: ptrUint32(1000),
			wantGID: ptrUint32(1000),
		},
		{
			name:    "linux root (uid=0 must not be dropped)",
			peer:    socket.PeerCred{Platform: "linux", PID: 1, UID: 0, GID: 0},
			wantUID: ptrUint32(0),
			wantGID: ptrUint32(0),
		},
		{
			name:    "darwin",
			peer:    socket.PeerCred{Platform: "darwin", PID: 99, UID: 501, GID: 20},
			wantUID: ptrUint32(501),
			wantGID: ptrUint32(20),
		},
		{
			name:    "non-POSIX platform (no UID concept)",
			peer:    socket.PeerCred{Platform: "windows", PID: 7, UID: 0, GID: 0},
			wantNil: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := buildPeerCred(tc.peer)
			if pc == nil {
				t.Fatal("buildPeerCred returned nil")
			}
			if tc.wantNil {
				if pc.UID != nil {
					t.Errorf("UID = %v, want nil on non-POSIX platform", pc.UID)
				}
				if pc.GID != nil {
					t.Errorf("GID = %v, want nil on non-POSIX platform", pc.GID)
				}
				return
			}
			if pc.UID == nil || *pc.UID != *tc.wantUID {
				t.Errorf("UID = %v, want %d", pc.UID, *tc.wantUID)
			}
			if pc.GID == nil || *pc.GID != *tc.wantGID {
				t.Errorf("GID = %v, want %d", pc.GID, *tc.wantGID)
			}
		})
	}
}

// TestPrincipalFromPeer covers derivation of the receipt principal from
// kernel-attested peer credentials: a resolvable uid yields the host login name
// (did:user:<login>); an unresolvable uid falls back to the numeric
// did:user:<platform>:<uid> (the attested uid is never lost, including root);
// and platforms with no POSIX uid — or an absent peer — fall back to the
// did:user:unknown sentinel. lookupUID is stubbed so the test is deterministic
// regardless of the host user database.
func TestPrincipalFromPeer(t *testing.T) {
	orig := lookupUID
	t.Cleanup(func() { lookupUID = orig })

	resolves := func(uid string) (*user.User, error) {
		return &user.User{Uid: uid, Username: "ottojongerius", Name: "Otto Jongerius"}, nil
	}
	emptyName := func(uid string) (*user.User, error) {
		return &user.User{Uid: uid, Username: ""}, nil
	}
	notFound := func(uid string) (*user.User, error) {
		return nil, user.UnknownUserIdError(0)
	}

	cases := []struct {
		name   string
		lookup func(string) (*user.User, error)
		peer   socket.PeerCred
		want   string
	}{
		{"resolvable uid yields login name", resolves, socket.PeerCred{Platform: "darwin", PID: 99, UID: 501, GID: 20}, "did:user:ottojongerius"},
		{"unresolvable uid falls back to numeric", notFound, socket.PeerCred{Platform: "linux", PID: 42, UID: 1000, GID: 1000}, "did:user:linux:1000"},
		{"empty resolved name falls back to numeric", emptyName, socket.PeerCred{Platform: "darwin", PID: 7, UID: 501, GID: 20}, "did:user:darwin:501"},
		{"unresolvable root (uid=0 attested, not unknown)", notFound, socket.PeerCred{Platform: "linux", PID: 1, UID: 0, GID: 0}, "did:user:linux:0"},
		{"non-POSIX platform falls back to unknown", notFound, socket.PeerCred{Platform: "windows", PID: 7}, "did:user:unknown"},
		{"absent peer falls back to unknown", notFound, socket.PeerCred{}, "did:user:unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookupUID = tc.lookup
			if got := principalFromPeer(tc.peer).ID; got != tc.want {
				t.Errorf("principalFromPeer(%+v).ID = %q, want %q", tc.peer, got, tc.want)
			}
		})
	}
}

func TestProcess_BuildsSignedReceipt(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}

	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(chainReceipts) != 1 {
		t.Fatalf("got %d receipts, want 1", len(chainReceipts))
	}
	r := chainReceipts[0]

	if r.CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("seq = %d, want 1", r.CredentialSubject.Chain.Sequence)
	}
	if r.CredentialSubject.Chain.PreviousReceiptHash != nil {
		t.Errorf("first receipt prev_hash = %v, want nil", r.CredentialSubject.Chain.PreviousReceiptHash)
	}
	if r.CredentialSubject.Action.Type != "mcp_proxy.github.list_repos" {
		t.Errorf("action.type = %q", r.CredentialSubject.Action.Type)
	}
	if r.CredentialSubject.Action.ToolName != "list_repos" {
		t.Errorf("action.tool_name = %q", r.CredentialSubject.Action.ToolName)
	}
	pc := r.CredentialSubject.Action.PeerCredential
	if pc == nil {
		t.Fatal("PeerCredential nil; daemon must record OS-attested peer cred on every live receipt")
	}
	if pc.Platform != "linux" || pc.PID != 4242 || pc.UID == nil || *pc.UID != 1000 {
		t.Errorf("peer attestation not recorded: %#v", pc)
	}
	if pc.ExePath != "/usr/bin/mcp-proxy" {
		t.Errorf("peer_credential.exe_path = %q", pc.ExePath)
	}
	// Principal must be derived from the kernel-attested peer uid (sampleFrame's
	// peer is uid 1000), not the did:user:unknown sentinel. Exact formatting —
	// resolved login name vs numeric fallback — is covered by TestPrincipalFromPeer;
	// here we only assert the wiring derives something from the peer.
	if got := r.CredentialSubject.Principal.ID; got == "did:user:unknown" || !strings.HasPrefix(got, "did:user:") {
		t.Errorf("principal.id = %q, want a peer-derived did:user:* (not the unknown sentinel)", got)
	}
	// Live receipts MUST NOT carry the synthetic emitter_metadata block —
	// drop_count belongs to events_dropped synthetic receipts only.
	if r.CredentialSubject.Action.EmitterMetadata != nil {
		t.Errorf("live receipt should not carry emitter_metadata; got %#v", r.CredentialSubject.Action.EmitterMetadata)
	}
	// parameters_disclosure stays nil until the daemon ships envelope-mode
	// disclosure (issue #280); the old plaintext-in-body shape is gone.
	if r.CredentialSubject.Action.ParametersDisclosure != nil {
		t.Errorf("ParametersDisclosure must be nil on plain live receipts; got %#v", r.CredentialSubject.Action.ParametersDisclosure)
	}
	if r.Issuer.SessionID != "sess-123" {
		t.Errorf("issuer.session_id = %q, want sess-123", r.Issuer.SessionID)
	}

	pubPEM, err := ks.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ok, err := receipt.Verify(r, pubPEM)
	if err != nil {
		t.Fatalf("verify err: %v", err)
	}
	if !ok {
		t.Error("signature did not verify")
	}
}

// TestProcess_StampsIdempotencyKey verifies the daemon copies the frame's
// idempotency_key onto action.idempotency_key (spec §7.3.6, #480) and omits it
// when the frame leaves it empty.
func TestProcess_StampsIdempotencyKey(t *testing.T) {
	build := func(t *testing.T, key string) receipt.Action {
		t.Helper()
		ks := newTestKeySource(t)
		st := newTestStore(t)
		state := chain.New("chain-1")
		p := New(state, ks, st, "did:agent-receipts-daemon:test")
		body, err := json.Marshal(EmitterFrame{
			Version:        "1",
			TsEmit:         "2026-05-23T00:00:00Z",
			SessionID:      "s",
			Channel:        "mcp",
			Tool:           EmitterTool{Name: "do_thing"},
			Decision:       "allowed",
			IdempotencyKey: key,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Process(socket.Frame{Payload: body}); err != nil {
			t.Fatal(err)
		}
		chainReceipts, err := st.GetChain("chain-1")
		if err != nil {
			t.Fatal(err)
		}
		if len(chainReceipts) != 1 {
			t.Fatalf("got %d receipts, want 1", len(chainReceipts))
		}
		return chainReceipts[0].CredentialSubject.Action
	}

	t.Run("present", func(t *testing.T) {
		if got := build(t, "jsonrpc-req-99").IdempotencyKey; got != "jsonrpc-req-99" {
			t.Errorf("action.idempotency_key = %q, want %q", got, "jsonrpc-req-99")
		}
	})
	t.Run("absent", func(t *testing.T) {
		if got := build(t, "").IdempotencyKey; got != "" {
			t.Errorf("action.idempotency_key = %q, want empty", got)
		}
	})
}

// TestValidateFrame_RejectsOversizeIdempotencyKey pins the per-field cap so a
// runaway idempotency_key cannot inflate receipts.
func TestValidateFrame_RejectsOversizeIdempotencyKey(t *testing.T) {
	f := &EmitterFrame{
		Version:        "1",
		SessionID:      "s",
		Channel:        "mcp",
		Tool:           EmitterTool{Name: "t"},
		Decision:       "allowed",
		IdempotencyKey: strings.Repeat("x", maxIdentityFieldLen+1),
	}
	if err := validateFrame(f); err == nil {
		t.Error("validateFrame accepted an oversize idempotency_key; want rejection")
	}
}

// TestValidateFrame_RejectsOversizeCorrelationID pins the per-field cap so an
// oversized correlation_id cannot inflate receipts.
func TestValidateFrame_RejectsOversizeCorrelationID(t *testing.T) {
	f := &EmitterFrame{
		Version:       "1",
		SessionID:     "s",
		Channel:       "mcp",
		Tool:          EmitterTool{Name: "t"},
		Decision:      "allowed",
		CorrelationID: strings.Repeat("x", maxIdentityFieldLen+1),
	}
	if err := validateFrame(f); err == nil {
		t.Error("validateFrame accepted an oversize correlation_id; want rejection")
	}
}

func TestProcess_OutcomeStatus(t *testing.T) {
	cases := []struct {
		name       string
		decision   string
		errorField string
		want       receipt.OutcomeStatus
	}{
		{"allowed no error", "allowed", "", receipt.StatusSuccess},
		{"allowed with error", "allowed", "upstream timeout", receipt.StatusFailure},
		{"denied", "denied", "", receipt.StatusFailure},
		{"pending", "pending", "", receipt.StatusPending},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ks := newTestKeySource(t)
			st := newTestStore(t)
			state := chain.New("chain-1")
			p := New(state, ks, st, "did:agent-receipts-daemon:test")

			body, err := json.Marshal(EmitterFrame{
				Version:   "1",
				TsEmit:    "2026-05-03T00:00:00Z",
				SessionID: "s",
				Channel:   "sdk",
				Tool:      EmitterTool{Name: "t"},
				Decision:  tc.decision,
				Error:     tc.errorField,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Process(socket.Frame{Payload: body}); err != nil {
				t.Fatalf("Process: %v", err)
			}
			receipts, err := st.GetChain("chain-1")
			if err != nil {
				t.Fatal(err)
			}
			got := receipts[0].CredentialSubject.Outcome.Status
			if got != tc.want {
				t.Errorf("status = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestProcess_MCPIsErrorOutcome covers the MCP CallToolResult envelope: a
// JSON-RPC call that returns successfully but whose result body sets
// "isError": true is a tool-level failure. The proxy reports it with
// decision="allowed" and an empty error field (no JSON-RPC error was
// returned), so the daemon must inspect the result body to derive
// outcome.status. Non-mcp channels must keep their existing mapping —
// other channels may use isError with different semantics.
func TestProcess_MCPIsErrorOutcome(t *testing.T) {
	mcpErrorOutput := json.RawMessage(`{"content":[{"type":"text","text":"401 Bad credentials"}],"isError":true}`)
	mcpOKOutput := json.RawMessage(`{"content":[{"type":"text","text":"ok"}],"isError":false}`)
	mcpImplicitOKOutput := json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)

	cases := []struct {
		name    string
		channel string
		output  json.RawMessage
		want    receipt.OutcomeStatus
	}{
		{"mcp isError true → failure", "mcp", mcpErrorOutput, receipt.StatusFailure},
		{"mcp isError false → success", "mcp", mcpOKOutput, receipt.StatusSuccess},
		{"mcp isError absent → success", "mcp", mcpImplicitOKOutput, receipt.StatusSuccess},
		{"mcp empty output → success", "mcp", nil, receipt.StatusSuccess},
		{"mcp non-object output → success (no escalation on parse failure)", "mcp", json.RawMessage(`"not-an-object"`), receipt.StatusSuccess},
		// Other channels must not be reinterpreted: a top-level isError
		// field there is not the MCP envelope.
		{"non-mcp channel with isError true → success", "sdk", mcpErrorOutput, receipt.StatusSuccess},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ks := newTestKeySource(t)
			st := newTestStore(t)
			state := chain.New("chain-1")
			p := New(state, ks, st, "did:agent-receipts-daemon:test")

			body, err := json.Marshal(EmitterFrame{
				Version:   "1",
				TsEmit:    "2026-05-03T00:00:00Z",
				SessionID: "s",
				Channel:   tc.channel,
				Tool:      EmitterTool{Server: "github", Name: "create_pull_request"},
				Output:    tc.output,
				Decision:  "allowed",
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Process(socket.Frame{Payload: body}); err != nil {
				t.Fatalf("Process: %v", err)
			}
			receipts, err := st.GetChain("chain-1")
			if err != nil {
				t.Fatal(err)
			}
			got := receipts[0].CredentialSubject.Outcome.Status
			if got != tc.want {
				t.Errorf("status = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProcess_AdvancesSequenceAndPrevHash(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	for i := 0; i < 3; i++ {
		if err := p.Process(sampleFrame(t)); err != nil {
			t.Fatalf("Process %d: %v", i, err)
		}
	}

	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(chainReceipts) != 3 {
		t.Fatalf("got %d receipts, want 3", len(chainReceipts))
	}
	for i, r := range chainReceipts {
		if r.CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("receipt %d: seq = %d, want %d", i, r.CredentialSubject.Chain.Sequence, i+1)
		}
	}
	if chainReceipts[0].CredentialSubject.Chain.PreviousReceiptHash != nil {
		t.Error("receipt 0: prev_hash should be nil")
	}
	for i := 1; i < len(chainReceipts); i++ {
		want, err := receipt.HashReceipt(chainReceipts[i-1])
		if err != nil {
			t.Fatal(err)
		}
		got := chainReceipts[i].CredentialSubject.Chain.PreviousReceiptHash
		if got == nil || *got != want {
			t.Errorf("receipt %d: prev_hash = %v, want %s", i, got, want)
		}
	}
}

func TestProcess_RiskLevelFromTaxonomy(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	// The daemon constructs action.type as "<channel>.<server>.<name>" or
	// "<channel>.<name>". None of those match the built-in taxonomy, so
	// receipts MUST come out as RiskMedium (UnknownAction's risk) rather
	// than RiskLow (the previous hardcoded default).
	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := chainReceipts[0].CredentialSubject.Action.RiskLevel, receipt.RiskMedium; got != want {
		t.Errorf("unknown action_type risk = %q, want %q (taxonomy unknown default)", got, want)
	}
}

func TestProcess_AcceptsExplicitNullInputOutput(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	// "input": null and "output": null are the documented wire form for events
	// that genuinely have no payload (see daemon/README.md). They MUST be
	// accepted as equivalent to absent — and MUST NOT produce hashes (a hash
	// of literal null would falsely commit the daemon to "the input was null"
	// vs. "no input was sent").
	payload := []byte(`{"v":"1","ts_emit":"2026-05-03T00:00:00Z","session_id":"s","channel":"sdk","tool":{"name":"noop"},"input":null,"output":null,"decision":"allowed"}`)
	if err := p.Process(socket.Frame{Payload: payload}); err != nil {
		t.Fatalf("frame with explicit null input/output should be accepted: %v", err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := chainReceipts[0]
	if r.CredentialSubject.Action.ParametersHash != "" {
		t.Errorf("null input must not produce parameters_hash, got %q", r.CredentialSubject.Action.ParametersHash)
	}
	if r.CredentialSubject.Outcome.ResponseHash != "" {
		t.Errorf("null output must not produce response_hash, got %q", r.CredentialSubject.Outcome.ResponseHash)
	}
}

func TestProcess_HashesInput(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	input := json.RawMessage(`{"path":"/etc/passwd","mode":"r"}`)
	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "fs.read"},
		Input:     input,
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("frame with input should be accepted: %v", err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := chainReceipts[0]

	// Recompute the expected hash via the same canonicalization path the
	// receipt.Create helper uses — no shortcut through the daemon's internals.
	var v any
	if err := json.Unmarshal(input, &v); err != nil {
		t.Fatal(err)
	}
	canonical, err := receipt.Canonicalize(v)
	if err != nil {
		t.Fatal(err)
	}
	want := receipt.SHA256Hash(canonical)
	if got := r.CredentialSubject.Action.ParametersHash; got != want {
		t.Errorf("parameters_hash = %q, want %q", got, want)
	}
}

func TestProcess_HashesOutput(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	output := json.RawMessage(`{"bytes":1024,"checksum":"sha256:abc"}`)
	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "fs.read"},
		Output:    output,
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("frame with output should be accepted: %v", err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := chainReceipts[0]

	var v any
	if err := json.Unmarshal(output, &v); err != nil {
		t.Fatal(err)
	}
	canonical, err := receipt.Canonicalize(v)
	if err != nil {
		t.Fatal(err)
	}
	want := receipt.SHA256Hash(canonical)
	if got := r.CredentialSubject.Outcome.ResponseHash; got != want {
		t.Errorf("response_hash = %q, want %q", got, want)
	}
}

func TestProcess_HashesAreCanonical(t *testing.T) {
	// Same logical payload sent two different ways (key order, whitespace) MUST
	// produce identical hashes — that's the property cross-language verifiers
	// rely on. If this test ever fails, the canonicalizer regressed and every
	// SDK that ever produced a hash is at risk of mismatch.
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	frameA, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "fs.read"},
		Input:     json.RawMessage(`{"a":1,"b":2,"c":3}`),
		Output:    json.RawMessage(`{"x":[1,2,3],"y":"ok"}`),
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	frameB, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "fs.read"},
		Input:     json.RawMessage(`{ "c":3, "b":2 ,  "a":1 }`),
		Output:    json.RawMessage("{\n  \"y\":\"ok\",\n  \"x\":[1, 2, 3]\n}"),
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: frameA}); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: frameB}); err != nil {
		t.Fatal(err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(chainReceipts) != 2 {
		t.Fatalf("got %d receipts, want 2", len(chainReceipts))
	}
	a, b := chainReceipts[0], chainReceipts[1]
	if a.CredentialSubject.Action.ParametersHash != b.CredentialSubject.Action.ParametersHash {
		t.Errorf("parameters_hash differs across whitespace/key-order variants:\n  a=%q\n  b=%q",
			a.CredentialSubject.Action.ParametersHash, b.CredentialSubject.Action.ParametersHash)
	}
	if a.CredentialSubject.Outcome.ResponseHash != b.CredentialSubject.Outcome.ResponseHash {
		t.Errorf("response_hash differs across whitespace/key-order variants:\n  a=%q\n  b=%q",
			a.CredentialSubject.Outcome.ResponseHash, b.CredentialSubject.Outcome.ResponseHash)
	}
}

func TestProcess_AcceptsPrimitiveInputOutput(t *testing.T) {
	// MCP tool inputs are typically JSON objects, but tool outputs are
	// commonly strings, numbers, or arrays. The wire schema MUST accept any
	// valid JSON value and hash it consistently.
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "echo"},
		Input:     json.RawMessage(`"hello"`),
		Output:    json.RawMessage(`["a","b"]`),
		Decision:  "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("primitive input + array output should be accepted: %v", err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := chainReceipts[0]
	if r.CredentialSubject.Action.ParametersHash == "" {
		t.Error("primitive input must produce a parameters_hash")
	}
	if r.CredentialSubject.Outcome.ResponseHash == "" {
		t.Error("array output must produce a response_hash")
	}
}

func TestProcess_RejectsUnrepresentableNumbers(t *testing.T) {
	// 1e400 is syntactically valid JSON, so it survives the EmitterFrame
	// unmarshal (json.RawMessage stores the token verbatim without numeric
	// parsing). Re-unmarshaling into Go's `any` for canonicalisation fails
	// because the value overflows float64. The daemon MUST surface that as a
	// per-frame error and keep running — a panic here would let any
	// authenticated emitter DoS the daemon for every other emitter on the
	// same socket.
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	cases := []struct {
		name    string
		payload []byte
	}{
		{"input is unrepresentable number", []byte(`{"v":"1","ts_emit":"2026-05-03T00:00:00Z","session_id":"s","channel":"sdk","tool":{"name":"t"},"input":1e400,"decision":"allowed"}`)},
		{"output is unrepresentable number", []byte(`{"v":"1","ts_emit":"2026-05-03T00:00:00Z","session_id":"s","channel":"sdk","tool":{"name":"t"},"output":1e400,"decision":"allowed"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Process panicked on %s — daemon would crash: %v", tc.name, r)
				}
			}()
			if err := p.Process(socket.Frame{Payload: tc.payload}); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}

	// Chain state must NOT have advanced — error before persist means
	// alloc.Rollback ran on every case.
	a := state.Allocate()
	defer a.Rollback()
	if a.Sequence != 1 {
		t.Errorf("after rejected frames, next seq = %d, want 1 (no advance)", a.Sequence)
	}
}

// panicSigningKeySource panics on Sign, simulating any unexpected runtime
// failure between Allocate and Commit. Used to prove pipeline.Process releases
// the chain mutex via deferred Rollback even when buildAndSign panics.
type panicSigningKeySource struct{}

func (panicSigningKeySource) Init() error                { return nil }
func (panicSigningKeySource) Teardown() error            { return nil }
func (panicSigningKeySource) PublicKey() (string, error) { return "", nil }
func (panicSigningKeySource) VerificationMethod() string { return "did:test#k1" }
func (panicSigningKeySource) Sign(_ []byte) ([]byte, error) {
	panic("simulated panic during signing")
}

func TestProcess_PanicReleasesChainAllocation(t *testing.T) {
	// Any panic between Allocate and Commit MUST release the chain mutex via
	// the deferred Rollback. Without that, a single bad frame would deadlock
	// the daemon for every subsequent emitter on the same socket.
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, panicSigningKeySource{}, st, "did:agent-receipts-daemon:test")

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected Process to panic with the panicSigningKeySource stub; setup is broken")
			}
		}()
		_ = p.Process(sampleFrame(t))
	}()

	// If the chain mutex is still held, the next Allocate would block forever.
	// Run it on a goroutine with a tight timeout so the test fails loudly
	// rather than hanging until the framework's default kill.
	done := make(chan struct{})
	go func() {
		a := state.Allocate()
		a.Rollback()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("chain.State.Allocate timed out: panic in buildAndSign orphaned the mutex")
	}
}

func TestProcess_DaemonControlsAllTimestamps(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	fixed := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	p.Now = func() time.Time { return fixed }

	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}
	chainReceipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	r := chainReceipts[0]

	want := fixed.Format(time.RFC3339)
	if r.IssuanceDate != want {
		t.Errorf("issuanceDate = %q, want %q (Now hook should govern all daemon-stamped timestamps)", r.IssuanceDate, want)
	}
	if r.CredentialSubject.Action.Timestamp != want {
		t.Errorf("action.timestamp = %q, want %q", r.CredentialSubject.Action.Timestamp, want)
	}
	if r.Proof.Created != want {
		t.Errorf("proof.created = %q, want %q", r.Proof.Created, want)
	}
}

func TestProcess_RejectsMalformedFrames(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	// All cases below include ts_emit where it's not the field under test, so
	// validateFrame doesn't short-circuit on the new ts_emit check before
	// reaching the field we're actually exercising.
	const ok = `"ts_emit":"2026-05-04T00:00:00Z"`
	cases := []struct {
		name    string
		payload string
	}{
		{"not JSON", `not json`},
		{"missing v", `{` + ok + `,"session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed"}`},
		{"unsupported v", `{"v":"2",` + ok + `,"session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed"}`},
		{"missing session_id", `{"v":"1",` + ok + `,"channel":"sdk","tool":{"name":"t"},"decision":"allowed"}`},
		{"missing ts_emit", `{"v":"1","session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed"}`},
		{"malformed ts_emit", `{"v":"1","ts_emit":"yesterday","session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed"}`},
		{"missing tool.name", `{"v":"1",` + ok + `,"session_id":"s","channel":"sdk","tool":{},"decision":"allowed"}`},
		{"missing decision", `{"v":"1",` + ok + `,"session_id":"s","channel":"sdk","tool":{"name":"t"}}`},
		{"unknown decision", `{"v":"1",` + ok + `,"session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"maybe"}`},
		{"negative drop_count", `{"v":"1",` + ok + `,"session_id":"s","channel":"sdk","tool":{"name":"t"},"decision":"allowed","drop_count":-1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.Process(socket.Frame{Payload: []byte(tc.payload)})
			if err == nil {
				t.Error("expected error")
			}
		})
	}

	// All rejected — chain state must NOT have advanced.
	a := state.Allocate()
	defer a.Rollback()
	if a.Sequence != 1 {
		t.Errorf("after rejected frames, next seq = %d, want 1 (no advance)", a.Sequence)
	}
}

func dropFrame(t *testing.T, dropCount int64) socket.Frame {
	t.Helper()
	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "sess-drop",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "op"},
		Decision:  "allowed",
		DropCount: dropCount,
	})
	if err != nil {
		t.Fatal(err)
	}
	return socket.Frame{
		Payload: body,
		Peer:    socket.PeerCred{Platform: "linux", PID: 99, UID: 1000, GID: 1000, ExePath: "/usr/bin/emitter"},
	}
}

// TestProcess_DropCountZero verifies that when drop_count is absent (zero),
// Process inserts exactly one receipt and the chain starts at sequence 1.
func TestProcess_DropCountZero(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}
	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1 (no synthetic receipt for zero drop_count)", len(receipts))
	}
	if receipts[0].CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("seq = %d, want 1", receipts[0].CredentialSubject.Chain.Sequence)
	}
}

// TestProcess_DropCountInsertsEventsDroppedReceipt verifies the core
// events_dropped guarantee: when drop_count > 0 the daemon inserts a synthetic
// receipt at the current chain slot before the live receipt, so the gap is
// visible in the chain with no missing sequences.
func TestProcess_DropCountInsertsEventsDroppedReceipt(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	if err := p.Process(dropFrame(t, 3)); err != nil {
		t.Fatalf("Process: %v", err)
	}

	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 2 {
		t.Fatalf("got %d receipts, want 2 (synthetic + live)", len(receipts))
	}

	synthetic := receipts[0]
	live := receipts[1]

	// Synthetic receipt at seq 1.
	if synthetic.CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("synthetic seq = %d, want 1", synthetic.CredentialSubject.Chain.Sequence)
	}
	if synthetic.CredentialSubject.Chain.PreviousReceiptHash != nil {
		t.Errorf("synthetic first-in-chain: prev_hash should be nil")
	}
	if got := synthetic.CredentialSubject.Action.Type; got != actionTypeEventsDropped {
		t.Errorf("synthetic action.type = %q, want %q", got, actionTypeEventsDropped)
	}
	if got := synthetic.CredentialSubject.Action.ToolName; got != "events_dropped" {
		t.Errorf("synthetic tool_name = %q, want events_dropped", got)
	}
	if got := synthetic.CredentialSubject.Action.RiskLevel; got != "low" {
		t.Errorf("synthetic risk_level = %q, want low", got)
	}
	if got := synthetic.CredentialSubject.Outcome.Status; got != "success" {
		t.Errorf("synthetic outcome.status = %q, want success", got)
	}
	em := synthetic.CredentialSubject.Action.EmitterMetadata
	if em == nil {
		t.Fatal("synthetic events_dropped receipt missing emitter_metadata")
	}
	if em.DropCount != 3 {
		t.Errorf("synthetic emitter_metadata.drop_count = %d, want 3", em.DropCount)
	}
	if got := synthetic.Issuer.SessionID; got != "sess-drop" {
		t.Errorf("synthetic session_id = %q, want sess-drop", got)
	}

	// Live receipt at seq 2, prev_hash pointing to synthetic.
	if live.CredentialSubject.Chain.Sequence != 2 {
		t.Errorf("live seq = %d, want 2", live.CredentialSubject.Chain.Sequence)
	}
	wantPrev, err := receipt.HashReceipt(synthetic)
	if err != nil {
		t.Fatalf("hash synthetic: %v", err)
	}
	if live.CredentialSubject.Chain.PreviousReceiptHash == nil || *live.CredentialSubject.Chain.PreviousReceiptHash != wantPrev {
		t.Errorf("live prev_hash = %v, want %s", live.CredentialSubject.Chain.PreviousReceiptHash, wantPrev)
	}
	if live.CredentialSubject.Action.Type != "sdk.op" {
		t.Errorf("live action.type = %q, want sdk.op", live.CredentialSubject.Action.Type)
	}

	// Both receipts must be verifiable — the synthetic receipt uses the same
	// signer as the live one.
	pubPEM, err := ks.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range receipts {
		ok, err := receipt.Verify(r, pubPEM)
		if err != nil || !ok {
			t.Errorf("receipt[%d]: verify ok=%v err=%v", i, ok, err)
		}
	}
}

// TestProcess_DropCountPreservesPeerAttestationOnSynthetic verifies that the
// peer cred from the emitter connection is recorded in the synthetic receipt's
// peer_credential, matching the live receipt's attribution source.
func TestProcess_DropCountPreservesPeerAttestationOnSynthetic(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	if err := p.Process(dropFrame(t, 1)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) < 1 {
		t.Fatal("no receipts")
	}
	pc := receipts[0].CredentialSubject.Action.PeerCredential
	if pc == nil {
		t.Fatal("synthetic receipt missing peer_credential")
	}
	if pc.Platform != "linux" {
		t.Errorf("peer_credential.platform = %q, want linux", pc.Platform)
	}
	if pc.PID != 99 {
		t.Errorf("peer_credential.pid = %d, want 99", pc.PID)
	}
	if pc.ExePath != "/usr/bin/emitter" {
		t.Errorf("peer_credential.exe_path = %q", pc.ExePath)
	}
}

// TestProcess_DropCountChainContinues verifies that a frame with a drop_count
// followed by a normal frame (no drops) produces a clean contiguous chain
// with correct prev_hash links across all three receipts.
func TestProcess_DropCountChainContinues(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	if err := p.Process(dropFrame(t, 2)); err != nil {
		t.Fatalf("Process (drop frame): %v", err)
	}
	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatalf("Process (normal frame): %v", err)
	}

	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 3 {
		t.Fatalf("got %d receipts, want 3 (synthetic + live + normal)", len(receipts))
	}
	for i, r := range receipts {
		if r.CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("receipts[%d].Sequence = %d, want %d", i, r.CredentialSubject.Chain.Sequence, i+1)
		}
	}
	for i := 1; i < len(receipts); i++ {
		want, err := receipt.HashReceipt(receipts[i-1])
		if err != nil {
			t.Fatalf("hash receipt %d: %v", i-1, err)
		}
		got := receipts[i].CredentialSubject.Chain.PreviousReceiptHash
		if got == nil || *got != want {
			t.Errorf("receipts[%d] prev_hash = %v, want %s", i, got, want)
		}
	}
}

// TestProcess_NoDisclosureWithoutKey verifies the privacy-preserving default:
// with no forensic public key (regardless of policy), no parameters_disclosure
// envelope is produced — only the hash. There is nothing to encrypt to.
func TestProcess_NoDisclosureWithoutKey(t *testing.T) {
	for _, policy := range []string{"", "true", "high", "fs.read"} {
		t.Run("policy="+policy, func(t *testing.T) {
			ks := newTestKeySource(t)
			st := newTestStore(t)
			p := New(chain.New("chain-1"), ks, st, "did:agent-receipts-daemon:test")
			pol, err := ParseDisclosurePolicy(policy)
			if err != nil {
				t.Fatal(err)
			}
			p.DisclosurePolicy = pol
			// No ForensicPublicKey set.

			body, err := json.Marshal(EmitterFrame{
				Version: "1", TsEmit: "2026-05-03T00:00:00Z", SessionID: "s",
				Channel: "sdk", Tool: EmitterTool{Name: "fs.read"},
				Input:    json.RawMessage(`{"path":"/tmp/file","mode":"r"}`),
				Output:   json.RawMessage(`{"bytes":42}`),
				Decision: "allowed",
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Process(socket.Frame{Payload: body}); err != nil {
				t.Fatalf("Process: %v", err)
			}
			receipts, err := st.GetChain("chain-1")
			if err != nil {
				t.Fatal(err)
			}
			r := receipts[0]
			if r.CredentialSubject.Action.ParametersDisclosure != nil {
				t.Errorf("ParametersDisclosure must be nil without a forensic key; got %#v",
					r.CredentialSubject.Action.ParametersDisclosure)
			}
			if r.CredentialSubject.Action.ParametersHash == "" {
				t.Error("parameters_hash must be present when input is set")
			}
		})
	}
}

// TestProcess_DisclosurePolicyGatesEncryption verifies that, with a forensic key
// configured, the policy decides whether each action discloses. A high-risk and
// a low-risk action are sent under policy "high"; only the high-risk one gets an
// envelope, and it decrypts back to the original parameters.
func TestProcess_DisclosurePolicyGatesEncryption(t *testing.T) {
	fk, err := receipt.GenerateForensicKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ks := newTestKeySource(t)
	st := newTestStore(t)
	p := New(chain.New("chain-1"), ks, st, "did:agent-receipts-daemon:test")
	p.ForensicPublicKey = fk.PublicKey
	pol, err := ParseDisclosurePolicy("high")
	if err != nil {
		t.Fatal(err)
	}
	p.DisclosurePolicy = pol

	// The daemon constructs action types as "<channel>.<tool.name>", so to hit a
	// high-risk taxonomy entry (filesystem.file.delete) we set channel and tool
	// name accordingly. A separate low-risk action uses an unknown type.
	send := func(channel, toolName string, input json.RawMessage) {
		body, err := json.Marshal(EmitterFrame{
			Version: "1", TsEmit: "2026-05-03T00:00:00Z", SessionID: "s",
			Channel: channel, Tool: EmitterTool{Name: toolName},
			Input: input, Decision: "allowed",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Process(socket.Frame{Payload: body}); err != nil {
			t.Fatalf("Process(%s.%s): %v", channel, toolName, err)
		}
	}
	send("filesystem", "file.delete", json.RawMessage(`{"command":"rm -rf /tmp/x"}`)) // high risk
	send("sdk", "noop", json.RawMessage(`{"path":"/tmp/x"}`))                         // unknown -> medium

	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 2 {
		t.Fatalf("got %d receipts, want 2", len(receipts))
	}

	// Find each receipt by action type (order is by sequence but be explicit).
	var highRec, lowRec *receipt.AgentReceipt
	for i := range receipts {
		switch receipts[i].CredentialSubject.Action.Type {
		case "filesystem.file.delete":
			highRec = &receipts[i]
		case "sdk.noop":
			lowRec = &receipts[i]
		}
	}
	if highRec == nil || lowRec == nil {
		t.Fatalf("missing expected receipts: high=%v low=%v", highRec != nil, lowRec != nil)
	}

	// High-risk action discloses under policy "high".
	if highRec.CredentialSubject.Action.RiskLevel != receipt.RiskHigh &&
		highRec.CredentialSubject.Action.RiskLevel != receipt.RiskCritical {
		t.Fatalf("expected system.command.execute to be high/critical risk, got %q",
			highRec.CredentialSubject.Action.RiskLevel)
	}
	env := highRec.CredentialSubject.Action.ParametersDisclosure
	if env == nil {
		t.Fatal("high-risk action must have a disclosure envelope under policy=high")
	}
	// The kid must be the ADR-0015 fingerprint of the forensic public key.
	wantKID, _ := receipt.ForensicKeyFingerprint(fk.PublicKey)
	if env.Recipients[0].KID != wantKID {
		t.Errorf("kid = %q, want %q (ADR-0015 fingerprint)", env.Recipients[0].KID, wantKID)
	}
	dec, err := receipt.DecryptDisclosure(env, fk.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptDisclosure: %v", err)
	}
	if dec["command"] != "rm -rf /tmp/x" {
		t.Errorf("decrypted command = %v, want rm -rf /tmp/x", dec["command"])
	}

	// Low-risk action does NOT disclose under policy "high".
	if lowRec.CredentialSubject.Action.ParametersDisclosure != nil {
		t.Errorf("low-risk action must not disclose under policy=high; got %#v",
			lowRec.CredentialSubject.Action.ParametersDisclosure)
	}
	// But its hash is still present.
	if lowRec.CredentialSubject.Action.ParametersHash == "" {
		t.Error("low-risk action still needs parameters_hash")
	}
}

// TestProcess_DisclosureFallsBackToHashOnNonObjectInput verifies the fail-open
// behaviour: when disclosure is on but the input is not a JSON object (so it
// cannot be encrypted as an HPKE parameters object), the receipt is still
// produced with the hash — the event is not dropped and the chain stays intact.
func TestProcess_DisclosureFallsBackToHashOnNonObjectInput(t *testing.T) {
	fk, err := receipt.GenerateForensicKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ks := newTestKeySource(t)
	st := newTestStore(t)
	p := New(chain.New("chain-1"), ks, st, "did:agent-receipts-daemon:test")
	p.ForensicPublicKey = fk.PublicKey
	pol, err := ParseDisclosurePolicy("true")
	if err != nil {
		t.Fatal(err)
	}
	p.DisclosurePolicy = pol

	// Input is a JSON array, not an object — valid JSON payload (so it is
	// hashed) but not encryptable as a parameters object.
	body, err := json.Marshal(EmitterFrame{
		Version: "1", TsEmit: "2026-05-03T00:00:00Z", SessionID: "s",
		Channel: "sdk", Tool: EmitterTool{Name: "system.command.execute"},
		Input:    json.RawMessage(`["arg1","arg2"]`),
		Decision: "allowed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("Process: %v", err)
	}
	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1 (event must not be dropped)", len(receipts))
	}
	r := receipts[0]
	if r.CredentialSubject.Action.ParametersDisclosure != nil {
		t.Errorf("non-object input must fall back to hash-only; got envelope %#v",
			r.CredentialSubject.Action.ParametersDisclosure)
	}
	if r.CredentialSubject.Action.ParametersHash == "" {
		t.Error("parameters_hash must still be present on the fallback receipt")
	}
}

// failOnNthInsert wraps a pipelineStore and returns an error on the Nth Insert.
type failOnNthInsert struct {
	pipelineStore
	n       int
	callNum int
}

func (f *failOnNthInsert) Insert(r receipt.AgentReceipt, hash string) error {
	f.callNum++
	if f.callNum == f.n {
		return fmt.Errorf("simulated store insert failure on call %d", f.n)
	}
	return f.pipelineStore.Insert(r, hash)
}

// TestProcess_DropCountSyntheticFailureLiveReceiptPersists verifies that when
// the synthetic events_dropped receipt fails to persist, Process still returns
// nil and the live receipt is written. The synthetic failure is routed to
// ErrorLog rather than returned, keeping the return-value contract: a non-nil
// return from Process always means the live receipt was NOT persisted.
func TestProcess_DropCountSyntheticFailureLiveReceiptPersists(t *testing.T) {
	ks := newTestKeySource(t)
	underlying := newTestStore(t)
	// Fail only the first Insert (the synthetic receipt); the second (live) must succeed.
	st := &failOnNthInsert{pipelineStore: underlying, n: 1}

	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	var logged string
	p.ErrorLog = func(format string, args ...any) {
		logged = fmt.Sprintf(format, args...)
	}

	if err := p.Process(dropFrame(t, 2)); err != nil {
		t.Errorf("Process returned error %v; want nil (live receipt was persisted)", err)
	}
	if logged == "" {
		t.Error("ErrorLog was not called; synthetic failure must be logged")
	}

	// Live receipt must be in the store.
	receipts, getErr := underlying.GetChain("chain-1")
	if getErr != nil {
		t.Fatalf("GetChain: %v", getErr)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1 (live receipt must survive synthetic failure)", len(receipts))
	}
	if got := receipts[0].CredentialSubject.Action.Type; got != "sdk.op" {
		t.Errorf("action.type = %q, want sdk.op", got)
	}
	if got := receipts[0].CredentialSubject.Chain.Sequence; got != 1 {
		t.Errorf("seq = %d, want 1", got)
	}
}

// TestProcess_IssuerFieldsFromFrame verifies that IssuerName, IssuerModel, and
// OperatorID/OperatorName from the emitter frame are stamped onto the receipt
// Issuer, so proxy-supplied host identity flows through to every receipt.
func TestProcess_IssuerFieldsFromFrame(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	body, err := json.Marshal(EmitterFrame{
		Version:      "1",
		TsEmit:       "2026-05-03T00:00:00Z",
		SessionID:    "sess-abc",
		Channel:      "mcp",
		Tool:         EmitterTool{Name: "bash"},
		Decision:     "allowed",
		IssuerName:   "Claude Code",
		IssuerModel:  "claude-opus-4-5",
		OperatorID:   "did:web:anthropic.com",
		OperatorName: "Anthropic",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("Process: %v", err)
	}
	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1", len(receipts))
	}
	iss := receipts[0].Issuer
	if iss.Name != "Claude Code" {
		t.Errorf("Issuer.Name = %q, want %q", iss.Name, "Claude Code")
	}
	if iss.Model != "claude-opus-4-5" {
		t.Errorf("Issuer.Model = %q, want %q", iss.Model, "claude-opus-4-5")
	}
	if iss.Operator == nil {
		t.Fatal("Issuer.Operator is nil, want non-nil")
	}
	if iss.Operator.ID != "did:web:anthropic.com" {
		t.Errorf("Issuer.Operator.ID = %q, want %q", iss.Operator.ID, "did:web:anthropic.com")
	}
	if iss.Operator.Name != "Anthropic" {
		t.Errorf("Issuer.Operator.Name = %q, want %q", iss.Operator.Name, "Anthropic")
	}
	if iss.ID != "did:agent-receipts-daemon:test" {
		t.Errorf("Issuer.ID = %q; daemon ID must not be overwritten", iss.ID)
	}
	if iss.SessionID != "sess-abc" {
		t.Errorf("Issuer.SessionID = %q, want sess-abc", iss.SessionID)
	}
}

// TestProcess_EmptyOperatorFieldsLeaveOperatorNil verifies that when
// operator_id and operator_name are both absent from the frame, Issuer.Operator
// remains nil rather than being set to a zero-value struct.
func TestProcess_EmptyOperatorFieldsLeaveOperatorNil(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "s",
		Channel:   "sdk",
		Tool:      EmitterTool{Name: "noop"},
		Decision:  "allowed",
		// IssuerName set but no operator fields.
		IssuerName: "Some Host",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("Process: %v", err)
	}
	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatal(err)
	}
	if receipts[0].Issuer.Operator != nil {
		t.Errorf("Issuer.Operator = %+v; want nil when operator fields are absent", receipts[0].Issuer.Operator)
	}
	if receipts[0].Issuer.Name != "Some Host" {
		t.Errorf("Issuer.Name = %q, want \"Some Host\"", receipts[0].Issuer.Name)
	}
}

// TestValidateFrame_RejectsOversizedIdentityField verifies that validateFrame
// rejects frames where any identity field exceeds maxIdentityFieldLen bytes.
// The receipt store must remain empty after the rejection.
func TestValidateFrame_RejectsOversizedIdentityField(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	body, err := json.Marshal(EmitterFrame{
		Version:    "1",
		TsEmit:     "2026-05-03T00:00:00Z",
		SessionID:  "s",
		Channel:    "sdk",
		Tool:       EmitterTool{Name: "t"},
		Decision:   "allowed",
		IssuerName: strings.Repeat("a", 257),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = p.Process(socket.Frame{Payload: body})
	if err == nil {
		t.Fatal("expected error for oversized issuer_name, got nil")
	}
	if !strings.Contains(err.Error(), "issuer_name") {
		t.Errorf("error %q should mention \"issuer_name\"", err.Error())
	}
	if !strings.Contains(err.Error(), "256") {
		t.Errorf("error %q should mention the limit 256", err.Error())
	}

	// No receipt should have been stored.
	receipts, getErr := st.GetChain("chain-1")
	if getErr != nil {
		t.Fatalf("GetChain: %v", getErr)
	}
	if len(receipts) != 0 {
		t.Errorf("got %d receipts, want 0 (frame was rejected)", len(receipts))
	}
}

// TestValidateFrame_RejectsPartialOperator verifies that validateFrame rejects
// frames where operator_name is set without operator_id, preventing a receipt
// with an empty operator.id from being signed.
func TestValidateFrame_RejectsPartialOperator(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("chain-1")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	body, err := json.Marshal(EmitterFrame{
		Version:      "1",
		TsEmit:       "2026-05-03T00:00:00Z",
		SessionID:    "s",
		Channel:      "sdk",
		Tool:         EmitterTool{Name: "t"},
		Decision:     "allowed",
		OperatorName: "Acme",
		// OperatorID intentionally absent.
	})
	if err != nil {
		t.Fatal(err)
	}
	err = p.Process(socket.Frame{Payload: body})
	if err == nil {
		t.Fatal("expected error for operator_name without operator_id, got nil")
	}
	if !strings.Contains(err.Error(), "operator_name") {
		t.Errorf("error %q should mention \"operator_name\"", err.Error())
	}

	// No receipt should have been stored.
	receipts, getErr := st.GetChain("chain-1")
	if getErr != nil {
		t.Fatalf("GetChain: %v", getErr)
	}
	if len(receipts) != 0 {
		t.Errorf("got %d receipts, want 0 (frame was rejected)", len(receipts))
	}
}

// TestBuild_ForensicPublicKeyEncryptsParameters demonstrates HPKE parameter
// encryption end-to-end via the daemon's Process API. When a forensic public
// key is configured, the daemon encrypts tool input to that key and attaches
// the HPKE v1 envelope as action.parameters_disclosure. The hash still commits
// to the original plaintext (tamper-evident), but parameters are opaque on the
// wire. Only the forensic responder holding the private key can decrypt.
func TestBuild_ForensicPublicKeyEncryptsParameters(t *testing.T) {
	// Generate a forensic key pair (ADR-0012).
	fk, err := receipt.GenerateForensicKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Set up the pipeline with the forensic public key.
	ks := newTestKeySource(t)
	st := newTestStore(t)
	pp := New(chain.New("chain-1"), ks, st, "did:agent-receipts-daemon:test")
	pp.ForensicPublicKey = fk.PublicKey
	pol, err := ParseDisclosurePolicy("true") // disclose all actions
	if err != nil {
		t.Fatal(err)
	}
	pp.DisclosurePolicy = pol

	// Build a frame with JSON parameters.
	emitterFrame := EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-05-03T00:00:00Z",
		SessionID: "sess-123",
		Channel:   "mcp_proxy",
		Tool:      EmitterTool{Server: "github", Name: "list_repos"},
		Input:     json.RawMessage(`{"command":"rm -rf /tmp/old-report.pdf"}`),
		Output:    json.RawMessage(`{"status":"success"}`),
		Decision:  "allowed",
	}
	body, err := json.Marshal(emitterFrame)
	if err != nil {
		t.Fatal(err)
	}
	frame := socket.Frame{
		Payload: body,
		Peer: socket.PeerCred{
			Platform: "linux",
			PID:      4242,
			UID:      1000,
			GID:      1000,
			ExePath:  "/usr/bin/mcp-proxy",
		},
	}

	// Process the frame through the pipeline.
	if err := pp.Process(frame); err != nil {
		t.Fatalf("Process: %v", err)
	}

	// Retrieve the stored receipt.
	receipts, err := st.GetChain("chain-1")
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1", len(receipts))
	}
	rec := receipts[0]

	// Verify parameters_disclosure envelope is present and opaque.
	if rec.CredentialSubject.Action.ParametersDisclosure == nil {
		t.Fatal("parameters_disclosure is nil; expected HPKE envelope")
	}
	env := rec.CredentialSubject.Action.ParametersDisclosure
	if env.V != "1" {
		t.Errorf("envelope version: got %q, want %q", env.V, "1")
	}
	if env.Alg != "hpke-x25519-hkdf-sha256-aes-256-gcm" {
		t.Errorf("algorithm: got %q, want hpke-x25519-...", env.Alg)
	}
	if len(env.Recipients) != 1 {
		t.Errorf("recipients: got %d, want 1", len(env.Recipients))
	}
	// enc and ct are opaque base64url-encoded HPKE material.
	if env.Recipients[0].Enc == "" {
		t.Fatal("enc is empty")
	}
	if env.CT == "" {
		t.Fatal("ct is empty")
	}

	// Verify parameters_hash still commits to the original canonical bytes.
	// The hash is tamper-evident even though parameters are encrypted.
	if rec.CredentialSubject.Action.ParametersHash == "" {
		t.Fatal("parameters_hash is empty")
	}
	if !strings.HasPrefix(rec.CredentialSubject.Action.ParametersHash, "sha256:") {
		t.Errorf("parameters_hash format: got %q, want sha256:...",
			rec.CredentialSubject.Action.ParametersHash)
	}

	// Verify the receipt is signed.
	if rec.Proof.ProofValue == "" {
		t.Fatal("proof.proofValue is empty")
	}

	// Decrypt the envelope using the private key and verify round-trip.
	decrypted, err := receipt.DecryptDisclosure(env, fk.PrivateKey)
	if err != nil {
		t.Fatalf("DecryptDisclosure: %v", err)
	}

	// Verify decrypted params match the original input.
	command, ok := decrypted["command"]
	if !ok {
		t.Fatalf("decrypted params missing 'command' key: %+v", decrypted)
	}
	if command != "rm -rf /tmp/old-report.pdf" {
		t.Errorf("command: got %v, want rm -rf /tmp/old-report.pdf", command)
	}
}

// TestProcess_EmitterDeclaredActionTypeDrivesRisk verifies the fix for
// risk-based disclosure through the daemon: when an emitter declares a taxonomic
// action_type, the daemon uses it as action.type and resolves risk from it, so a
// "high" policy fires. Without the declaration, the synthetic channel.tool type
// resolves to medium and "high" would not fire — proven by the negative case.
func TestProcess_EmitterDeclaredActionTypeDrivesRisk(t *testing.T) {
	fk, err := receipt.GenerateForensicKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := ParseDisclosurePolicy("high")
	if err != nil {
		t.Fatal(err)
	}

	run := func(declaredType string) receipt.AgentReceipt {
		ks := newTestKeySource(t)
		st := newTestStore(t)
		p := New(chain.New("chain-1"), ks, st, "did:agent-receipts-daemon:test")
		p.ForensicPublicKey = fk.PublicKey
		p.DisclosurePolicy = pol

		body, err := json.Marshal(EmitterFrame{
			Version: "1", TsEmit: "2026-05-03T00:00:00Z", SessionID: "s",
			Channel: "sdk", Tool: EmitterTool{Name: "rm"},
			ActionType: declaredType, // may be empty
			Input:      json.RawMessage(`{"command":"rm -rf /tmp/x"}`),
			Decision:   "allowed",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Process(socket.Frame{Payload: body}); err != nil {
			t.Fatalf("Process: %v", err)
		}
		receipts, err := st.GetChain("chain-1")
		if err != nil {
			t.Fatal(err)
		}
		return receipts[0]
	}

	// Declared high-risk taxonomic type → action.type is used, risk is high,
	// disclosure fires.
	r := run("filesystem.file.delete")
	if r.CredentialSubject.Action.Type != "filesystem.file.delete" {
		t.Errorf("action.type = %q, want filesystem.file.delete (emitter-declared)",
			r.CredentialSubject.Action.Type)
	}
	if r.CredentialSubject.Action.RiskLevel != receipt.RiskHigh {
		t.Errorf("risk = %q, want high", r.CredentialSubject.Action.RiskLevel)
	}
	if r.CredentialSubject.Action.ParametersDisclosure == nil {
		t.Error("high-risk declared action must disclose under policy=high")
	}

	// No declared type → synthetic "sdk.rm" type resolves to medium, so "high"
	// does NOT fire. This is the limitation the action_type field addresses.
	r = run("")
	if r.CredentialSubject.Action.Type != "sdk.rm" {
		t.Errorf("action.type = %q, want synthetic sdk.rm", r.CredentialSubject.Action.Type)
	}
	if r.CredentialSubject.Action.RiskLevel == receipt.RiskHigh {
		t.Error("synthetic type unexpectedly resolved to high risk")
	}
	if r.CredentialSubject.Action.ParametersDisclosure != nil {
		t.Error("medium-risk action must not disclose under policy=high")
	}
}

// agentFrame returns a socket.Frame whose payload has the given agent_id.
func agentFrame(t *testing.T, agentID string) socket.Frame {
	t.Helper()
	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-06-08T00:00:00Z",
		SessionID: "sess-agent-test",
		Channel:   "claude-code",
		Tool:      EmitterTool{Name: "Bash"},
		Decision:  "allowed",
		AgentID:   agentID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return socket.Frame{Payload: body}
}

// TestProcess_RuntimeModelUsageOnRootReceipt verifies that the transcript-
// derived model/usage/capture_method fields on a frame are stamped onto
// issuer.runtime — even on a ROOT receipt with no agent_id, which historically
// carried no runtime. Usage is forwarded verbatim, and the receipt round-trips
// through HashReceipt so a dropped runtime key would fail the hash.
func TestProcess_RuntimeModelUsageOnRootReceipt(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("root")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	usage := json.RawMessage(`{"input_tokens":1954,"output_tokens":392,"cache_read_input_tokens":0,"cache_creation_input_tokens":16762}`)
	body, err := json.Marshal(EmitterFrame{
		Version:       "1",
		TsEmit:        "2026-05-03T00:00:00Z",
		SessionID:     "sess-abc",
		Channel:       "claude-code",
		Tool:          EmitterTool{Name: "Bash"},
		Decision:      "allowed",
		Model:         "claude-opus-4-8",
		Usage:         usage,
		CaptureMethod: "transcript",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("Process: %v", err)
	}

	receipts, err := st.GetChain("root")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts, want 1", len(receipts))
	}
	rt := receipts[0].Issuer.Runtime
	if rt == nil {
		t.Fatal("issuer.runtime is nil; want model/usage/capture_method on a root receipt")
	}
	if rt.AgentID != "" {
		t.Errorf("runtime.agent_id = %q; want empty on a root receipt", rt.AgentID)
	}
	if rt.Model != "claude-opus-4-8" {
		t.Errorf("runtime.model = %q; want claude-opus-4-8", rt.Model)
	}
	if rt.CaptureMethod != "transcript" {
		t.Errorf("runtime.capture_method = %q; want transcript", rt.CaptureMethod)
	}
	var got map[string]int
	if err := json.Unmarshal(rt.Usage, &got); err != nil {
		t.Fatalf("runtime.usage is not an object: %v (%s)", err, rt.Usage)
	}
	if got["input_tokens"] != 1954 || got["output_tokens"] != 392 || got["cache_creation_input_tokens"] != 16762 {
		t.Errorf("runtime.usage = %v; want the verbatim token object", got)
	}

	// The signed receipt must re-hash to a stable value through the typed
	// Runtime struct (the open-container round-trip invariant from ADR-0026).
	if _, err := receipt.HashReceipt(receipts[0]); err != nil {
		t.Fatalf("HashReceipt on a runtime-bearing receipt: %v", err)
	}
}

// TestProcess_AgentIDRoutesToSeparateChain verifies that frames with a non-empty
// agent_id land on a per-agent chain distinct from the root chain.
func TestProcess_AgentIDRoutesToSeparateChain(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("root")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	// One root receipt (no agent_id).
	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}
	// One subagent receipt.
	if err := p.Process(agentFrame(t, "agent-abc")); err != nil {
		t.Fatal(err)
	}

	rootReceipts, err := st.GetChain("root")
	if err != nil {
		t.Fatal(err)
	}
	if len(rootReceipts) != 1 {
		t.Errorf("root chain: got %d receipts, want 1", len(rootReceipts))
	}
	if rootReceipts[0].CredentialSubject.Chain.ChainID != "root" {
		t.Errorf("root receipt chain_id = %q", rootReceipts[0].CredentialSubject.Chain.ChainID)
	}
	if rootReceipts[0].Issuer.Runtime != nil {
		t.Errorf("root receipt issuer.runtime = %+v; want nil (no agent_id)", rootReceipts[0].Issuer.Runtime)
	}

	agentChainID := "root/agent/agent-abc"
	agentReceipts, err := st.GetChain(agentChainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(agentReceipts) != 1 {
		t.Errorf("agent chain: got %d receipts, want 1", len(agentReceipts))
	}
	if agentReceipts[0].CredentialSubject.Chain.ChainID != agentChainID {
		t.Errorf("agent receipt chain_id = %q, want %q",
			agentReceipts[0].CredentialSubject.Chain.ChainID, agentChainID)
	}
	if rt := agentReceipts[0].Issuer.Runtime; rt == nil || rt.AgentID != "agent-abc" {
		t.Errorf("agent receipt issuer.runtime = %+v, want AgentID=agent-abc", rt)
	}
}

// TestProcess_DelegationOnFirstAgentReceipt verifies that the first receipt on
// a subagent chain carries a delegation that links back to the root chain's tail.
func TestProcess_DelegationOnFirstAgentReceipt(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("root")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	// Emit a root receipt so there is a tail to backlink to.
	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}
	rootReceipts, err := st.GetChain("root")
	if err != nil || len(rootReceipts) != 1 {
		t.Fatalf("setup: expected 1 root receipt, err=%v", err)
	}
	rootTailID := rootReceipts[0].ID

	// First subagent receipt — delegation must be present.
	if err := p.Process(agentFrame(t, "agent-xyz")); err != nil {
		t.Fatal(err)
	}
	agentReceipts, err := st.GetChain("root/agent/agent-xyz")
	if err != nil || len(agentReceipts) != 1 {
		t.Fatalf("expected 1 agent receipt, got %d, err=%v", len(agentReceipts), err)
	}
	del := agentReceipts[0].CredentialSubject.Delegation
	if del == nil {
		t.Fatal("first agent receipt missing delegation")
	}
	if del.ParentChainID != "root" {
		t.Errorf("delegation.parent_chain_id = %q, want root", del.ParentChainID)
	}
	if del.ParentReceiptID != rootTailID {
		t.Errorf("delegation.parent_receipt_id = %q, want %q", del.ParentReceiptID, rootTailID)
	}
	if del.Delegator.ID != "did:agent-receipts-daemon:test" {
		t.Errorf("delegation.delegator.id = %q", del.Delegator.ID)
	}

	// Second subagent receipt on the same chain — no delegation.
	if err := p.Process(agentFrame(t, "agent-xyz")); err != nil {
		t.Fatal(err)
	}
	agentReceipts, err = st.GetChain("root/agent/agent-xyz")
	if err != nil || len(agentReceipts) != 2 {
		t.Fatalf("expected 2 agent receipts, got %d, err=%v", len(agentReceipts), err)
	}
	if agentReceipts[1].CredentialSubject.Delegation != nil {
		t.Error("second receipt must not carry delegation")
	}
}

// TestProcess_DelegationOnFirstAgentDropReceipt verifies that when the first
// frame for a subagent chain has DropCount>0, the synthetic events_dropped
// receipt (sequence 1) carries delegation and the following live receipt
// (sequence 2) does not.
func TestProcess_DelegationOnFirstAgentDropReceipt(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("root")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	// Emit a root receipt so there is a tail to backlink to.
	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}
	rootReceipts, err := st.GetChain("root")
	if err != nil || len(rootReceipts) != 1 {
		t.Fatalf("setup: expected 1 root receipt, err=%v", err)
	}
	rootTailID := rootReceipts[0].ID

	// First subagent frame with drop_count=2: produces a synthetic receipt
	// (seq 1) followed by the live receipt (seq 2).
	body, err := json.Marshal(EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-06-08T00:00:00Z",
		SessionID: "sess-agent-drop",
		Channel:   "claude-code",
		Tool:      EmitterTool{Name: "Bash"},
		Decision:  "allowed",
		AgentID:   "agent-drop",
		DropCount: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatal(err)
	}

	agentChainID := "root/agent/agent-drop"
	agentReceipts, err := st.GetChain(agentChainID)
	if err != nil || len(agentReceipts) != 2 {
		t.Fatalf("expected 2 agent receipts (drop+live), got %d, err=%v", len(agentReceipts), err)
	}

	// Sequence 1: synthetic events_dropped — must carry delegation.
	dropR := agentReceipts[0]
	if dropR.CredentialSubject.Chain.Sequence != 1 {
		t.Errorf("drop receipt seq = %d, want 1", dropR.CredentialSubject.Chain.Sequence)
	}
	del := dropR.CredentialSubject.Delegation
	if del == nil {
		t.Fatal("drop receipt (seq 1) missing delegation")
	}
	if del.ParentChainID != "root" {
		t.Errorf("delegation.parent_chain_id = %q, want root", del.ParentChainID)
	}
	if del.ParentReceiptID != rootTailID {
		t.Errorf("delegation.parent_receipt_id = %q, want %q", del.ParentReceiptID, rootTailID)
	}
	if del.Delegator.ID != "did:agent-receipts-daemon:test" {
		t.Errorf("delegation.delegator.id = %q", del.Delegator.ID)
	}

	// Sequence 2: live receipt — must NOT carry delegation.
	liveR := agentReceipts[1]
	if liveR.CredentialSubject.Chain.Sequence != 2 {
		t.Errorf("live receipt seq = %d, want 2", liveR.CredentialSubject.Chain.Sequence)
	}
	if liveR.CredentialSubject.Delegation != nil {
		t.Error("live receipt (seq 2) must not carry delegation")
	}
}

// TestProcess_NoDelegationWhenRootChainEmpty verifies that if the first event is
// a subagent frame with no prior root receipt, delegation is omitted rather than
// panicking or returning an error.
func TestProcess_NoDelegationWhenRootChainEmpty(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("root")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	// Subagent frame arrives before any root receipt.
	if err := p.Process(agentFrame(t, "agent-early")); err != nil {
		t.Fatal(err)
	}
	agentReceipts, err := st.GetChain("root/agent/agent-early")
	if err != nil || len(agentReceipts) != 1 {
		t.Fatalf("expected 1 agent receipt, got %d, err=%v", len(agentReceipts), err)
	}
	// No root tail → delegation should be omitted, not an error.
	if agentReceipts[0].CredentialSubject.Delegation != nil {
		t.Error("expected no delegation when root chain has no receipts yet")
	}
}

// TestProcess_DelegationPreservedAfterFirstReceiptFailure verifies that when the
// first receipt for a new subagent chain fails to persist (store error), the
// retry still carries the delegation. The chain is cached in agentChains after
// the first call but NextSeq stays at 1 after the rollback, so
// getOrCreateAgentState must re-derive delegation on the next attempt.
func TestProcess_DelegationPreservedAfterFirstReceiptFailure(t *testing.T) {
	ks := newTestKeySource(t)
	underlying := newTestStore(t)
	// Insert 1: root receipt (succeeds). Insert 2: first agent attempt (fails).
	// Insert 3+: retry (succeeds).
	st := &failOnNthInsert{pipelineStore: underlying, n: 2}
	state := chain.New("root")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	// Emit a root receipt so the delegation has a backlink target.
	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}
	rootReceipts, err := underlying.GetChain("root")
	if err != nil || len(rootReceipts) != 1 {
		t.Fatalf("setup: expected 1 root receipt, err=%v", err)
	}
	rootTailID := rootReceipts[0].ID

	// First attempt: store insert fails. Process should return an error and the
	// chain should have no receipts.
	if err := p.Process(agentFrame(t, "agent-retry")); err == nil {
		t.Fatal("expected error from first agent frame (store inject failure); got nil")
	}

	// Retry: store insert succeeds. The receipt must carry delegation.
	if err := p.Process(agentFrame(t, "agent-retry")); err != nil {
		t.Fatalf("retry agent frame failed: %v", err)
	}
	agentReceipts, err := underlying.GetChain("root/agent/agent-retry")
	if err != nil || len(agentReceipts) != 1 {
		t.Fatalf("expected 1 agent receipt after retry, got %d, err=%v", len(agentReceipts), err)
	}
	del := agentReceipts[0].CredentialSubject.Delegation
	if del == nil {
		t.Fatal("retry receipt missing delegation; getOrCreateAgentState must re-derive it when NextSeq==1")
	}
	if del.ParentChainID != "root" {
		t.Errorf("delegation.parent_chain_id = %q, want root", del.ParentChainID)
	}
	if del.ParentReceiptID != rootTailID {
		t.Errorf("delegation.parent_receipt_id = %q, want %q", del.ParentReceiptID, rootTailID)
	}
}

// TestEmitTerminator_ContinuesAfterAgentChainError verifies that when one agent
// chain fails to be terminated, EmitTerminator still attempts the remaining
// chains and the root chain, returning the first error after all attempts.
func TestEmitTerminator_ContinuesAfterAgentChainError(t *testing.T) {
	ks := newTestKeySource(t)
	underlying := newTestStore(t)
	state := chain.New("root")
	// Fail insert 3 (the agent terminator): inserts 1=root, 2=agent, then 3=agent
	// terminator fails. Insert 4 (root terminator) must still proceed.
	st := &failOnNthInsert{pipelineStore: underlying, n: 3}
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(agentFrame(t, "agent-fail-term")); err != nil {
		t.Fatal(err)
	}

	err := p.EmitTerminator(context.Background())
	if err == nil {
		t.Error("expected EmitTerminator to return error from the failing agent chain")
	}

	// Root chain must still be terminated even though the agent chain failed.
	rootReceipts, qErr := underlying.GetChain("root")
	if qErr != nil {
		t.Fatalf("GetChain root: %v", qErr)
	}
	tail := rootReceipts[len(rootReceipts)-1]
	if tail.CredentialSubject.Chain.Terminal == nil || !*tail.CredentialSubject.Chain.Terminal {
		t.Error("root chain tail must be terminal even when one agent chain terminator failed")
	}
}

// TestValidateFrame_RejectsAgentIDWithSlash verifies that an agent_id containing
// '/' is rejected before chain ID construction to prevent ambiguous chain IDs of
// the form rootChainID+"/agent/"+agentID.
func TestValidateFrame_RejectsAgentIDWithSlash(t *testing.T) {
	cases := []struct {
		name    string
		agentID string
	}{
		{"single slash", "sub/agent"},
		{"agent segment", "x/agent/y"},
		{"null byte", "agent\x00id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &EmitterFrame{
				Version:   "1",
				TsEmit:    "2026-05-03T00:00:00Z",
				SessionID: "s",
				Channel:   "mcp",
				Tool:      EmitterTool{Name: "t"},
				Decision:  "allowed",
				AgentID:   tc.agentID,
			}
			if err := validateFrame(f); err == nil {
				t.Errorf("validateFrame accepted agent_id %q; want rejection", tc.agentID)
			}
		})
	}
}

// TestEmitTerminator_TerminatesAgentChains verifies that EmitTerminator closes
// all open agent chains in addition to the root chain.
func TestEmitTerminator_TerminatesAgentChains(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("root")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	// Populate root and one agent chain.
	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatal(err)
	}
	if err := p.Process(agentFrame(t, "agent-term")); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := p.EmitTerminator(ctx); err != nil {
		t.Fatal(err)
	}

	for _, chainID := range []string{"root", "root/agent/agent-term"} {
		receipts, err := st.GetChain(chainID)
		if err != nil {
			t.Fatalf("GetChain %q: %v", chainID, err)
		}
		tail := receipts[len(receipts)-1]
		if tail.CredentialSubject.Chain.Terminal == nil || !*tail.CredentialSubject.Chain.Terminal {
			t.Errorf("chain %q tail is not terminal", chainID)
		}
	}
}

// TestProcess_TargetResourcePopulatesActionTarget verifies that TargetSystem and
// TargetResource in the emitter frame flow through into action.target on the
// signed receipt.
func TestProcess_TargetResourcePopulatesActionTarget(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("root")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	body, err := json.Marshal(EmitterFrame{
		Version:        "1",
		TsEmit:         "2026-05-03T00:00:00Z",
		SessionID:      "sess-target",
		Channel:        "claude-code",
		Tool:           EmitterTool{Name: "Read"},
		Decision:       "allowed",
		TargetSystem:   "filesystem",
		TargetResource: "/home/user/project/main.go",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(socket.Frame{Payload: body}); err != nil {
		t.Fatalf("Process: %v", err)
	}

	receipts, err := st.GetChain("root")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts; want 1", len(receipts))
	}
	target := receipts[0].CredentialSubject.Action.Target
	if target == nil {
		t.Fatal("action.target is nil; want populated")
	}
	if target.System != "filesystem" {
		t.Errorf("action.target.system = %q; want filesystem", target.System)
	}
	if target.Resource != "/home/user/project/main.go" {
		t.Errorf("action.target.resource = %q; want /home/user/project/main.go", target.Resource)
	}
}

// TestProcess_NoTargetLeavesActionTargetNil verifies that a frame with no
// TargetSystem/TargetResource leaves action.target nil.
func TestProcess_NoTargetLeavesActionTargetNil(t *testing.T) {
	ks := newTestKeySource(t)
	st := newTestStore(t)
	state := chain.New("root")
	p := New(state, ks, st, "did:agent-receipts-daemon:test")

	if err := p.Process(sampleFrame(t)); err != nil {
		t.Fatalf("Process: %v", err)
	}

	receipts, err := st.GetChain("root")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 {
		t.Fatalf("got %d receipts; want 1", len(receipts))
	}
	if target := receipts[0].CredentialSubject.Action.Target; target != nil {
		t.Errorf("action.target = %+v; want nil", *target)
	}
}

// TestValidateFrame_RejectsOversizeTargetSystem verifies that validateFrame rejects
// a target_system value exceeding maxIdentityFieldLen bytes.
func TestValidateFrame_RejectsOversizeTargetSystem(t *testing.T) {
	f := &EmitterFrame{
		Version:        "1",
		TsEmit:         "2026-06-12T00:00:00Z",
		SessionID:      "s",
		Channel:        "claude-code",
		Tool:           EmitterTool{Name: "Read"},
		Decision:       "allowed",
		TargetSystem:   strings.Repeat("x", maxIdentityFieldLen+1),
		TargetResource: "/etc/hosts",
	}
	if err := validateFrame(f); err == nil {
		t.Error("validateFrame accepted an oversize target_system; want rejection")
	}
}

// TestValidateFrame_RejectsOversizeTargetResource verifies that validateFrame rejects
// a target_resource value exceeding maxTargetResourceLen bytes.
func TestValidateFrame_RejectsOversizeTargetResource(t *testing.T) {
	f := &EmitterFrame{
		Version:        "1",
		TsEmit:         "2026-06-12T00:00:00Z",
		SessionID:      "s",
		Channel:        "claude-code",
		Tool:           EmitterTool{Name: "Read"},
		Decision:       "allowed",
		TargetSystem:   "filesystem",
		TargetResource: strings.Repeat("x", maxTargetResourceLen+1),
	}
	if err := validateFrame(f); err == nil {
		t.Error("validateFrame accepted an oversize target_resource; want rejection")
	}
}

// TestValidateFrame_RejectsHalfPopulatedTarget verifies that validateFrame rejects
// frames where only one of target_system/target_resource is set.
func TestValidateFrame_RejectsHalfPopulatedTarget(t *testing.T) {
	base := EmitterFrame{
		Version:   "1",
		TsEmit:    "2026-06-12T00:00:00Z",
		SessionID: "s",
		Channel:   "claude-code",
		Tool:      EmitterTool{Name: "Read"},
		Decision:  "allowed",
	}

	t.Run("system without resource", func(t *testing.T) {
		f := base
		f.TargetSystem = "filesystem"
		if err := validateFrame(&f); err == nil {
			t.Error("validateFrame accepted target_system without target_resource; want rejection")
		}
	})
	t.Run("resource without system", func(t *testing.T) {
		f := base
		f.TargetResource = "/etc/hosts"
		if err := validateFrame(&f); err == nil {
			t.Error("validateFrame accepted target_resource without target_system; want rejection")
		}
	})
}
