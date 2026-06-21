//go:build integration && (linux || darwin)

package daemon

import (
	"encoding/json"
	"sort"
	"sync"
	"testing"
	"time"

	"obsigna.dev/sdk/go/emitter"
	"obsigna.dev/sdk/go/receipt"
)

// TestMCPProxyActionType verifies that a frame with channel="mcp_proxy" and
// tool.server="github" produces an action.type of "mcp_proxy.github.list_repos".
func TestMCPProxyActionType(t *testing.T) {
	fix := StartDaemon(t)

	sessionID := "mcp-proxy-test"
	if err := fix.EmitGoFrame(t, sessionID, "mcp_proxy", "list_repos", "github", "allowed"); err != nil {
		t.Fatalf("emit failed: %v", err)
	}

	receipts := fix.WaitForReceiptCount(t, 1, 5*time.Second)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}

	r := receipts[0]

	// Verify action.type is the three-part form
	if r.CredentialSubject.Action.Type != "mcp_proxy.github.list_repos" {
		t.Errorf("action.type = %q, want %q",
			r.CredentialSubject.Action.Type, "mcp_proxy.github.list_repos")
	}

	// Verify tool_name is the short form (not the three-part type)
	if r.CredentialSubject.Action.ToolName != "list_repos" {
		t.Errorf("action.tool_name = %q, want %q",
			r.CredentialSubject.Action.ToolName, "list_repos")
	}

	// Verify signature
	ok, err := receipt.Verify(r, fix.PublicKey)
	if !ok || err != nil {
		t.Errorf("verify failed: ok=%v err=%v", ok, err)
	}
}

// TestMCPProxyWithInputOutput verifies that mcp_proxy frames with input and
// output payloads produce correct hash fields in the receipt.
func TestMCPProxyWithInputOutput(t *testing.T) {
	fix := StartDaemon(t)

	sessionID := "mcp-proxy-io-test"

	// Create input and output payloads
	inputData := json.RawMessage(`{"owner":"anthropic","repo":"sdk-ts"}`)
	outputData := json.RawMessage(`{"total_count":1000,"repositories":[{"name":"sdk-ts"}]}`)

	// Use the full Event struct to test with input/output
	event := emitter.Event{
		Channel: "mcp_proxy",
		Tool: emitter.Tool{
			Name:   "list_repos",
			Server: "github",
		},
		Input:    inputData,
		Output:   outputData,
		Decision: "allowed",
	}

	if err := fix.EmitGoFrameFull(t, sessionID, event); err != nil {
		t.Fatalf("emit failed: %v", err)
	}

	receipts := fix.WaitForReceiptCount(t, 1, 5*time.Second)
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}

	r := receipts[0]

	// Compute expected hashes using RFC 8785 canonical JSON
	var inputMap interface{}
	if err := json.Unmarshal(inputData, &inputMap); err != nil {
		t.Fatalf("unmarshal input: %v", err)
	}
	expectedInputCanonical, err := receipt.Canonicalize(inputMap)
	if err != nil {
		t.Fatalf("canonicalize input: %v", err)
	}
	expectedInputHash := receipt.SHA256Hash(expectedInputCanonical)

	var outputMap interface{}
	if err := json.Unmarshal(outputData, &outputMap); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	expectedOutputCanonical, err := receipt.Canonicalize(outputMap)
	if err != nil {
		t.Fatalf("canonicalize output: %v", err)
	}
	expectedOutputHash := receipt.SHA256Hash(expectedOutputCanonical)

	// Verify parameters_hash matches expected hash
	if r.CredentialSubject.Action.ParametersHash != expectedInputHash {
		t.Errorf("parameters_hash mismatch: got %s, want %s",
			r.CredentialSubject.Action.ParametersHash, expectedInputHash)
	}

	// Verify response_hash matches expected hash (on Outcome, not Action)
	if r.CredentialSubject.Outcome.ResponseHash != expectedOutputHash {
		t.Errorf("response_hash mismatch: got %s, want %s",
			r.CredentialSubject.Outcome.ResponseHash, expectedOutputHash)
	}

	// Hashes should be different (different payloads)
	if expectedInputHash == expectedOutputHash {
		t.Errorf("input and output hashes should differ")
	}

	// Verify signature
	ok, err := receipt.Verify(r, fix.PublicKey)
	if !ok || err != nil {
		t.Errorf("verify failed: ok=%v err=%v", ok, err)
	}
}

// TestMCPProxyConcurrentWithSDKEmitters verifies that frames from mcp_proxy
// and sdk channels can be interleaved and result in a contiguous chain.
func TestMCPProxyConcurrentWithSDKEmitters(t *testing.T) {
	fix := StartDaemon(t)

	sessionID := "mixed-channels"

	// 2 goroutines emit mcp_proxy frames, 2 emit sdk frames, 10 each = 40 total
	errCh := make(chan error, 4)
	var wg sync.WaitGroup

	// 2 mcp_proxy emitters
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(_ int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				err := fix.EmitGoFrame(t, sessionID, "mcp_proxy", "tool_a", "server_x", "allowed")
				if err != nil {
					errCh <- err
					return
				}
			}
			errCh <- nil
		}(g)
	}

	// 2 sdk emitters
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(goroutine int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				err := fix.EmitGoFrame(t, sessionID, "sdk", "tool_b", "", "allowed")
				if err != nil {
					errCh <- err
					return
				}
			}
			errCh <- nil
		}(g)
	}

	// Wait for all emitters to finish
	wg.Wait()
	for i := 0; i < 4; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("emitter goroutine failed: %v", err)
		}
	}

	// Wait for all 40 receipts
	receipts := fix.WaitForReceiptCount(t, 40, 10*time.Second)
	if len(receipts) != 40 {
		t.Fatalf("expected 40 receipts, got %d\ntrace:\n%s",
			len(receipts), fix.Trace())
	}

	// Sort by sequence
	sort.Slice(receipts, func(i, j int) bool {
		return receipts[i].CredentialSubject.Chain.Sequence <
			receipts[j].CredentialSubject.Chain.Sequence
	})

	// Verify contiguity
	for i := 0; i < len(receipts); i++ {
		if receipts[i].CredentialSubject.Chain.Sequence != i+1 {
			t.Errorf("sequence gap at index %d: got seq %d, want %d",
				i, receipts[i].CredentialSubject.Chain.Sequence, i+1)
		}
	}

	// Verify signatures
	for i, r := range receipts {
		ok, err := receipt.Verify(r, fix.PublicKey)
		if !ok || err != nil {
			t.Errorf("receipt %d verify failed: ok=%v err=%v", i, ok, err)
		}
	}

	// Verify prev_hash chain
	for i := 1; i < len(receipts); i++ {
		expectedHash, err := receipt.HashReceipt(receipts[i-1])
		if err != nil {
			t.Errorf("hash receipt %d: %v", i-1, err)
			continue
		}
		actualHash := receipts[i].CredentialSubject.Chain.PreviousReceiptHash
		if actualHash == nil {
			t.Errorf("prev_hash is nil at seq %d, expected hash value", i+1)
		} else if expectedHash != *actualHash {
			t.Errorf("prev_hash mismatch at seq %d: expected %s, got %s",
				i+1, expectedHash, *actualHash)
		}
	}

	// Verify action.type patterns
	mcp_proxyCount := 0
	sdkCount := 0
	for _, r := range receipts {
		if r.CredentialSubject.Action.Type == "mcp_proxy.server_x.tool_a" {
			mcp_proxyCount++
		} else if r.CredentialSubject.Action.Type == "sdk.tool_b" {
			sdkCount++
		} else {
			t.Errorf("unexpected action.type: %q", r.CredentialSubject.Action.Type)
		}
	}

	if mcp_proxyCount != 20 {
		t.Errorf("expected 20 mcp_proxy receipts, got %d", mcp_proxyCount)
	}
	if sdkCount != 20 {
		t.Errorf("expected 20 sdk receipts, got %d", sdkCount)
	}
}
