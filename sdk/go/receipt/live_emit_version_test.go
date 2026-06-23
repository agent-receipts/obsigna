package receipt

import "testing"

// liveEmitVersion is the cross-SDK invariant: every SDK's createReceipt()
// (Go: Create) MUST stamp this literal string into the receipt's `version`
// field. The Go, TS, and Python SDKs each carry their own copy of this test
// pinned to the same literal — drift in any single SDK's VERSION constant
// breaks that SDK's test in isolation, closing the gap surfaced by #512 where
// the existing v030 cross-SDK byte-identicality tests load a pre-built JSON
// fixture and never consult the SDK's VERSION constant.
const liveEmitVersion = "0.6.0"

// TestCreateStampsCrossSDKVersion asserts that Create() stamps the
// cross-SDK-agreed literal version string. This pins the SDK's Version
// constant to the value the Go/TS/Python SDKs must agree on for newly-minted
// receipts. The parallel tests in sdk/ts/src/receipt/live-emit-version.test.ts
// and sdk/py/tests/receipt/test_live_emit_version.py pin the same literal.
func TestCreateStampsCrossSDKVersion(t *testing.T) {
	r := Create(CreateInput{
		Issuer:    Issuer{ID: "did:agent:test"},
		Principal: Principal{ID: "did:user:alice"},
		Action:    Action{Type: "filesystem.file.read", RiskLevel: RiskLow},
		Outcome:   Outcome{Status: StatusSuccess},
		Chain:     Chain{Sequence: 1, ChainID: "chain-1"},
	})

	if r.Version != liveEmitVersion {
		t.Errorf("Create() stamped version %q, want cross-SDK literal %q", r.Version, liveEmitVersion)
	}
	if Version != liveEmitVersion {
		t.Errorf("package Version constant = %q, want cross-SDK literal %q", Version, liveEmitVersion)
	}
}
