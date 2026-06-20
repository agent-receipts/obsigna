import { describe, expect, it } from "vitest";
import { createReceipt } from "./create.js";
import { VERSION } from "./types.js";

// LIVE_EMIT_VERSION is the cross-SDK invariant: every SDK's createReceipt()
// (Go: Create) MUST stamp this literal string into the receipt's `version`
// field. The Go, TS, and Python SDKs each carry their own copy of this test
// pinned to the same literal — drift in any single SDK's VERSION constant
// breaks that SDK's test in isolation, closing the gap surfaced by #512 where
// the existing v030 cross-SDK byte-identicality tests load a pre-built JSON
// fixture and never consult the SDK's VERSION constant.
const LIVE_EMIT_VERSION = "0.6.0";

describe("createReceipt cross-SDK version invariant", () => {
	it("stamps the cross-SDK literal version on freshly-emitted receipts", () => {
		const receipt = createReceipt({
			issuer: { id: "did:agent:test-agent" },
			principal: { id: "did:user:test-user" },
			action: {
				type: "filesystem.file.read",
				risk_level: "low",
			},
			outcome: { status: "success" },
			chain: {
				sequence: 1,
				previous_receipt_hash: null,
				chain_id: "chain_test",
			},
		});

		expect(receipt.version).toBe(LIVE_EMIT_VERSION);
	});

	it("keeps the exported VERSION constant aligned with the cross-SDK literal", () => {
		expect(VERSION).toBe(LIVE_EMIT_VERSION);
	});
});
