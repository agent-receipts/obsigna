# ADR-0008: Response Hashing and Chain Completeness

## Status

Accepted

## Context

Two independent gaps in the current receipt model (v0.1.0) motivate this ADR. The initial framing was that bundling them would let the protocol migrate from `0.1.0` once. Working through the chain-completeness mechanism closely (see §"Why in-chain positive commitment to successors does not work" below) narrowed which in-chain designs are actually viable: a *positive* commitment to successors ("expected length", "hash of the next receipt") reduces to a transparency-log protocol and is rejected, but a *negative* commitment — a terminal-marker flag meaning "no more receipts will follow" — is a single optional boolean with unambiguous semantics, an automatic integrity check against extension, and an opt-in affordance for verifiers that want to demand closure. The schema-bump-once rationale therefore holds for that one mechanism, alongside an out-of-band verifier parameter for the general open-ended case.

**Gap 1 — Receipts hash the request but not the response (#153).** The `credentialSubject.action.parameters_hash` field (see spec §4.3.2, [agent-receipt.schema.json#L158](../../spec/schema/agent-receipt.schema.json#L158)) captures what the agent asked. The `outcome` block captures status and result metadata but not a cryptographic commitment to the server's response body. A compromised MCP server, a tampering proxy, or an incident investigator cannot distinguish a legitimate response from a modified one from the receipt alone. The receipt chain proves intent but not outcome.

**Gap 2 — Chain verification does not detect tail truncation (#171).** The SDK verifiers in [sdk/go/receipt/chain.go](../../sdk/go/receipt/chain.go), [sdk/ts/src/receipt/chain.ts](../../sdk/ts/src/receipt/chain.ts), and [sdk/py/src/agent_receipts/receipt/chain.py](../../sdk/py/src/agent_receipts/receipt/chain.py) check signatures, hash linkage, and strict sequence increment. Dropping the last N receipts from a chain still verifies as `Valid: true` because there is no anchor for "this chain is complete". Mid-chain deletion is caught; tail truncation is not.

### Why in-chain positive commitment to successors does not work

Before enumerating options, a cryptographic floor: no in-chain field that makes a *positive* claim about future receipts — their count, their hashes, their Merkle root — can detect truncation, because the issuer does not know at signing time what those successors will be. A receipt can only commit to values its issuer already knows.

| What an in-chain field could positively commit to | Detects tail truncation? |
|---|---|
| "Current length at this receipt" | No — equivalent to `sequence`, already present |
| "Expected final length" | Only if the issuer knows its end state at sign time, which open-ended agents do not |
| "Hash of final receipt" | Same constraint — unknowable mid-chain |
| "Hash of the next receipt" | Requires delaying signing until the next action is chosen; still leaves the last signed receipt unprotected |
| Merkle accumulator of prior receipts | Detects prior-receipt deletion (already covered by hash chaining); does nothing for the tail |

A *negative* commitment — "no more receipts will follow this one" — sits outside the floor. The issuer always knows whether it intends to close the chain at the receipt it is currently signing. This is the category Option D belongs to: the issuer makes a one-bit closure claim, and verifiers enforce it by rejecting any later receipt that points back at a terminal predecessor. Terminal does not detect truncation of an open (non-terminal) chain, and it does not detect truncation of a chain where the terminal receipt itself was dropped — neither can be detected in-chain, which is exactly the floor above.

The mechanisms adopted in this ADR are therefore: (a) an external witness supplied at verification time (`ExpectedLength` / `ExpectedFinalHash`), which handles the open-ended case — the only way to detect truncation of a chain that was never closed; and (b) a negative in-chain commitment (`chain.terminal: true`), which handles the close-cleanly case — automatic rejection of extension past closure, plus an opt-in `RequireTerminal` verifier parameter for callers that want to demand closure. Anything in-chain that goes beyond these is effectively a transparency-log protocol — substantially larger than a single field, deferred to a future ADR if a real deployment needs it.

Absence of a terminal marker is not an error — it simply means "no claim", identical to today's behaviour. A verifier that does not set `RequireTerminal` treats a non-terminal tail as it does today.

### Options considered

- **Option A: Documentation-only (the minimal #171).** Update the spec §7.3 to state explicitly that chain verification does not detect tail truncation, mirror that language in the three SDK verifier docstrings, and add per-SDK tests that pin `Valid: true` for a truncated chain so future maintainers cannot silently tighten verification without a spec change. No schema change. Honest about current behaviour but provides no mitigation on its own.

- **Option B: Out-of-band commitment (verifier parameters).** Extend each SDK's `VerifyChain` API with optional `ExpectedLength` and/or `ExpectedFinalHash` parameters. Callers who know — through an external mechanism such as an audit log, a signed checkpoint, or a published transparency record — what the chain's final state should be, pass that in and the verifier fails if the observed chain does not match. No schema change; no per-receipt overhead. The cost is pushed to the caller: they must obtain the expected value out of band. This is the only mechanism that actually works for open-ended chains, and it composes cleanly with Option A (callers who cannot supply external state still get the `Valid: true` signal today, but now with documented caveats).

- **Option C (rejected): In-chain length commitment schema field.** An earlier draft of this ADR proposed adding an optional `credentialSubject.chain.length_commitment` field signed into each receipt. On closer analysis, see the table above: every concrete interpretation of such a field either duplicates `sequence`, requires knowledge the issuer does not have, or reduces to a transparency-log protocol. The ADR rejects this option as security theatre. If in-chain truncation detection is pursued in the future, it needs a purpose-designed ADR covering checkpoint receipts, external anchoring, and the accompanying verifier state — not a single hand-wavy field.

- **Option D: Terminal-marker receipt.** Add an optional `chain.terminal: true` flag to mark the final receipt in a chain. This is a positive claim, not a required one: its presence means the issuer asserts the chain ends here; its absence means no claim (same as today). Schema-restricted to the constant `true` or absent — `false` is disallowed to avoid canonicalization/signature ambiguity between two "no claim" forms. Verifiers gain one integrity check — if receipt N has `terminal: true`, no receipt with `previous_receipt_hash` pointing at N may exist — and one opt-in API affordance — callers can pass `RequireTerminal` and fail verification when closure is required. The integrity check runs automatically; the truncation-detection aspect requires caller discipline on the `RequireTerminal` side, same as Option B. Chains that crash, are killed, or are long-running simply never emit a terminal and are no worse off than today. Pairs cleanly with the `0.2.0` schema bump motivated by §1.

Related: #153, #171, spec §7.3 (chain integrity verification), spec §9.3 (open question on receipt tampering), ADR-0002 (RFC 8785 canonicalization), ADR-0003 (VC envelope format).

## Decision

*All four sub-decisions below are concrete and intended for immediate implementation. The open questions listed at the end are for community input on details, not on the overall shape.*

The release that closes #153 and #171 ships four things together:

1. §1 — response hashing (schema change, `0.2.0`).
2. §2 — Option A: documentation + pinning tests for chain truncation (no schema change).
3. §3 — Option B: optional verifier parameters for out-of-band truncation detection (no schema change).
4. §4 — Option D: terminal-marker field on the final receipt (schema change, shares the `0.2.0` bump with §1).

Option C (in-chain length-commitment field) is rejected as security theatre — see Context §"Options considered". Transparency-log-style checkpointing remains deferred to a future ADR.

> **Anchoring freeze (added by the checkpoint-anchor spike, #600).** Receipts MUST NOT carry an anchor reference; anchoring is out-of-band by design — same rationale as the issuer-DID and `/context/v1` freezes. The signed checkpoint that realises Option B's "out-of-band commitment" (see §3) is a separate, additive artifact emitted to a pluggable multi-sink anchor; it never touches the receipt schema, the hash chain, `@context`, or the issuer DID. If closing the truncation gap appears to require an in-receipt anchor field, the design is wrong — the freeze does not move.

### 1. Response hashing (from #153)

Add an optional field `credentialSubject.outcome.response_hash` containing the SHA-256 hash of the RFC 8785 canonical JSON of the server's response, computed **after** secret redaction.

- **Field name and location.** `outcome.response_hash`, same shape as the existing `parameters_hash` (`$ref: "#/$defs/sha256Hash"`).
- **Canonicalization.** RFC 8785 over the redacted response body, identical to the rules already in force for the receipt envelope (ADR-0002).
- **Ordering.** Redact → hash response → populate `outcome` → sign receipt. Non-negotiable: a hash computed before redaction does not match the record anyone can ever replay, which defeats the purpose.
- **Optional field.** Receipts without `response_hash` remain valid. Verifiers validate the hash *when present* and treat absence as "the issuer did not commit to the response"; they do not fail. This preserves backwards compatibility with `0.1.0` receipts.
- **Storage.** Hash only. Full responses are not stored in the receipt. MCP responses can be megabytes (`get_file_contents`, search results); inlining would balloon receipt size and leak data by default.
- **Verifier behaviour.** `mcp-proxy verify` and the three SDK verifiers recompute the hash when the response is available (e.g., during an integration test or a replay) and fail if it does not match. When the response is not available, they note "response hash present, response body not supplied" and continue.

Schema bumps from `0.1.0` to `0.2.0`. Verifiers must accept both.

### 2. Documentation of truncation detection limits (Option A, from #171)

Add a normative subsection to spec §7.3 stating that chain verification does not detect tail truncation. Mirror that language in the `VerifyChain` godoc, TSDoc, and docstring in the three SDKs. Add a test per SDK that constructs a chain, drops the last N receipts, and asserts the result is still `Valid: true`. These tests pin the property so a future maintainer cannot silently tighten verification without a spec change and ADR update.

This is no-cost honesty about the current guarantee and a necessary precondition for §3 — callers cannot reason about the out-of-band verifier parameters without understanding why they exist.

### 3. Out-of-band truncation detection (Option B, from #171 follow-up)

Extend each SDK's chain-verification API with optional parameters:

- `ExpectedLength` (integer) — if supplied, verification fails when the observed chain length does not equal this value.
- `ExpectedFinalHash` (hash) — if supplied, verification fails when the hash of the last observed receipt does not equal this value.

Both parameters are optional and default to unset (current behaviour). No schema change. Callers who maintain an external record of chain state (audit log, transparency log, signed checkpoint) can pass these in and detect truncation; callers who do not are no worse off than today.

The exact parameter names and idiomatic surface differ per SDK (`ExpectedLength`/`ExpectedFinalHash` in Go; `expectedLength`/`expectedFinalHash` options object in TS; `expected_length=`/`expected_final_hash=` kwargs in Python) but the semantics are shared and covered by cross-SDK test vectors.

This is the concrete mitigation the original #171 follow-up gestured at, landed now.

### 4. Terminal-marker receipt (Option D)

Add an optional field `credentialSubject.chain.terminal` to the receipt schema:

- **Field name and location.** `chain.terminal`, optional. Schema-level type: the constant `true` (`"enum": [true]` or equivalent). The field is either present with value `true` or omitted entirely; explicit `false` is **not** a valid value. This avoids a canonicalization ambiguity: `{"terminal": false}` and `{}` produce different RFC 8785 canonical forms and therefore different signatures, so allowing both would fragment what is supposed to be a single "no claim" state. Omission is the only way to express "no claim".
- **Issuer guidance.** Issuers with a defined chain lifecycle — single-task agents, CLI tools on normal exit, workflow-bound MCP proxies — set `terminal: true` on the last receipt they emit. Open-ended agents simply never set it. The issuer is not required to predict closure at arbitrary mid-chain points.
- **Verifier behaviour (new integrity check, automatic).** If any receipt R(i) in the verified input has `terminal: true`, any receipt at position i+1 in that input fails verification with a clear error ("receipt after terminal"), regardless of caller parameters and regardless of R(i+1)'s `previous_receipt_hash`. Position-based (not hash-linkage-based): any receipt following a terminal in the verified sequence is a protocol violation. This is strictly stricter than hash-linkage detection — it also catches an attacker who appends an unrelated (non-hash-linked) receipt after a terminal. Spec §7.3.2 is the normative statement of this rule.
- **Verifier behaviour (opt-in caller affordance).** Chain-verification APIs gain an optional `RequireTerminal` / `require_terminal=True` parameter. When supplied, verification fails if the last observed receipt is not explicitly `terminal: true`. When unsupplied, default remains "no claim either way" — absence of a terminal is not a verification failure. Truncation-detection for terminal-ended chains requires callers to opt in via this parameter; without it, a truncated terminal-ended chain still verifies as `Valid: true`, exactly like any other non-terminal chain today.
- **Delegation interaction.** Delegation links (spec §7.6) are distinct from chain closure. A receipt that delegates to another chain is not automatically terminal. `terminal: true` means "no more receipts on *this* chain", regardless of whether downstream delegated chains exist. A receipt may both delegate and be terminal — those are orthogonal claims.

Schema-wise this is one optional field restricted to the constant `true`, signed as part of the receipt body like any other field. Pairs with §1 in the same `0.2.0` bump.

### Open questions for community input

- **Does response hashing need to be mandatory at some future version?** Leaving it optional forever weakens the guarantee for compliance use cases. A future minor version could require it.
- **Redaction determinism across SDKs.** RFC 8785 is stable, but the redaction step is SDK-specific. Do all three SDKs produce byte-identical redacted responses for the same input? If not, `response_hash` verification will fail cross-SDK. This must be nailed down in the spec and covered by shared test vectors.
- **What does `response_hash` mean for streaming responses?** MCP does not currently stream tool results, but if it does in the future, hashing the full response is not possible without buffering.
- **Is there a near-term need for deeper in-chain truncation detection (transparency-log / checkpoint design)?** §3 covers callers with external state; §4 covers chains with clean closure. Chains that are open-ended *and* whose callers cannot supply external state still have no in-band detection. Before investing in a larger protocol change, we want signal on whether real deployments need it.
- **Should agents by default mark their final receipt as terminal?** An issuer-side default of "set terminal on normal shutdown" is a small behavioural commitment that would make the signal far more useful in practice. The ADR does not mandate it; SDK defaults can evolve after adoption.

## Security Considerations

### Redaction before hashing is load-bearing

If response hashing happens before secret redaction, the hash commits to a value that is never stored or shared — so verification always fails, or worse, the raw response is shipped to verifiers to make hashes match, defeating redaction. The ordering rule (redact → hash → sign) must be specified in the spec and enforced by per-SDK tests with a known secret in a known response.

### Response hash ≠ response integrity across the wire

`response_hash` commits the issuer to a particular response at the time of receipt creation. It does not protect against an attacker who controls the issuer at receipt-creation time — such an attacker can compute any hash they want. The protection is against post-hoc tampering (modified receipts, replayed responses, compromised archival storage) and against downstream parties who alter their copy of the response.

### Truncation detection has a floor

No mechanism can detect truncation of receipts that never existed. A receipt only commits to values its issuer already knows; it cannot commit to its own successors. §4's terminal marker is a negative claim ("no more will follow"), which the issuer always knows at signing time — but it only fires as a truncation detector when (a) the original chain actually ended in a terminal receipt *and* (b) the verifier opted in with `RequireTerminal`. If an attacker drops the terminal receipt itself, or drops the tail of a chain that was never closed, §4 is blind. §3 catches the open-ended case by pushing the commitment out of band. Neither mechanism helps for chains that are both open-ended and lack any external witness — the spec must state this explicitly so operators understand what the protocol does and does not guarantee.

### Terminal marker is a positive claim only

A verifier that sees a chain ending in a non-terminal receipt cannot conclude anything about completeness — the issuer may simply not have closed the chain yet, or ever. §4 only provides signal when `terminal: true` is observed (chain explicitly closed) or when a receipt is found after a prior terminal marker (protocol violation). The natural misread — "no terminal means truncated" — must be avoided in spec text and SDK docs.

### Schema version as a security signal

Bumping the schema version to `0.2.0` is itself a security communication: verifiers that see `0.1.0` receipts know the response-hashing guarantee is absent. Verifiers that see `0.2.0` receipts with a missing `response_hash` know the issuer chose not to hash the response, which may be a policy violation. The spec must make these states distinguishable and meaningful.

### Hash collisions and algorithm agility

SHA-256 is consistent with existing hashes in the schema. No algorithm change is proposed here. If a future ADR moves to SHA-3 or another family, the schema will need algorithm agility in both `parameters_hash` and `response_hash`.

## Known Risks

- **Cross-SDK hash divergence.** If the three SDKs redact responses differently, `response_hash` will not verify across implementations. This risk is elevated for responses (more variety, more nested structures) than for request parameters. Shared test vectors and a normative redaction algorithm are the mitigation.
- **Receipt size growth.** Adding one hash per receipt is negligible in bytes but normalizes the idea that receipts accumulate optional fields. The ADR should not open the door to storing the response itself; this must be explicit.
- **Migration surface area.** A `0.2.0` bump touches the spec, the JSON schema, three SDKs, the proxy verifier, examples, and any downstream tooling. A coordinated release is necessary; a staggered one will leave verifiers failing on valid receipts.
- **Option B requires caller discipline.** §3's verifier parameters only help callers who actually maintain external chain state. A caller who ignores them is no worse off than today but gains no protection. Operator guidance in the spec should explain when these parameters are expected to be supplied (e.g., any audit-trail use case with an external record should be passing `ExpectedFinalHash`).
- **Option D relies on issuer discipline.** §4 only gives signal when issuers actually mark their closed chains. Issuers that never emit `terminal: true` get nothing. The mitigation is SDK-side: make "set terminal on normal shutdown" easy or default for lifecycle-bound issuers.
- **Option D is a positive signal, not a guarantee.** A missing terminal does not mean the chain is truncated. Operators must not treat absence as a failure; only the "receipt after terminal" integrity violation is a hard error.
- **Signature change concerns.** `response_hash` and `chain.terminal` are part of the signed body. Any mismatch between what the issuer signed and what the verifier reconstructs will fail signature verification, which is correct. But it means that adding either field cannot be retrofitted to `0.1.0` receipts — the decision to hash or mark terminal must be made at receipt-creation time.

## Consequences

- Receipt schema version bumps from `0.1.0` to `0.2.0`. Verifiers must accept both; issuers may emit either, with clear guidance to prefer `0.2.0`.
- Spec §4.3.2 (`credentialSubject` — `outcome` sub-field) must be updated to describe `response_hash`, the ordering rule, and the verifier's handling of a missing field.
- Spec §4.3.2 (`credentialSubject` — `chain` sub-field) must be updated to describe `chain.terminal`, its schema restriction (constant `true` or absent; explicit `false` not allowed), its semantics (positive claim only), and the new "receipt after terminal" integrity rule.
- Spec §7.3 (chain integrity verification) must gain a subsection stating that chain verification does not detect tail truncation by default, document the `ExpectedLength` / `ExpectedFinalHash` verifier parameters as the out-of-band mitigation, and document `terminal` + `RequireTerminal` as the in-band mitigation for chains with clean closure.
- All three SDKs must implement (a) response hashing on the issuer side and verification on the verifier side, (b) the optional `ExpectedLength` / `ExpectedFinalHash` verifier parameters, (c) setting `chain.terminal` on the issuer side when the caller indicates chain closure, and (d) the "receipt after terminal" integrity check plus the optional `RequireTerminal` verifier parameter. Shared test vectors in `sdk/shared-test-vectors/` (or equivalent) enforce cross-SDK interop in CI.
- Each SDK gains tests for: `Valid: true` for a tail-truncated chain when no expected length/hash/terminal requirement is supplied; `Valid: false` when `ExpectedLength`/`ExpectedFinalHash` is supplied and does not match; terminal marker round-trip; `Valid: false` for any receipt that follows a terminal predecessor in the verified input sequence (position-based); `Valid: false` when `RequireTerminal` is set but the chain does not end in a terminal receipt.
- `mcp-proxy verify` must validate `response_hash` when present, enforce the "receipt after terminal" rule, and emit a clear diagnostic when the response body is not available for recomputation.
- New examples in `spec/examples/` demonstrating a `0.2.0` receipt with `response_hash` and a chain that ends with `chain.terminal: true`. Existing `0.1.0` examples are retained to document backwards compatibility.
- Migration notes in `spec/CHANGELOG.md` and a top-level upgrade section in the spec.
- Implementation should land as a single coordinated change across spec, schema, three SDKs, proxy, examples, and changelog, to avoid a window where the schema says one thing and the code says another.
- Option C (in-chain length commitment) is explicitly rejected. If deeper in-chain detection is pursued later, that work starts with a new ADR covering checkpoint semantics, verifier state, and any transparency-log coupling — not a bare schema field.

---

*Source: planning for #153 + #171, April 2026.*
