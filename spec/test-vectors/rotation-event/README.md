# Rotation event test vector

A worked example of a `credentialSubject.keyRotation` receipt, pinning the
canonical wire form proposed in the
[ADR-0015 amendment](../../../docs/adr/0015-key-rotation-byok-anchoring.md#amendments).

The vector is consumed directly by each SDK's rotation tests
(`sdk/go/receipt/rotation_test.go`, `sdk/ts/src/receipt/rotation.test.ts`,
`sdk/py/tests/receipt/test_rotation.py`), which load it, verify it under the
outgoing key, and cross-check its canonical-body hash — so all three SDKs agree
on the wire form. The schema validates it via
`cross-sdk-tests/spec_schema_test.go`.

## What this vector demonstrates

- The `credentialSubject.keyRotation` field carrying the seven rotation-event
  fields named in [ADR-0015 §"Rotation event schema"](../../../docs/adr/0015-key-rotation-byok-anchoring.md#rotation-event-schema)
  (`event_type`, `new_public_key`, `old_key_fingerprint`, `new_key_fingerprint`,
  `old_algorithm`, `new_algorithm`, `signed_with`).
- A receipt body that round-trips through
  [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonicalisation
  (per [ADR-0009](../../../docs/adr/0009-canonicalization-and-schema-consistency.md))
  and is signed end-to-end with the *outgoing* key (`signed_with: "old"`).
- All other receipt fields exactly as a `0.2.1` receipt already requires —
  this vector adds `keyRotation` and nothing else.

## Test keys

Both keys are well-known [RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1)
test vectors. They MUST NOT be used in production.

| Role | RFC 8032 vector | Public key (hex) |
|---|---|---|
| Outgoing (signs the rotation) | TEST 2 | `3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c` |
| Incoming | TEST 3 | `fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025` |

The outgoing secret seed is published at [RFC 8032 §7.1, TEST 2](https://www.rfc-editor.org/rfc/rfc8032#section-7.1).
It is **not** inlined here — even though the value is famous and public, secret-scanning
tooling commonly trips on raw seed hex regardless of provenance. Reviewers reproducing
the signature use the seed as published by the RFC.

## Chain position

The vector represents a **genesis-position** rotation: `chain.sequence = 1` and
`chain.previous_receipt_hash = null`. This is the simplest position that exercises the
`credentialSubject.keyRotation` field end-to-end without requiring a separate predecessor
receipt to be shipped alongside. A rotation at a non-genesis position would require
including the predecessor (so verifiers can recompute its `hashReceipt` and check it
matches the successor's `previous_receipt_hash`); that is deliberately out of scope for a
wire-format pin.

## Derived values (recomputable from the keys above)

- `old_key_fingerprint`: `sha256:39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f`
- `new_key_fingerprint`: `sha256:dac073e0123bdea59dd9b3bda9cf6037f63aca82627d7abcd5c4ac29dd74003e`
- `new_public_key` (multibase-`u` base64url of the 32 raw bytes — same encoding ADR-0001 defines for `proof.proofValue`, applied here to raw public-key bytes):
  `u_FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU`
- RFC 8785 canonical bytes of the receipt body (`proof` removed) hash to
  `sha256:6983c9bd6fb24e844b90f7616315a914fdedc5fef8126e11d46149ba2f320457`.
  This is the value the next receipt in the chain would carry as
  `previous_receipt_hash`.
- Ed25519 signature over those canonical bytes, signed by the outgoing key,
  base64url-encoded with the multibase `u` prefix:
  `uqwcXwDOGW3UKEMyboz6NzEHqcG7C6HdXnMJvn_wR6tsZLdH2i8zYBS-yFRAOu_6JePCJdP80E6BR41AHSi9eCw`

## Out of scope

- No daemon emission. This fixture exercises the verifier (read) side only; it
  does not cover how a daemon *produces* a `key_rotated` receipt. Offline
  emission is daemon-orchestrated via `agent-receipts-daemon --rotate` (there is
  no `KeySource.Rotate()`); this vector is silent on that path.
- No rotation event anchored to an external sink. ADR-0015 specifies that
  rotation events MUST be anchored before the local chain commits — this
  fixture is a *wire-format* vector and is silent on the anchor write contract.
