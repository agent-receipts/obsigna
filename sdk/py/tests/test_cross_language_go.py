"""Cross-language compatibility tests: Go SDK.

Verifies that the Python SDK can verify receipts signed by the Go SDK
and produces identical canonicalization and hashing outputs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from obsigna.receipt.chain import verify_chain
from obsigna.receipt.hash import (
    _strip_optional_nulls,
    canonicalize,
    hash_receipt,
    sha256,
)
from obsigna.receipt.signing import generate_key_pair, verify_receipt
from obsigna.receipt.types import AgentReceipt

VECTORS = (
    Path(__file__).parent.parent.parent.parent / "cross-sdk-tests" / "go_vectors.json"
)

V020_VECTORS = (
    Path(__file__).parent.parent.parent.parent / "cross-sdk-tests" / "v020_vectors.json"
)


def _load_vectors() -> dict:
    with open(VECTORS) as f:
        return json.load(f)


def _load_v020_vectors() -> dict:
    with open(V020_VECTORS) as f:
        return json.load(f)


class TestCanonicalizeMatchesGo:
    """Verify RFC 8785 canonicalization matches Go SDK output."""

    def test_simple_object(self) -> None:
        vectors = _load_vectors()
        input_data = vectors["canonicalization"]["simpleInput"]
        expected = vectors["canonicalization"]["simpleExpected"]
        assert canonicalize(input_data) == expected

    def test_unsigned_receipt(self) -> None:
        vectors = _load_vectors()
        input_data = vectors["canonicalization"]["receiptInput"]
        expected = vectors["canonicalization"]["receiptExpected"]
        assert canonicalize(input_data) == expected


class TestSha256MatchesGo:
    """Verify SHA-256 hashing matches Go SDK output."""

    def test_simple_string(self) -> None:
        vectors = _load_vectors()
        input_data = vectors["hashing"]["simpleInput"]
        expected = vectors["hashing"]["simpleExpected"]
        assert sha256(input_data) == expected

    def test_receipt_hash(self) -> None:
        vectors = _load_vectors()
        signed_data = vectors["signing"]["signed"]
        expected_hash = vectors["hashing"]["receiptExpected"]
        receipt = AgentReceipt(**signed_data)
        assert hash_receipt(receipt) == expected_hash


class TestVerifyGoSignature:
    """Verify that receipts signed by the Go SDK verify in Python."""

    def test_go_signature_verifies(self) -> None:
        vectors = _load_vectors()
        signed_data = vectors["signing"]["signed"]
        public_key = vectors["keys"]["publicKey"]
        receipt = AgentReceipt(**signed_data)
        assert verify_receipt(receipt, public_key) is True

    def test_go_signature_fails_with_wrong_key(self) -> None:
        vectors = _load_vectors()
        signed_data = vectors["signing"]["signed"]
        receipt = AgentReceipt(**signed_data)
        other_keys = generate_key_pair()
        assert verify_receipt(receipt, other_keys.public_key) is False

    def test_go_signature_fails_when_tampered(self) -> None:
        vectors = _load_vectors()
        signed_data = vectors["signing"]["signed"]
        public_key = vectors["keys"]["publicKey"]
        receipt = AgentReceipt(**signed_data)
        receipt.credentialSubject.action.type = "filesystem.file.delete"
        assert verify_receipt(receipt, public_key) is False


class TestV020Vectors:
    """ADR-0008 cross-SDK vectors: response_hash and chain.terminal."""

    def test_response_hash_matches_go(self) -> None:
        """Python canonicalize+sha256 of redacted response matches Go."""
        vectors = _load_v020_vectors()
        redacted = vectors["responseHash"]["redactedResponse"]
        expected = vectors["responseHash"]["expectedHash"]
        assert sha256(canonicalize(redacted)) == expected

    def test_terminal_chain_verifies(self) -> None:
        """Go-signed terminal chain verifies in Python."""
        vectors = _load_v020_vectors()
        public_key = vectors["keys"]["publicKey"]
        receipts = [AgentReceipt(**r) for r in vectors["terminalChain"]["receipts"]]

        result = verify_chain(receipts, public_key)
        assert result.valid is True

    def test_terminal_chain_with_require_terminal(self) -> None:
        """Go-signed terminal chain passes require_terminal in Python."""
        vectors = _load_v020_vectors()
        public_key = vectors["keys"]["publicKey"]
        receipts = [AgentReceipt(**r) for r in vectors["terminalChain"]["receipts"]]

        result = verify_chain(receipts, public_key, require_terminal=True)
        assert result.valid is True

    def test_last_receipt_has_terminal_true(self) -> None:
        """Terminal marker is set on the last receipt in the Go-generated chain."""
        vectors = _load_v020_vectors()
        receipts = [AgentReceipt(**r) for r in vectors["terminalChain"]["receipts"]]
        assert receipts[-1].credentialSubject.chain.terminal is True

    def test_parameters_disclosure_receipt_verifies(self) -> None:
        """Go-signed legacy v0.2.x parameters_disclosure (flat-map) receipt
        verifies via raw-dict path.

        After v0.3.0 the typed AgentReceipt model no longer accepts the legacy
        flat-map ``parameters_disclosure`` shape, so we verify the Ed25519
        signature inline against the canonical-JSON-without-proof rather than
        round-tripping through Pydantic. This preserves the cross-SDK
        signature-compatibility guarantee for historical receipts.
        """
        import base64

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        vectors = _load_v020_vectors()
        public_key_pem = vectors["keys"]["publicKey"]
        section = vectors["parametersDisclosureReceipt"]
        receipt: dict[str, Any] = dict(section["receipt"])

        proof = receipt.pop("proof")
        proof_value = proof["proofValue"]
        assert proof_value.startswith("u")
        sig_b64 = proof_value[1:]
        sig_b64 += "=" * ((4 - len(sig_b64) % 4) % 4)
        signature = base64.urlsafe_b64decode(sig_b64)

        # Mirror verify_receipt: strip null optional fields (ADR-0009 Rule 2)
        # and re-insert the required-nullable previous_receipt_hash, so the
        # canonical bytes match what the production verify path would feed
        # into Ed25519. Without this, a future v0.2.x vector with an explicit
        # null on any optional field would diverge silently.
        stripped: dict[str, Any] = _strip_optional_nulls(receipt)
        cs: dict[str, Any] = stripped.setdefault("credentialSubject", {})
        chain: dict[str, Any] = cs.setdefault("chain", {})
        if "previous_receipt_hash" not in chain:
            chain["previous_receipt_hash"] = None

        canonical = canonicalize(stripped).encode("utf-8")
        key = load_pem_public_key(public_key_pem.encode("ascii"))
        assert isinstance(key, Ed25519PublicKey)
        verified = True
        try:
            key.verify(signature, canonical)
        except InvalidSignature:
            verified = False
        assert verified, "Go-signed v0.2.x receipt failed Ed25519 verify"

    def test_parameters_disclosure_receipt_hash_matches_go(self) -> None:
        """Python hash_receipt(dict) matches the Go-computed expectedReceiptHash
        for the legacy v0.2.x flat-map shape (bypasses AgentReceipt model, which
        only accepts the v0.3.0 envelope shape going forward)."""
        vectors = _load_v020_vectors()
        section = vectors["parametersDisclosureReceipt"]
        assert hash_receipt(section["receipt"]) == section["expectedReceiptHash"]


MALFORMED_VECTORS = (
    Path(__file__).parent.parent.parent.parent
    / "cross-sdk-tests"
    / "malformed_vectors.json"
)


def _load_malformed_vectors() -> dict:
    with open(MALFORMED_VECTORS) as f:
        return json.load(f)


def _verify_or_false(receipt_dict: dict, public_key: str) -> bool:
    """Run verify_receipt, treating any pydantic/verify failure as rejection.

    The malformed corpus intentionally contains shapes that may fail at parse
    time in some SDKs and at verify time in others — both outcomes count as
    "the SDK refused to accept this receipt".
    """
    try:
        receipt = AgentReceipt(**receipt_dict)
    except Exception:  # noqa: BLE001 — any parse failure = rejection
        return False
    try:
        return verify_receipt(receipt, public_key)
    except Exception:  # noqa: BLE001 — any verify-time error = rejection
        return False


class TestMalformedReceiptsRejected:
    """Every malformed receipt in the shared corpus must fail verification."""

    def test_corpus_is_present(self) -> None:
        v = _load_malformed_vectors()
        assert v["receipts"], "malformed_vectors.json has no receipt cases"

    def test_each_receipt_case_fails(self) -> None:
        v = _load_malformed_vectors()
        public_key = v["keys"]["publicKey"]
        accepted = [
            case["name"]
            for case in v["receipts"]
            if _verify_or_false(case["receipt"], public_key)
        ]
        assert not accepted, f"Python accepted malformed cases: {accepted}"


class TestMalformedChainsRejected:
    """Every malformed chain in the shared corpus must fail chain verify."""

    def test_each_chain_case_fails(self) -> None:
        v = _load_malformed_vectors()
        public_key = v["keys"]["publicKey"]
        accepted = []
        for case in v["chains"]:
            try:
                receipts = [AgentReceipt(**r) for r in case["receipts"]]
            except Exception:  # noqa: BLE001
                continue  # parse-time rejection counts
            result = verify_chain(receipts, public_key)
            if result.valid:
                accepted.append(case["name"])
        assert not accepted, f"Python accepted malformed chains: {accepted}"
