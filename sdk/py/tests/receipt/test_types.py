"""Tests for receipt types and constants."""

import pytest
from pydantic import ValidationError

from obsigna.receipt.hash import hash_receipt
from obsigna.receipt.types import (
    CONTEXT,
    CREDENTIAL_TYPE,
    VERSION,
    AgentReceipt,
    EmitterMetadata,
    PeerCredential,
)
from tests.conftest import make_receipt, make_unsigned


class TestConstants:
    def test_context_has_two_entries(self) -> None:
        assert len(CONTEXT) == 2

    def test_context_starts_with_w3c(self) -> None:
        assert CONTEXT[0] == "https://www.w3.org/ns/credentials/v2"

    def test_context_includes_agent_receipts_uri(self) -> None:
        assert CONTEXT[1] == "https://agentreceipts.ai/context/v2"

    def test_credential_type_has_two_entries(self) -> None:
        assert len(CREDENTIAL_TYPE) == 2

    def test_credential_type_includes_verifiable_credential(self) -> None:
        assert "VerifiableCredential" in CREDENTIAL_TYPE

    def test_credential_type_includes_agent_receipt(self) -> None:
        assert "AgentReceipt" in CREDENTIAL_TYPE

    def test_version(self) -> None:
        assert VERSION == "0.5.0"


class TestAgentReceipt:
    def test_make_receipt_creates_valid_receipt(self) -> None:
        receipt = make_receipt()
        assert receipt.id == "urn:receipt:test-1"
        assert receipt.proof.proofValue == "utest"

    def test_receipt_has_context(self) -> None:
        receipt = make_receipt()
        assert receipt.context == list(CONTEXT)

    def test_receipt_has_credential_type(self) -> None:
        receipt = make_receipt()
        assert receipt.type == list(CREDENTIAL_TYPE)


class TestUnsignedAgentReceipt:
    def test_make_unsigned_has_no_proof(self) -> None:
        unsigned = make_unsigned(1, None)
        assert not hasattr(unsigned, "proof") or "proof" not in unsigned.model_fields

    def test_unsigned_has_correct_id(self) -> None:
        unsigned = make_unsigned(1, None)
        assert unsigned.id == "urn:receipt:chain_test-1"

    def test_unsigned_has_correct_chain(self) -> None:
        unsigned = make_unsigned(1, None)
        assert unsigned.credentialSubject.chain.sequence == 1
        assert unsigned.credentialSubject.chain.previous_receipt_hash is None


def _sample_envelope() -> dict:
    """A valid v1 HPKE envelope shape suitable for round-trip / hashing tests.

    The cryptographic bytes are placeholders that satisfy the schema's length /
    alphabet constraints; tests here exercise shape only, not encryption.
    """
    return {
        "v": "1",
        "alg": "hpke-x25519-hkdf-sha256-aes-256-gcm",
        "recipients": [{"kid": "did:key:test#enc-1", "enc": "A" * 43}],
        "ct": "B" * 24,
    }


class TestParametersDisclosure:
    """Round-trip tests for the optional Action.parameters_disclosure field
    (v0.3.0+ HPKE envelope shape; legacy flat-map is no longer SDK-supported)."""

    def test_default_is_none(self) -> None:
        receipt = make_receipt()
        assert receipt.credentialSubject.action.parameters_disclosure is None

    def test_round_trip_serialise_deserialise(self) -> None:
        receipt = make_receipt()
        envelope = _sample_envelope()
        receipt.credentialSubject.action.parameters_disclosure = envelope

        dumped = receipt.model_dump(by_alias=True)
        action_dict = dumped["credentialSubject"]["action"]
        assert action_dict["parameters_disclosure"] == envelope

        restored = AgentReceipt.model_validate(dumped)
        assert restored.credentialSubject.action.parameters_disclosure == envelope

    def test_included_in_canonical_hash_when_present(self) -> None:
        """Setting parameters_disclosure must change the canonical hash."""
        baseline = make_receipt()
        baseline_hash = hash_receipt(baseline)

        with_disclosure = make_receipt()
        with_disclosure.credentialSubject.action.parameters_disclosure = (
            _sample_envelope()
        )
        disclosure_hash = hash_receipt(with_disclosure)

        assert baseline_hash != disclosure_hash

    def test_omitted_from_canonical_hash_when_none(self) -> None:
        """Explicit null and omitted parameters_disclosure hash identically."""
        with_null = make_receipt().model_dump(by_alias=True)
        with_null["credentialSubject"]["action"]["parameters_disclosure"] = None

        omitted = make_receipt().model_dump(by_alias=True)
        omitted["credentialSubject"]["action"].pop("parameters_disclosure", None)

        assert hash_receipt(with_null) == hash_receipt(omitted)


class TestPeerCredential:
    """Round-trip tests for the optional Action.peer_credential field (v0.3.0+)."""

    def test_default_is_none(self) -> None:
        receipt = make_receipt()
        assert receipt.credentialSubject.action.peer_credential is None

    def test_round_trip_full(self) -> None:
        """Full POSIX peer credential round-trips through serialize/deserialize."""
        receipt = make_receipt()
        receipt.credentialSubject.action.peer_credential = PeerCredential(
            platform="linux",
            pid=12345,
            uid=1000,
            gid=1000,
            exe_path="/usr/local/bin/some-tool",
        )

        dumped = receipt.model_dump(by_alias=True)
        restored = AgentReceipt.model_validate(dumped)
        pc = restored.credentialSubject.action.peer_credential
        assert pc is not None
        assert pc.platform == "linux"
        assert pc.pid == 12345
        assert pc.uid == 1000
        assert pc.gid == 1000
        assert pc.exe_path == "/usr/local/bin/some-tool"

    def test_round_trip_minimal_windows_style(self) -> None:
        """Windows-style peer credential omits uid/gid; round-trip clean."""
        receipt = make_receipt()
        receipt.credentialSubject.action.peer_credential = PeerCredential(
            platform="windows",
            pid=4242,
        )

        dumped = receipt.model_dump(by_alias=True, exclude_none=True)
        action_dict = dumped["credentialSubject"]["action"]
        assert "uid" not in action_dict["peer_credential"]
        assert "gid" not in action_dict["peer_credential"]
        assert "exe_path" not in action_dict["peer_credential"]

    def test_changes_canonical_hash(self) -> None:
        """Setting peer_credential must change the canonical hash."""
        baseline = make_receipt()
        with_pc = make_receipt()
        with_pc.credentialSubject.action.peer_credential = PeerCredential(
            platform="linux",
            pid=1,
        )
        assert hash_receipt(baseline) != hash_receipt(with_pc)


class TestEmitterMetadata:
    """Round-trip tests for the optional Action.emitter_metadata field (v0.3.0+)."""

    def test_default_is_none(self) -> None:
        receipt = make_receipt()
        assert receipt.credentialSubject.action.emitter_metadata is None

    def test_rejects_all_none_construction(self) -> None:
        # Every field on EmitterMetadata is optional, so a bare ``EmitterMetadata()``
        # would otherwise serialize to ``{}`` and perturb the canonical hash
        # (issue #509). The validator must reject this at construction time.
        with pytest.raises(ValidationError, match="requires at least one non-None"):
            EmitterMetadata()

    def test_rejects_empty_dict_deserialization(self) -> None:
        # The deserialization path must also reject ``{}`` so a JSON receipt
        # carrying ``"emitter_metadata": {}`` cannot be silently rehydrated
        # into the same hash-perturbing instance the constructor refuses.
        with pytest.raises(ValidationError, match="requires at least one non-None"):
            EmitterMetadata.model_validate({})

    def test_round_trip_drop_count(self) -> None:
        receipt = make_receipt()
        receipt.credentialSubject.action.emitter_metadata = EmitterMetadata(
            drop_count=7,
        )

        dumped = receipt.model_dump(by_alias=True)
        restored = AgentReceipt.model_validate(dumped)
        em = restored.credentialSubject.action.emitter_metadata
        assert em is not None
        assert em.drop_count == 7

    def test_changes_canonical_hash(self) -> None:
        baseline = make_receipt()
        with_em = make_receipt()
        with_em.credentialSubject.action.emitter_metadata = EmitterMetadata(
            drop_count=3,
        )
        assert hash_receipt(baseline) != hash_receipt(with_em)
