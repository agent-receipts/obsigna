"""Tests for chain verification."""

from typing import Literal
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from obsigna.receipt.chain import (
    STATUS_COMPLETE,
    STATUS_INTERRUPTED,
    STATUS_UNKNOWN,
    verify_chain,
)
from obsigna.receipt.create import (
    ActionInput,
    CreateReceiptInput,
    create_receipt,
)
from obsigna.receipt.hash import canonicalize, hash_receipt, sha256
from obsigna.receipt.signing import (
    generate_key_pair,
    sign_receipt,
    verify_receipt,
)
from obsigna.receipt.types import (
    Chain,
    Issuer,
    Outcome,
    Principal,
    UnsignedAgentReceipt,
)
from tests.conftest import TEST_PRIVATE_KEY, TEST_PUBLIC_KEY, make_unsigned


def _build_chain(count: int, private_key: str) -> list:
    """Build a signed chain of `count` receipts."""
    chain = []
    previous_hash = None
    for i in range(1, count + 1):
        unsigned = make_unsigned(i, previous_hash)
        signed = sign_receipt(unsigned, private_key, "did:agent:test#key-1")
        chain.append(signed)
        previous_hash = hash_receipt(signed)
    return chain


def _build_terminal_chain(count: int, private_key: str) -> list:
    """Build a chain of `count` receipts where the last has chain.terminal=True."""
    chain = _build_chain(count - 1, private_key)
    prev_hash = hash_receipt(chain[-1]) if chain else None
    unsigned = create_receipt(
        CreateReceiptInput(
            issuer=Issuer(id="did:agent:test"),
            principal=Principal(id="did:user:test"),
            action=ActionInput(type="filesystem.file.read", risk_level="low"),
            outcome=Outcome(status="success"),
            chain=Chain(
                sequence=count,
                previous_receipt_hash=prev_hash,
                chain_id="chain_test",
            ),
            terminal=True,
        )
    )
    signed = sign_receipt(unsigned, private_key, "did:agent:test#key-1")
    return [*chain, signed]


class TestVerifyChain:
    def test_empty_chain_is_valid(self) -> None:
        result = verify_chain([], TEST_PUBLIC_KEY)
        assert result.valid is True
        assert result.length == 0
        assert result.broken_at == -1

    def test_single_receipt_valid(self) -> None:
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        result = verify_chain([signed], TEST_PUBLIC_KEY)
        assert result.valid is True
        assert result.length == 1

    def test_three_receipt_chain(self) -> None:
        u1 = make_unsigned(1, None)
        s1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        h1 = hash_receipt(s1)

        u2 = make_unsigned(2, h1)
        s2 = sign_receipt(u2, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        h2 = hash_receipt(s2)

        u3 = make_unsigned(3, h2)
        s3 = sign_receipt(u3, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain([s1, s2, s3], TEST_PUBLIC_KEY)
        assert result.valid is True
        assert result.length == 3
        assert result.broken_at == -1

    def test_tampered_receipt_detected(self) -> None:
        u1 = make_unsigned(1, None)
        s1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        # Tamper with action type
        s1.credentialSubject.action.type = "filesystem.file.delete"

        result = verify_chain([s1], TEST_PUBLIC_KEY)
        assert result.valid is False
        assert result.broken_at == 0
        assert result.receipts[0].signature_valid is False

    def test_broken_hash_link(self) -> None:
        u1 = make_unsigned(1, None)
        s1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        fake_hash = "sha256:" + "0" * 64
        u2 = make_unsigned(2, fake_hash)
        s2 = sign_receipt(u2, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain([s1, s2], TEST_PUBLIC_KEY)
        assert result.valid is False
        assert result.broken_at == 1
        assert result.receipts[1].hash_link_valid is False

    def test_broken_sequence(self) -> None:
        u1 = make_unsigned(1, None)
        s1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        h1 = hash_receipt(s1)

        u3 = make_unsigned(3, h1)  # Skips sequence 2
        s3 = sign_receipt(u3, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain([s1, s3], TEST_PUBLIC_KEY)
        assert result.valid is False
        assert result.broken_at == 1
        assert result.receipts[1].sequence_valid is False

    def test_wrong_key_fails(self) -> None:
        u1 = make_unsigned(1, None)
        s1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        other_keys = generate_key_pair()
        result = verify_chain([s1], other_keys.public_key)
        assert result.valid is False
        assert result.receipts[0].signature_valid is False

    def test_continues_after_break(self) -> None:
        """Verification continues even after finding a broken receipt."""
        u1 = make_unsigned(1, None)
        s1 = sign_receipt(u1, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        h1 = hash_receipt(s1)

        u2 = make_unsigned(2, h1)
        s2 = sign_receipt(u2, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        # Tamper
        s2.credentialSubject.action.type = "filesystem.file.delete"
        h2 = hash_receipt(s2)

        u3 = make_unsigned(3, h2)
        s3 = sign_receipt(u3, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain([s1, s2, s3], TEST_PUBLIC_KEY)
        assert result.length == 3
        assert len(result.receipts) == 3
        assert result.broken_at == 1


class TestAdr0008ChainBehaviours:
    """ADR-0008: response_hash, chain.terminal, and truncation detection."""

    # --- truncation pin ---

    def test_truncated_chain_is_valid_without_options(self) -> None:
        """Dropping tail receipts must not break verification (pins §7.3.1)."""
        kp = generate_key_pair()
        chain = _build_chain(5, kp.private_key)
        truncated = chain[:3]

        result = verify_chain(truncated, kp.public_key)
        assert result.valid is True
        assert result.length == 3

    # --- expected_length ---

    def test_expected_length_detects_truncation(self) -> None:
        kp = generate_key_pair()
        chain = _build_chain(5, kp.private_key)
        truncated = chain[:3]

        result = verify_chain(truncated, kp.public_key, expected_length=5)
        assert result.valid is False

    def test_expected_length_passes_when_matches(self) -> None:
        kp = generate_key_pair()
        chain = _build_chain(5, kp.private_key)

        result = verify_chain(chain, kp.public_key, expected_length=5)
        assert result.valid is True

    # --- expected_final_hash ---

    def test_expected_final_hash_detects_truncation(self) -> None:
        kp = generate_key_pair()
        chain = _build_chain(5, kp.private_key)
        real_final_hash = hash_receipt(chain[-1])
        truncated = chain[:3]

        result = verify_chain(
            truncated, kp.public_key, expected_final_hash=real_final_hash
        )
        assert result.valid is False

    def test_expected_final_hash_passes_when_matches(self) -> None:
        kp = generate_key_pair()
        chain = _build_chain(5, kp.private_key)
        final_hash = hash_receipt(chain[-1])

        result = verify_chain(chain, kp.public_key, expected_final_hash=final_hash)
        assert result.valid is True

    # --- terminal round-trip ---

    def test_terminal_chain_round_trips_as_valid(self) -> None:
        kp = generate_key_pair()
        chain = _build_terminal_chain(3, kp.private_key)

        result = verify_chain(chain, kp.public_key)
        assert result.valid is True
        assert chain[-1].credentialSubject.chain.terminal is True

    # --- receipt after terminal ---

    def test_compute_error_preserved_through_terminal_check(self) -> None:
        """sig-compute error surfaces even when terminal violation also present."""
        kp = generate_key_pair()
        terminal_chain = _build_terminal_chain(2, kp.private_key)
        terminal_hash = hash_receipt(terminal_chain[-1])

        extra_unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="filesystem.file.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=3,
                    previous_receipt_hash=terminal_hash,
                    chain_id="chain_test",
                ),
            )
        )
        extra_signed = sign_receipt(
            extra_unsigned, kp.private_key, "did:agent:test#key-1"
        )
        chain = [*terminal_chain, extra_signed]
        target_id = chain[0].id
        real_verify = verify_receipt

        def raise_sig(receipt: object, key: object) -> bool:
            if getattr(receipt, "id", None) == target_id:
                raise ValueError("synthetic sig failure")
            return real_verify(receipt, key)  # type: ignore[arg-type]

        target = "obsigna.receipt.chain.verify_receipt"
        with patch(target, side_effect=raise_sig):
            result = verify_chain(chain, kp.public_key)

        assert result.valid is False
        assert "signature compute failed at index 0" in result.error

    def test_receipt_after_terminal_is_always_invalid(self) -> None:
        kp = generate_key_pair()
        terminal_chain = _build_terminal_chain(3, kp.private_key)
        terminal_hash = hash_receipt(terminal_chain[-1])

        extra_unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="filesystem.file.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=4,
                    previous_receipt_hash=terminal_hash,
                    chain_id="chain_test",
                ),
            )
        )
        extra_signed = sign_receipt(
            extra_unsigned, kp.private_key, "did:agent:test#key-1"
        )
        bad = [*terminal_chain, extra_signed]

        result = verify_chain(bad, kp.public_key)
        assert result.valid is False
        assert result.broken_at > -1

    def test_receipt_after_terminal_fires_unconditionally(self) -> None:
        """receipt-after-terminal must fire even with no caller options."""
        kp = generate_key_pair()
        terminal_chain = _build_terminal_chain(2, kp.private_key)
        terminal_hash = hash_receipt(terminal_chain[-1])

        extra_unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="filesystem.file.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=3,
                    previous_receipt_hash=terminal_hash,
                    chain_id="chain_test",
                ),
            )
        )
        extra_signed = sign_receipt(
            extra_unsigned, kp.private_key, "did:agent:test#key-1"
        )

        result = verify_chain([*terminal_chain, extra_signed], kp.public_key)
        assert result.valid is False

    # --- require_terminal ---

    def test_require_terminal_passes_when_chain_ends_in_terminal(self) -> None:
        kp = generate_key_pair()
        chain = _build_terminal_chain(3, kp.private_key)

        result = verify_chain(chain, kp.public_key, require_terminal=True)
        assert result.valid is True

    def test_require_terminal_fails_when_terminal_receipt_dropped(self) -> None:
        kp = generate_key_pair()
        chain = _build_terminal_chain(3, kp.private_key)
        truncated = chain[:2]  # drop terminal receipt

        result = verify_chain(truncated, kp.public_key, require_terminal=True)
        assert result.valid is False

    def test_require_terminal_not_set_non_terminal_is_valid(self) -> None:
        kp = generate_key_pair()
        chain = _build_chain(3, kp.private_key)

        result = verify_chain(chain, kp.public_key)  # no require_terminal
        assert result.valid is True

    # --- response_hash note ---

    def test_response_hash_note_set_when_hash_present_no_body(self) -> None:
        kp = generate_key_pair()
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="data.api.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1,
                    previous_receipt_hash=None,
                    chain_id="chain_test",
                ),
                response_body={"result": "ok"},
            )
        )
        signed = sign_receipt(unsigned, kp.private_key, "did:agent:test#key-1")

        result = verify_chain([signed], kp.public_key)
        assert result.valid is True
        assert result.response_hash_note != ""

    def test_no_response_hash_note_when_hash_absent(self) -> None:
        kp = generate_key_pair()
        chain = _build_chain(1, kp.private_key)

        result = verify_chain(chain, kp.public_key)
        assert result.valid is True
        assert result.response_hash_note == ""

    # --- create_receipt response_hash ---

    def test_create_receipt_computes_correct_response_hash(self) -> None:
        response_body = {"result": "ok", "status": 200}
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="data.api.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1,
                    previous_receipt_hash=None,
                    chain_id="chain_test",
                ),
                response_body=response_body,
            )
        )
        expected = sha256(canonicalize(response_body))
        assert unsigned.credentialSubject.outcome.response_hash == expected

    def test_redact_then_hash_ordering(self) -> None:
        """Hash must equal hash(redacted), not hash(raw)."""
        raw_response = {"result": "ok", "password": "super-secret"}
        redacted_response = {"result": "ok", "password": "[REDACTED]"}

        hash_of_redacted = sha256(canonicalize(redacted_response))
        hash_of_raw = sha256(canonicalize(raw_response))
        assert hash_of_redacted != hash_of_raw

        # Caller pre-redacts and passes redacted body.
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="data.api.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1,
                    previous_receipt_hash=None,
                    chain_id="chain_test",
                ),
                response_body=redacted_response,
            )
        )

        assert unsigned.credentialSubject.outcome.response_hash == hash_of_redacted
        assert unsigned.credentialSubject.outcome.response_hash != hash_of_raw

    # --- terminal field presence ---

    def test_no_terminal_option_field_is_absent(self) -> None:
        """When terminal is not set, chain.terminal must be absent (None)."""
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="filesystem.file.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1,
                    previous_receipt_hash=None,
                    chain_id="chain_test",
                ),
                # terminal not set (defaults to False)
            )
        )
        assert unsigned.credentialSubject.chain.terminal is None

    def test_terminal_true_emits_terminal_field(self) -> None:
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="filesystem.file.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1,
                    previous_receipt_hash=None,
                    chain_id="chain_test",
                ),
                terminal=True,
            )
        )
        assert unsigned.credentialSubject.chain.terminal is True

    # --- response_bodies verification ---

    def test_response_bodies_matching_body_passes(self) -> None:
        """When the supplied body matches the stored hash, verification passes."""
        body = {"result": "ok", "status": 200}
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="data.api.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1, previous_receipt_hash=None, chain_id="chain-rb"
                ),
                response_body=body,
            )
        )
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain(
            [signed],
            TEST_PUBLIC_KEY,
            response_bodies={signed.id: body},
        )
        assert result.valid
        assert result.response_hash_note == ""

    def test_response_bodies_mismatch_fails(self) -> None:
        """When the supplied body does not match the stored hash, verification fails."""
        good_body = {"result": "ok"}
        bad_body = {"result": "tampered"}
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="data.api.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1, previous_receipt_hash=None, chain_id="chain-mm"
                ),
                response_body=good_body,
            )
        )
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain(
            [signed],
            TEST_PUBLIC_KEY,
            response_bodies={signed.id: bad_body},
        )
        assert not result.valid
        assert "response_hash mismatch" in result.error

    # --- hash compute errors ---

    def test_hash_failure_in_loop_populates_error(self) -> None:
        """hash_receipt raising on a previous receipt surfaces as a structured error.

        Patch hash_receipt to raise ValueError on every call. The first
        patched invocation occurs when the loop computes hash_receipt(previous)
        for receipt[1], which exercises the try/except at the per-receipt
        hash-link check.  verify_receipt is unaffected because it does not call
        hash_receipt — this isolates the try/except at the per-receipt
        hash-link check in verify_chain.
        """
        kp = generate_key_pair()
        chain = _build_chain(2, kp.private_key)

        with patch(
            "obsigna.receipt.chain.hash_receipt",
            side_effect=ValueError("injected hash failure"),
        ):
            result = verify_chain(chain, kp.public_key)

        assert result.valid is False
        assert result.broken_at == 1
        assert result.error.startswith("hash compute failed at index 0:")
        assert len(result.receipts) == 2
        assert result.receipts[1].hash_link_valid is False

    def test_hash_compute_error_all_receipts_present(self) -> None:
        """hash_receipt error mid-chain: all receipts must be in the result (invariant).

        Uses a 5-receipt chain with a selective mock that only fails on receipt[0].
        Verifies iteration continues: length==5, len(receipts)==5, broken_at==1,
        and subsequent hash links (which hash receipt[1] onward) resolve normally.
        """
        kp = generate_key_pair()
        chain = _build_chain(5, kp.private_key)
        target_id = chain[0].id
        real_hash_receipt = hash_receipt

        def selective_raise(r: object) -> str:
            if getattr(r, "id", None) == target_id:
                raise ValueError("injected failure on receipt 0")
            return real_hash_receipt(r)  # type: ignore[arg-type]

        with patch(
            "obsigna.receipt.chain.hash_receipt",
            side_effect=selective_raise,
        ):
            result = verify_chain(chain, kp.public_key)

        assert result.valid is False
        assert result.broken_at == 1
        assert result.length == 5
        assert len(result.receipts) == 5
        assert result.receipts[1].hash_link_valid is False
        # Subsequent receipts: hash links resolved normally via receipt[1] onward.
        assert result.receipts[2].hash_link_valid is True

    def test_expected_final_hash_mismatch_error_message(self) -> None:
        """expected_final_hash mismatch error includes expected and computed hashes."""
        kp = generate_key_pair()
        chain = _build_chain(3, kp.private_key)
        real_final_hash = hash_receipt(chain[-1])
        wrong_hash = "sha256:" + "0" * 64

        result = verify_chain(chain, kp.public_key, expected_final_hash=wrong_hash)

        assert result.valid is False
        assert "final receipt hash mismatch at index 2" in result.error
        assert wrong_hash in result.error
        assert real_final_hash in result.error

    def test_hash_failure_in_expected_final_hash_populates_error(self) -> None:
        """hash_receipt raising on the final receipt surfaces via expected_final_hash.

        Patches hash_receipt to raise only when called on the last receipt's id,
        so the per-receipt loop succeeds (hash_receipt(previous) is called for
        earlier indices and returns normally) and the expected_final_hash branch
        triggers the new try/except.
        """
        kp = generate_key_pair()
        chain = _build_chain(2, kp.private_key)
        real_final_hash = hash_receipt(chain[-1])

        target_id = chain[-1].id
        real_hash_receipt = hash_receipt

        def selective_raise(r: object) -> str:
            if getattr(r, "id", None) == target_id:
                raise ValueError("injected hash failure on final receipt")
            return real_hash_receipt(r)  # type: ignore[arg-type]

        with patch(
            "obsigna.receipt.chain.hash_receipt",
            side_effect=selective_raise,
        ):
            result = verify_chain(
                chain,
                kp.public_key,
                expected_final_hash=real_final_hash,
            )

        assert result.valid is False
        assert result.broken_at == 1
        assert result.error.startswith("hash compute failed at index 1:")
        assert "injected hash failure" in result.error

    def test_signature_failure_in_loop_populates_error(self) -> None:
        """verify_receipt raising surfaces as a structured error.

        Patches verify_receipt to raise ValueError on every call. The
        try/except mirrors the False-return path: signature_valid is set to
        False and the loop continues, so every receipt still gets a per-receipt
        entry. ChainVerification.error captures the first failure (index 0).
        """
        kp = generate_key_pair()
        chain = _build_chain(2, kp.private_key)

        with patch(
            "obsigna.receipt.chain.verify_receipt",
            side_effect=ValueError("injected verify failure"),
        ):
            result = verify_chain(chain, kp.public_key)

        assert result.valid is False
        assert result.broken_at == 0
        assert result.error.startswith("signature compute failed at index 0:")
        assert "injected verify failure" in result.error
        # Loop continued: both receipts have entries with signature_valid=False,
        # and non-signature checks (hash_link, sequence) still ran for each.
        assert len(result.receipts) == 2
        assert result.receipts[0].signature_valid is False
        assert result.receipts[1].signature_valid is False
        assert result.receipts[0].hash_link_valid is True
        assert result.receipts[1].hash_link_valid is True

    def test_dual_error_sig_takes_precedence_over_hash_compute(self) -> None:
        """When both sig-compute and hash-compute errors occur, sig wins in cv.error."""
        kp = generate_key_pair()
        chain = _build_chain(3, kp.private_key)
        target_id = chain[0].id
        real_verify = verify_receipt
        real_hash = hash_receipt

        def raise_sig(receipt: object, key: object) -> bool:
            if getattr(receipt, "id", None) == target_id:
                raise ValueError("sig compute failure")
            return real_verify(receipt, key)  # type: ignore[arg-type]

        def raise_hash(r: object) -> str:
            if getattr(r, "id", None) == target_id:
                raise ValueError("hash compute failure")
            return real_hash(r)  # type: ignore[arg-type]

        sig_target = "obsigna.receipt.chain.verify_receipt"
        hash_target = "obsigna.receipt.chain.hash_receipt"
        with patch(sig_target, side_effect=raise_sig):
            with patch(hash_target, side_effect=raise_hash):
                result = verify_chain(chain, kp.public_key)

        assert result.valid is False
        assert "signature compute failed at index 0" in result.error
        assert "hash compute" not in result.error

    def test_terminal_violation_before_compute_error(self) -> None:
        """terminal violation (index 1) wins over compute error at later index.

        Chain: [receipt[0](terminal), receipt[1], receipt[2]]
        - terminal_violation_at = 1  (receipt[1] follows terminal receipt[0])
        - hash_compute_error_at  = 2  (hash_receipt(receipt[1]) fails when
          the loop processes receipt[2]'s link)
        Terminal violation comes first, so broken_at must be 1 and the error
        must describe the terminal violation, not the hash failure.
        """
        kp = generate_key_pair()
        # receipt[0] is the sole terminal receipt.
        terminal_chain = _build_terminal_chain(1, kp.private_key)
        terminal_hash = hash_receipt(terminal_chain[0])

        r1_unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="filesystem.file.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=2,
                    previous_receipt_hash=terminal_hash,
                    chain_id="chain_test",
                ),
            )
        )
        r1 = sign_receipt(r1_unsigned, kp.private_key, "did:agent:test#key-1")
        r1_hash = hash_receipt(r1)

        r2_unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="filesystem.file.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=3,
                    previous_receipt_hash=r1_hash,
                    chain_id="chain_test",
                ),
            )
        )
        r2 = sign_receipt(r2_unsigned, kp.private_key, "did:agent:test#key-1")

        chain = [*terminal_chain, r1, r2]

        # Inject a hash failure only on receipt[1] (r1), so the error fires
        # when the loop processes receipt[2] (loop index 2).
        target_id = r1.id
        real_hash_receipt = hash_receipt

        def selective_raise(r: object) -> str:
            if getattr(r, "id", None) == target_id:
                raise ValueError("injected hash failure on receipt 1")
            return real_hash_receipt(r)  # type: ignore[arg-type]

        with patch(
            "obsigna.receipt.chain.hash_receipt",
            side_effect=selective_raise,
        ):
            result = verify_chain(chain, kp.public_key)

        assert result.valid is False
        # Terminal violation at index 1 must be the first broken point.
        assert result.broken_at == 1
        # Terminal violation message must win because it precedes the hash error.
        assert "receipt after terminal" in result.error

    def test_response_bodies_absent_entry_emits_note(self) -> None:
        """When response_hash is present but receipt id is not in the map, emit note."""
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:test"),
                action=ActionInput(type="data.api.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1, previous_receipt_hash=None, chain_id="chain-note3"
                ),
                response_body={"result": "ok"},
            )
        )
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        result = verify_chain(
            [signed],
            TEST_PUBLIC_KEY,
            response_bodies={},  # empty map — no entry for this receipt
        )
        assert result.valid
        assert result.response_hash_note != ""


def _build_chain_with_status(
    count: int,
    private_key: str,
    status: Literal["complete", "interrupted"] | None,
) -> list:
    """Build a chain of `count` receipts; last receipt is terminal with status."""
    chain = _build_chain(count - 1, private_key)
    prev_hash = hash_receipt(chain[-1]) if chain else None
    unsigned = create_receipt(
        CreateReceiptInput(
            issuer=Issuer(id="did:agent:test"),
            principal=Principal(id="did:user:test"),
            action=ActionInput(type="filesystem.file.read", risk_level="low"),
            outcome=Outcome(status="success"),
            chain=Chain(
                sequence=count,
                previous_receipt_hash=prev_hash,
                chain_id="chain_test",
            ),
            terminal=True,
            termination_status=status,
        )
    )
    signed = sign_receipt(unsigned, private_key, "did:agent:test#key-1")
    return [*chain, signed]


class TestChainTerminationStatus:
    """Spec §7.3.3 / #475 — chain.status classification."""

    def test_terminal_no_status_classifies_as_complete(self) -> None:
        chain = _build_terminal_chain(3, TEST_PRIVATE_KEY)
        result = verify_chain(chain, TEST_PUBLIC_KEY)
        assert result.valid is True
        assert result.status == STATUS_COMPLETE
        # Wire form: no status field emitted when not explicitly set.
        assert chain[-1].credentialSubject.chain.status is None

    def test_terminal_with_status_complete(self) -> None:
        chain = _build_chain_with_status(3, TEST_PRIVATE_KEY, "complete")
        result = verify_chain(chain, TEST_PUBLIC_KEY)
        assert result.valid is True
        assert result.status == STATUS_COMPLETE
        assert chain[-1].credentialSubject.chain.status == "complete"

    def test_terminal_with_status_interrupted(self) -> None:
        chain = _build_chain_with_status(3, TEST_PRIVATE_KEY, "interrupted")
        result = verify_chain(chain, TEST_PUBLIC_KEY)
        assert result.valid is True
        assert result.status == STATUS_INTERRUPTED
        assert chain[-1].credentialSubject.chain.status == "interrupted"

    def test_non_terminal_chain_classifies_as_unknown(self) -> None:
        chain = _build_chain(3, TEST_PRIVATE_KEY)
        result = verify_chain(chain, TEST_PUBLIC_KEY)
        assert result.valid is True
        assert result.status == STATUS_UNKNOWN

    def test_empty_chain_classifies_as_unknown(self) -> None:
        result = verify_chain([], TEST_PUBLIC_KEY)
        assert result.valid is True
        assert result.length == 0
        assert result.status == STATUS_UNKNOWN

    def test_status_independent_of_validity(self) -> None:
        """Broken chain still reports termination status as claimed on the wire."""
        chain = _build_chain_with_status(3, TEST_PRIVATE_KEY, "interrupted")
        # Tamper with the middle receipt to break verification.
        chain[1].credentialSubject.action.risk_level = "critical"

        result = verify_chain(chain, TEST_PUBLIC_KEY)
        assert result.valid is False
        # Status reflects what the chain claims on the wire, not its validity.
        assert result.status == STATUS_INTERRUPTED

    def test_status_without_terminal_rejected_at_validation(self) -> None:
        """Chain validator must reject status set without terminal=True.

        Mirrors the Go SDK's verifier check on deserialized receipts:
        the "status implies terminal" invariant (spec §7.3.3) is enforced
        at model-construction time so a Chain parsed from external JSON
        cannot smuggle in a schema-invalid combination.
        """
        with pytest.raises(ValidationError, match="chain.terminal"):
            Chain(
                sequence=1,
                previous_receipt_hash=None,
                chain_id="chain-1",
                terminal=None,
                status="interrupted",
            )

    def test_serializer_drops_status_when_terminal_mutated_to_none(self) -> None:
        """Serializer is a belt-and-suspenders backup against post-validation mutation."""  # noqa: E501
        c = Chain(
            sequence=1,
            previous_receipt_hash=None,
            chain_id="chain-1",
            terminal=True,
            status="interrupted",
        )
        # Mutate after construction (bypasses validator).
        c.terminal = None
        d = c.model_dump(exclude_none=True)
        assert "terminal" not in d
        assert "status" not in d

    def test_status_preserved_when_terminal_is_true(self) -> None:
        """The serializer only drops status when terminal is unset."""
        c = Chain(
            sequence=1,
            previous_receipt_hash=None,
            chain_id="chain-1",
            terminal=True,
            status="interrupted",
        )
        d = c.model_dump(exclude_none=True)
        assert d.get("terminal") is True
        assert d.get("status") == "interrupted"


def _build_chain_with_id(
    count: int,
    private_key: str,
    chain_id: str,
    start_sequence: int = 1,
    start_previous_hash: str | None = None,
) -> list:
    """Build a signed chain of `count` receipts under a given chain_id.

    Lets tests construct cross-chain splices by starting from an arbitrary
    sequence number and previous_receipt_hash.
    """
    chain = []
    previous_hash = start_previous_hash
    for i in range(count):
        seq = start_sequence + i
        unsigned = make_unsigned(seq, previous_hash, chain_id=chain_id)
        signed = sign_receipt(unsigned, private_key, "did:agent:test#key-1")
        chain.append(signed)
        previous_hash = hash_receipt(signed)
    return chain


class TestChainIDBinding:
    """Spec §7.3.4 / #477 — chain.chain_id binding check."""

    def test_single_chain_passes(self) -> None:
        chain = _build_chain_with_id(3, TEST_PRIVATE_KEY, "chain-A")
        result = verify_chain(chain, TEST_PUBLIC_KEY)
        assert result.valid is True
        assert result.length == 3
        assert result.broken_at == -1

    def test_cross_chain_splice_with_forged_hash_link_rejected(self) -> None:
        """Even when an attacker forges a valid-looking hash link between two
        chains, the verifier MUST reject because chain_id differs.
        """
        chain_a = _build_chain_with_id(2, TEST_PRIVATE_KEY, "chain-A")
        splice_hash = hash_receipt(chain_a[-1])
        chain_b = _build_chain_with_id(
            2,
            TEST_PRIVATE_KEY,
            "chain-B",
            start_sequence=3,
            start_previous_hash=splice_hash,
        )

        result = verify_chain(chain_a + chain_b, TEST_PUBLIC_KEY)
        assert result.valid is False
        assert result.broken_at == 2  # first mismatched index
        assert "chain_id mismatch at index 2" in result.error
        assert '"chain-A"' in result.error
        assert '"chain-B"' in result.error

    def test_single_mismatched_receipt_in_middle_rejected(self) -> None:
        """A single off-chain receipt spliced into the middle (with a valid
        signature for its own chain_id) is rejected solely on chain_id.

        Isolation note: this test confirms the chain would otherwise verify
        cleanly; the only failure mode is the chain_id binding check. We
        re-sign the middle receipt with a different chain_id AND re-link and
        re-sign the trailing receipt so its previous_receipt_hash points at
        the middle's new hash — keeping hash linkage valid so the sole
        invariant violated is chain_id binding (not collateral hash breakage).
        """
        chain = _build_chain_with_id(3, TEST_PRIVATE_KEY, "chain-A")
        # Re-sign the middle receipt with chain_id="chain-other" so its
        # signature still validates against TEST_PUBLIC_KEY.
        middle = chain[1]
        middle.credentialSubject.chain.chain_id = "chain-other"
        unsigned = UnsignedAgentReceipt(
            **{
                "@context": middle.context,
                "id": middle.id,
                "type": middle.type,
                "version": middle.version,
                "issuer": middle.issuer,
                "issuanceDate": middle.issuanceDate,
                "credentialSubject": middle.credentialSubject,
            }
        )
        resigned = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        chain[1] = resigned

        # Re-link the trailing receipt to the re-signed middle so hash linkage
        # stays valid; its chain_id remains "chain-A".
        tail = chain[2]
        tail.credentialSubject.chain.previous_receipt_hash = hash_receipt(resigned)
        unsigned_tail = UnsignedAgentReceipt(
            **{
                "@context": tail.context,
                "id": tail.id,
                "type": tail.type,
                "version": tail.version,
                "issuer": tail.issuer,
                "issuanceDate": tail.issuanceDate,
                "credentialSubject": tail.credentialSubject,
            }
        )
        resigned_tail = sign_receipt(
            unsigned_tail, TEST_PRIVATE_KEY, "did:agent:test#key-1"
        )
        chain[2] = resigned_tail

        result = verify_chain(chain, TEST_PUBLIC_KEY)
        assert result.valid is False
        assert "chain_id mismatch at index 1" in result.error
        assert '"chain-A"' in result.error
        assert '"chain-other"' in result.error


def _append_receipt(
    chain: list,
    private_key: str,
    status: Literal["success", "failure", "pending"],
    terminal: bool = False,
) -> list:
    """Append a receipt with the given outcome status to the tail of `chain`."""
    last = chain[-1] if chain else None
    prev_hash = hash_receipt(last) if last is not None else None
    unsigned = create_receipt(
        CreateReceiptInput(
            issuer=Issuer(id="did:agent:test"),
            principal=Principal(id="did:user:test"),
            action=ActionInput(type="filesystem.file.read", risk_level="low"),
            outcome=Outcome(status=status),
            chain=Chain(
                sequence=len(chain) + 1,
                previous_receipt_hash=prev_hash,
                chain_id="chain_test",
            ),
            terminal=terminal,
        )
    )
    signed = sign_receipt(unsigned, private_key, "did:agent:test#key-1")
    return [*chain, signed]


class TestIncompleteToolRoundtrip:
    """ADR-0019 §O3 (retained by ADR-0020): advisory incomplete-roundtrip flag."""

    def test_flags_pending_non_terminal_tail(self) -> None:
        kp = generate_key_pair()
        chain = _append_receipt(
            _build_chain(2, kp.private_key), kp.private_key, "pending"
        )

        result = verify_chain(chain, kp.public_key)

        # Advisory only: the chain still verifies cryptographically.
        assert result.valid is True
        assert result.incomplete_tool_roundtrip is True

    def test_does_not_flag_completed_tail(self) -> None:
        kp = generate_key_pair()
        chain = _append_receipt(
            _build_chain(2, kp.private_key), kp.private_key, "success"
        )

        result = verify_chain(chain, kp.public_key)

        assert result.valid is True
        assert result.incomplete_tool_roundtrip is False

    def test_does_not_flag_pending_that_is_not_final(self) -> None:
        kp = generate_key_pair()
        # pending in the middle, success at the tail
        with_pending = _append_receipt(
            _build_chain(1, kp.private_key), kp.private_key, "pending"
        )
        chain = _append_receipt(with_pending, kp.private_key, "success")

        result = verify_chain(chain, kp.public_key)

        assert result.incomplete_tool_roundtrip is False

    def test_does_not_flag_terminal_even_if_pending(self) -> None:
        kp = generate_key_pair()
        chain = _append_receipt(
            _build_chain(2, kp.private_key), kp.private_key, "pending", terminal=True
        )

        result = verify_chain(chain, kp.public_key)

        assert result.incomplete_tool_roundtrip is False

    def test_empty_chain_is_false(self) -> None:
        kp = generate_key_pair()
        assert verify_chain([], kp.public_key).incomplete_tool_roundtrip is False
