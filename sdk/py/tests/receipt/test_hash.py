"""Tests for RFC 8785 canonicalization and SHA-256 hashing."""

import json

import pytest

from obsigna.receipt.hash import canonicalize, hash_raw_receipt, hash_receipt, sha256
from obsigna.receipt.signing import sign_receipt
from tests.conftest import TEST_PRIVATE_KEY, make_receipt, make_unsigned


class TestCanonicalize:
    def test_null(self) -> None:
        assert canonicalize(None) == "null"

    def test_true(self) -> None:
        assert canonicalize(True) == "true"

    def test_false(self) -> None:
        assert canonicalize(False) == "false"

    def test_integer(self) -> None:
        assert canonicalize(42) == "42"

    def test_negative_integer(self) -> None:
        assert canonicalize(-1) == "-1"

    def test_zero(self) -> None:
        assert canonicalize(0) == "0"

    def test_float_zero(self) -> None:
        assert canonicalize(0.0) == "0"

    def test_string(self) -> None:
        assert canonicalize("hello") == '"hello"'

    def test_empty_string(self) -> None:
        assert canonicalize("") == '""'

    def test_string_with_quotes(self) -> None:
        result = canonicalize('say "hi"')
        assert result == '"say \\"hi\\""'

    def test_empty_array(self) -> None:
        assert canonicalize([]) == "[]"

    def test_array_with_values(self) -> None:
        assert canonicalize([1, "two", None]) == '[1,"two",null]'

    def test_empty_object(self) -> None:
        assert canonicalize({}) == "{}"

    def test_object_keys_sorted(self) -> None:
        result = canonicalize({"b": 2, "a": 1})
        assert result == '{"a":1,"b":2}'

    def test_nested_object(self) -> None:
        result = canonicalize({"z": {"b": 2, "a": 1}, "a": []})
        assert result == '{"a":[],"z":{"a":1,"b":2}}'

    def test_no_whitespace(self) -> None:
        result = canonicalize({"key": "value"})
        assert " " not in result
        assert "\n" not in result

    def test_non_finite_raises(self) -> None:
        with pytest.raises(ValueError, match="non-finite"):
            canonicalize(float("inf"))

    def test_nan_raises(self) -> None:
        with pytest.raises(ValueError, match="non-finite"):
            canonicalize(float("nan"))

    def test_unsupported_type_raises(self) -> None:
        with pytest.raises(TypeError, match="unsupported type"):
            canonicalize(set())  # type: ignore[arg-type]

    def test_deterministic(self) -> None:
        data = {"c": 3, "a": 1, "b": 2}
        assert canonicalize(data) == canonicalize(data)


class TestSha256:
    def test_returns_prefixed_hex(self) -> None:
        result = sha256("hello")
        assert result.startswith("sha256:")
        assert len(result) == len("sha256:") + 64

    def test_deterministic(self) -> None:
        assert sha256("test") == sha256("test")

    def test_different_inputs_different_hashes(self) -> None:
        assert sha256("a") != sha256("b")


class TestHashReceipt:
    def test_returns_prefixed_hex(self) -> None:
        receipt = make_receipt()
        result = hash_receipt(receipt)
        assert result.startswith("sha256:")

    def test_deterministic(self) -> None:
        receipt = make_receipt()
        assert hash_receipt(receipt) == hash_receipt(receipt)

    def test_excludes_proof(self) -> None:
        """Same receipt with different proofs should hash the same."""
        r1 = make_receipt()
        r2 = make_receipt()
        # Modify proof — hash should be identical
        r2.proof.proofValue = "udifferent"
        assert hash_receipt(r1) == hash_receipt(r2)

    def test_dict_input_without_chain_does_not_fabricate_chain(self) -> None:
        """Regression test for issue #1005.

        A dict receipt missing `credentialSubject.chain` entirely is
        schema-invalid, but hash_receipt must not fabricate
        `chain: {previous_receipt_hash: null}` out of nothing — that
        invents structure that was never on the wire and diverges from the
        TS SDK's pluckChain, which only restores the field when a chain
        object already exists. If nothing was fabricated, the hash equals
        hashing the input completely unchanged (there are no nulls to strip
        and no proof to pop here).
        """
        receipt: dict[str, object] = {
            "credentialSubject": {
                "principal": {"id": "did:user:test"},
            },
        }

        assert hash_receipt(receipt) == sha256(canonicalize(receipt))

    def test_dict_input_with_chain_still_preserves_null_previous_hash(self) -> None:
        """The fabrication fix must not regress the required-nullable rule
        when a chain object is genuinely present.
        """
        receipt: dict[str, object] = {
            "credentialSubject": {
                "chain": {"sequence": 1, "chain_id": "chain_test"},
            },
        }

        expected = sha256(
            canonicalize(
                {
                    "credentialSubject": {
                        "chain": {
                            "sequence": 1,
                            "chain_id": "chain_test",
                            "previous_receipt_hash": None,
                        },
                    },
                }
            )
        )

        assert hash_receipt(receipt) == expected


class TestHashRawReceipt:
    def test_matches_hash_receipt_for_known_fields(self) -> None:
        # Use the real wire serialization the emitters send (no
        # exclude_none): Pydantic writes absent optional fields as literal
        # `null`, so this also exercises hash_raw_receipt's ADR-0009 Rule 2
        # normalisation, not just the "no nulls present" case.
        unsigned = make_unsigned(1, None, chain_id="chain-eq")
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")

        want = hash_receipt(signed)
        raw = signed.model_dump_json(by_alias=True)
        got = hash_raw_receipt(raw)

        assert got == want

    def test_preserves_unknown_fields(self) -> None:
        unsigned = make_unsigned(1, None, chain_id="chain-fc")
        signed = sign_receipt(unsigned, TEST_PRIVATE_KEY, "did:agent:test#key-1")
        raw = signed.model_dump_json(by_alias=True)
        base_hash = hash_raw_receipt(raw)

        # Splice in a forward-compat top-level field. hash_receipt would
        # never see this (model_dump drops unknown fields); hash_raw_receipt
        # operates on the raw JSON and must observe the change.
        enriched = raw.replace('"id":', '"_future_field":"v2","id":', 1)
        assert '"_future_field":"v2"' in enriched

        enriched_hash = hash_raw_receipt(enriched)
        assert enriched_hash != base_hash

    def test_strips_proof(self) -> None:
        base = """{
            "id": "urn:r:1",
            "issuer": {"id": "did:example:a"},
            "credentialSubject": {"x": 1},
            "proof": {"type": "Ed25519Signature2020", "proofValue": "u-AAA"}
        }"""
        alt = """{
            "id": "urn:r:1",
            "issuer": {"id": "did:example:a"},
            "credentialSubject": {"x": 1},
            "proof": {"type": "Ed25519Signature2020", "proofValue": "u-ZZZ"}
        }"""
        assert hash_raw_receipt(base) == hash_raw_receipt(alt)

    def test_accepts_dict_input(self) -> None:
        raw_dict = {
            "id": "urn:r:1",
            "issuer": {"id": "did:example:a"},
            "credentialSubject": {"x": 1},
            "proof": {"type": "Ed25519Signature2020", "proofValue": "u-AAA"},
        }
        raw_json = json.dumps(raw_dict)
        assert hash_raw_receipt(raw_dict) == hash_raw_receipt(raw_json)

    @pytest.mark.parametrize("body", ["[1,2,3]", "42", '"string"', "", "null"])
    def test_rejects_non_object(self, body: str) -> None:
        with pytest.raises(ValueError, match="raw receipt"):
            hash_raw_receipt(body)
