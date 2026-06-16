"""Tests for RFC 8785 canonicalization and SHA-256 hashing."""

import pytest

from obsigna.receipt.hash import canonicalize, hash_receipt, sha256
from tests.conftest import make_receipt


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
