"""Cross-SDK canonicalization test vectors (ADR-0009).

Runs all canonicalization vectors in
cross-sdk-tests/canonicalization_vectors.json against the Python SDK's
canonicaliser, and runs receipt-hash checks only for vectors with a concrete
``receipt`` field and a resolvable ``expectedHash``. Vectors using
``receiptsFrom`` references (e.g. signature-preservation invariants) and
those marked ``COMPUTE_AT_COMMIT_TIME`` are not executed by this harness.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from obsigna.receipt.hash import canonicalize, hash_receipt

VECTORS_PATH = (
    Path(__file__).parent.parent.parent.parent
    / "cross-sdk-tests"
    / "canonicalization_vectors.json"
)


def _load_vectors() -> dict:
    with open(VECTORS_PATH, encoding="utf-8") as f:
        return json.load(f)


def _sha256_hex(data: str) -> str:
    """Return the raw hex digest (no prefix) of the UTF-8 SHA-256 of data."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Canonicalization vectors
# ---------------------------------------------------------------------------


def _canon_params() -> list[pytest.param]:
    data = _load_vectors()
    params = []
    for v in data["canonicalization_vectors"]:
        name = v["name"]
        canonical = v["canonical"]
        params.append(pytest.param(v["input"], canonical, id=name))
    return params


@pytest.mark.parametrize("inp,canonical", _canon_params())
def test_canonicalization_vector(inp: object, canonical: str) -> None:
    """SDK.canonicalize(input) must equal canonical string."""
    assert canonicalize(inp) == canonical


# ---------------------------------------------------------------------------
# Canonicalization vectors — expectedHash
# ---------------------------------------------------------------------------


def _canon_hash_params() -> list[pytest.param]:
    data = _load_vectors()
    params = []
    for v in data["canonicalization_vectors"]:
        name = v["name"]
        expected_hash = v.get("expectedHash")
        if expected_hash and expected_hash not in ("COMPUTE_AT_COMMIT_TIME",):
            params.append(pytest.param(v["input"], expected_hash, id=name))
    return params


@pytest.mark.parametrize("inp,expected_hash", _canon_hash_params())
def test_canonicalization_vector_hash(inp: object, expected_hash: str) -> None:
    """sha256(canonicalize(input)) must equal expectedHash."""
    actual_hex = _sha256_hex(canonicalize(inp))
    assert f"sha256:{actual_hex}" == expected_hash


# ---------------------------------------------------------------------------
# Receipt hash vectors
# ---------------------------------------------------------------------------


def _receipt_hash_params() -> list[pytest.param]:
    data = _load_vectors()
    # Build a lookup so SAME_AS_* references can be resolved.
    resolved: dict[str, str] = {}
    vectors = data["receipt_hash_vectors"]

    # First pass: collect all concrete hashes.
    for v in vectors:
        if "expectedHash" not in v:
            continue
        eh = v["expectedHash"]
        if eh not in ("COMPUTE_AT_COMMIT_TIME",) and not eh.startswith("SAME_AS_"):
            resolved[v["name"]] = eh

    params = []
    for v in vectors:
        name = v["name"]
        if "receipt" not in v:
            # Skip reference-only vectors (e.g. signature_preservation_legacy).
            continue
        receipt = v["receipt"]
        eh = v.get("expectedHash", "COMPUTE_AT_COMMIT_TIME")

        # Resolve SAME_AS_ references.
        if eh.startswith("SAME_AS_"):
            ref_name = eh[len("SAME_AS_") :]
            if ref_name not in resolved:
                # Referenced hash not yet computed — skip.
                continue
            eh = resolved[ref_name]

        if eh == "COMPUTE_AT_COMMIT_TIME":
            # Not yet populated — skip.
            continue

        must_contain = v.get("mustContainSubstring")
        params.append(pytest.param(receipt, eh, must_contain, id=name))

    return params


@pytest.mark.parametrize(
    "receipt,expected_hash,must_contain",
    _receipt_hash_params(),
)
def test_receipt_hash_vector(
    receipt: dict,
    expected_hash: str,
    must_contain: str | None,
) -> None:
    """hash_receipt(receipt) must equal expectedHash.

    Also asserts mustContainSubstring when set on the vector.
    """
    from obsigna.receipt.hash import _strip_optional_nulls

    # Build canonical for substring check — apply same normalisation as hash_receipt.
    d = _strip_optional_nulls(dict(receipt))
    d.pop("proof", None)
    cs: dict = d.get("credentialSubject", {})
    chain: dict = cs.get("chain", {})
    if "previous_receipt_hash" not in chain:
        chain["previous_receipt_hash"] = None
    canonical = canonicalize(d)

    if must_contain is not None:
        assert must_contain in canonical, (
            f"canonical output missing required substring {must_contain!r}"
        )

    actual = hash_receipt(receipt)
    assert actual == expected_hash
