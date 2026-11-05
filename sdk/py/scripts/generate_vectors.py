"""Generate cross-SDK test vectors signed by the Python SDK.

Reads ``../tests/fixtures/ts_vectors.json`` to obtain the shared keypair and
unsigned receipt, signs the receipt with the Python SDK using the shared key,
and writes ``../../../cross-sdk-tests/py_vectors.json``.

The output structure mirrors ``cross-sdk-tests/cmd/generate-vectors/main.go``
(which produces ``go_vectors.json``) so the Go and TypeScript SDKs can consume
both files via the same vector schema.

Ed25519 is deterministic (RFC 8032), so signing the same canonical bytes with
the same private key produces a byte-identical ``proofValue`` regardless of the
SDK that produced it. ``proof.created`` is overridden to a fixed timestamp so
re-running this script produces a byte-identical file.

Usage:
    cd sdk/py
    uv run python scripts/generate_vectors.py
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from obsigna.receipt.hash import canonicalize, hash_receipt, sha256
from obsigna.receipt.signing import sign_receipt
from obsigna.receipt.types import AgentReceipt, UnsignedAgentReceipt

FIXED_PROOF_CREATED = "2026-04-22T00:00:00Z"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
TS_VECTORS_PATH = REPO_ROOT / "sdk/py/tests/fixtures/ts_vectors.json"
OUT_PATH = REPO_ROOT / "cross-sdk-tests/py_vectors.json"


def _sign(
    unsigned_dict: dict[str, Any], private_key: str, verification_method: str
) -> tuple[AgentReceipt, dict[str, Any]]:
    unsigned = UnsignedAgentReceipt.model_validate(unsigned_dict)
    signed = sign_receipt(unsigned, private_key, verification_method)
    signed.proof.created = FIXED_PROOF_CREATED

    signed_dict = signed.model_dump(by_alias=True, exclude_none=True)
    # previous_receipt_hash is required-nullable per spec — model_dump(exclude_none)
    # strips it, but consumers (TS verify, Go unmarshal) need it present as null
    # for the canonicalized bytes to match the bytes that were signed.
    chain = signed_dict["credentialSubject"]["chain"]
    chain.setdefault("previous_receipt_hash", None)
    return signed, signed_dict


def _rich_unsigned(minimal: dict[str, Any]) -> dict[str, Any]:
    rich = copy.deepcopy(minimal)
    action = rich["credentialSubject"]["action"]
    action["tool_name"] = "refund.create"
    action["target"] = {"system": "razorpay", "resource": "payments/pay_test_0001"}
    action["parameters_hash"] = sha256('{"amount":10000,"currency":"INR"}')
    return rich


def main() -> None:
    with open(TS_VECTORS_PATH) as f:
        ts_vectors: dict[str, Any] = json.load(f)

    keys = ts_vectors["keys"]
    canon_in = ts_vectors["canonicalization"]
    hash_in = ts_vectors["hashing"]
    signing_in = ts_vectors["signing"]

    signed, signed_dict = _sign(
        signing_in["unsigned"], keys["privateKey"], signing_in["verificationMethod"]
    )
    receipt_hash = hash_receipt(signed)

    rich_unsigned = _rich_unsigned(signing_in["unsigned"])
    _, rich_signed_dict = _sign(
        rich_unsigned, keys["privateKey"], signing_in["verificationMethod"]
    )

    py_vectors: dict[str, Any] = {
        "keys": keys,
        "canonicalization": {
            "simpleInput": canon_in["simpleInput"],
            "simpleExpected": canonicalize(canon_in["simpleInput"]),
            "receiptInput": canon_in["receiptInput"],
            "receiptExpected": canonicalize(canon_in["receiptInput"]),
        },
        "hashing": {
            "simpleInput": hash_in["simpleInput"],
            "simpleExpected": sha256(hash_in["simpleInput"]),
            "receiptExpected": receipt_hash,
        },
        "signing": {
            "unsigned": signing_in["unsigned"],
            "signed": signed_dict,
            "verificationMethod": signing_in["verificationMethod"],
        },
        # A receipt with action.target and parameters_hash set. The minimal
        # receipt above leaves both out, so it does not exercise them.
        "signingRich": {
            "unsigned": rich_unsigned,
            "signed": rich_signed_dict,
            "verificationMethod": signing_in["verificationMethod"],
        },
    }

    with open(OUT_PATH, "w") as f:
        json.dump(py_vectors, f, indent=2)
        f.write("\n")
    print(f"wrote {OUT_PATH.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
