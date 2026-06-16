"""JSON Schema validation tests.

Validates that:
1. Every example in spec/examples/ satisfies spec/schema/agent-receipt.schema.json.
2. Every receipt produced by sign_receipt() satisfies the spec schema.
3. The schema rejects regressions like missing required fields and unknown
   top-level fields (additionalProperties: false at the root).

Without these tests, an SDK could drift from the spec (e.g. emit a new field
the schema does not allow) and only be caught when a downstream consumer
fails to parse the output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from obsigna.receipt.create import (
    ActionInput,
    CreateReceiptInput,
    create_receipt,
)
from obsigna.receipt.signing import generate_key_pair, sign_receipt
from obsigna.receipt.types import Chain, Issuer, Outcome, Principal

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SCHEMA_PATH = REPO_ROOT / "spec" / "schema" / "agent-receipt.schema.json"
EXAMPLES_DIR = REPO_ROOT / "spec" / "examples"


@pytest.fixture(scope="module")
def schema() -> dict:
    with open(SCHEMA_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def validator(schema: dict) -> Draft202012Validator:
    Draft202012Validator.check_schema(schema)
    # Draft202012Validator treats `format` as annotation-only by default per
    # JSON Schema spec — without FORMAT_CHECKER the schema's
    # "format": "date-time" constraints on issuanceDate / proof.created are
    # silent, and a regression to a non-RFC3339 timestamp would not fail.
    return Draft202012Validator(
        schema, format_checker=Draft202012Validator.FORMAT_CHECKER
    )


class TestSpecExamples:
    """Every checked-in spec example must validate against the schema."""

    @pytest.mark.parametrize(
        "name", sorted(p.name for p in EXAMPLES_DIR.glob("*.json"))
    )
    def test_example_validates(
        self, name: str, validator: Draft202012Validator
    ) -> None:
        with open(EXAMPLES_DIR / name) as f:
            doc = json.load(f)
        errors = sorted(validator.iter_errors(doc), key=lambda e: e.path)
        assert not errors, f"{name} failed schema validation: {errors}"


class TestSDKOutputMatchesSchema:
    """Receipts produced by the Python SDK must validate against the spec."""

    def test_signed_receipt_validates(self, validator: Draft202012Validator) -> None:
        kp = generate_key_pair()
        unsigned = create_receipt(
            CreateReceiptInput(
                issuer=Issuer(id="did:agent:test"),
                principal=Principal(id="did:user:alice"),
                action=ActionInput(type="filesystem.file.read", risk_level="low"),
                outcome=Outcome(status="success"),
                chain=Chain(
                    sequence=1,
                    chain_id="chain_schema_test",
                    previous_receipt_hash=None,
                ),
            )
        )
        signed = sign_receipt(unsigned, kp.private_key, "did:agent:test#key-1")
        # Use mode="json" so Pydantic emits the same shape we put on the wire
        # (camelCase aliases, no None fields, JSON-native types).
        as_dict = signed.model_dump(mode="json", by_alias=True, exclude_none=True)
        # previous_receipt_hash is required-nullable; exclude_none drops it.
        as_dict["credentialSubject"]["chain"].setdefault("previous_receipt_hash", None)
        errors = sorted(validator.iter_errors(as_dict), key=lambda e: e.path)
        assert not errors, f"SDK-signed receipt failed schema validation: {errors}"


class TestSchemaEnforcement:
    """Defensive tests: the schema must reject obvious regressions."""

    def _minimal(self) -> dict:
        with open(EXAMPLES_DIR / "minimal-receipt.json") as f:
            return json.load(f)

    @pytest.mark.parametrize(
        "field",
        [
            "@context",
            "id",
            "type",
            "version",
            "issuer",
            "issuanceDate",
            "credentialSubject",
            "proof",
        ],
    )
    def test_missing_required_field_rejected(
        self, field: str, validator: Draft202012Validator
    ) -> None:
        receipt = self._minimal()
        receipt.pop(field)
        with pytest.raises(ValidationError):
            validator.validate(receipt)

    def test_unknown_top_level_field_rejected(
        self, validator: Draft202012Validator
    ) -> None:
        receipt = self._minimal()
        receipt["unexpected_field"] = "value"
        with pytest.raises(ValidationError):
            validator.validate(receipt)

    def test_invalid_receipt_id_rejected(self, validator: Draft202012Validator) -> None:
        receipt = self._minimal()
        receipt["id"] = "not-a-urn"
        with pytest.raises(ValidationError):
            validator.validate(receipt)

    def test_non_rfc3339_issuance_date_rejected(
        self, validator: Draft202012Validator
    ) -> None:
        # Pins that FORMAT_CHECKER is wired in — without it, "format": "date-time"
        # is annotation-only and this would silently pass.
        receipt = self._minimal()
        receipt["issuanceDate"] = "2026/04/22 00:00:00"
        with pytest.raises(ValidationError):
            validator.validate(receipt)
