"""Tests for the dev-only GeneratingKeyProvider and its production guard."""

from __future__ import annotations

import pytest

from obsigna.receipt.key_provider import (
    GeneratingKeyProvider,
    ProductionKeyProviderError,
)
from obsigna.receipt.signing import sign_receipt, verify_receipt
from tests.conftest import make_unsigned

ENV_VAR = "AGENTRECEIPTS_PRODUCTION"


@pytest.fixture(autouse=True)
def _reset_warning_latch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start each test with an unset env var and a fresh once-per-process latch."""
    monkeypatch.delenv(ENV_VAR, raising=False)
    monkeypatch.setattr("obsigna.receipt.key_provider._dev_warning_emitted", False)


class TestProductionGuard:
    def test_raises_when_production(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_VAR, "true")
        with pytest.raises(ProductionKeyProviderError):
            GeneratingKeyProvider()

    def test_no_warning_when_guard_fires(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv(ENV_VAR, "true")
        with pytest.raises(ProductionKeyProviderError):
            GeneratingKeyProvider()
        assert capsys.readouterr().err == ""

    def test_only_exact_true_is_production(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_VAR, "1")
        # Must not raise — only the exact value "true" is production.
        GeneratingKeyProvider()

    def test_error_is_named_and_exported(self) -> None:
        assert ProductionKeyProviderError.__name__ == "ProductionKeyProviderError"
        assert issubclass(ProductionKeyProviderError, Exception)


class TestKeyGeneration:
    def test_generates_usable_stable_keypair(self) -> None:
        provider = GeneratingKeyProvider()
        kp = provider.get_key_pair()

        assert kp.public_key.startswith("-----BEGIN PUBLIC KEY-----")
        assert kp.private_key.startswith("-----BEGIN PRIVATE KEY-----")
        # Stable for the lifetime of the provider (value equality, not identity).
        assert provider.get_key_pair() == kp

        # The generated keypair must produce a verifiable signature.
        unsigned = make_unsigned(1, None)
        signed = sign_receipt(unsigned, kp.private_key, "did:agent:test#key-1")
        assert verify_receipt(signed, kp.public_key)


class TestWarning:
    def test_warns_exactly_once_per_process(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        GeneratingKeyProvider()
        GeneratingKeyProvider()
        GeneratingKeyProvider()

        warnings = [
            line
            for line in capsys.readouterr().err.splitlines()
            if "GeneratingKeyProvider is dev-only" in line
        ]
        assert len(warnings) == 1
