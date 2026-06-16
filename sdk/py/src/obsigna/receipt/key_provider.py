"""Dev-only key provider with a production guard (ADR-0018, ADR-0019 §S2)."""

from __future__ import annotations

import os
import sys
import threading
from dataclasses import replace
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from obsigna.receipt.signing import generate_key_pair

if TYPE_CHECKING:
    from obsigna.receipt.signing import KeyPair

_PRODUCTION_ENV_VAR = "AGENTRECEIPTS_PRODUCTION"
"""Environment variable that marks a production deployment. A
:class:`GeneratingKeyProvider` refuses to run when it is set to the exact
value ``"true"`` (see ADR-0018 § Key generation policy and ADR-0019 § S2)."""

_DEV_WARNING = (
    "⚠ GeneratingKeyProvider is dev-only — set AGENTRECEIPTS_PRODUCTION=true "
    "to disable in production"
)
"""The one-line, dev-only warning emitted at most once per process."""

# One stderr warning per process, regardless of how many providers are built.
_dev_warning_lock = threading.Lock()
_dev_warning_emitted = False


class ProductionKeyProviderError(RuntimeError):
    """Raised when a :class:`GeneratingKeyProvider` is constructed in production.

    Generating a keypair on the fly mints a fresh DID on every cold start,
    producing an unverifiable audit trail with no error surfaced. Production
    deployments must provision a keypair out-of-band and load it via a file,
    env-var, or secret-store key provider. See the ephemeral-compute
    deployment guide.
    """


@runtime_checkable
class KeyProvider(Protocol):
    """Supplies the Ed25519 keypair the SDK signs with.

    Models environments where the private key bytes are accessible locally
    (files, env vars, in-memory fixtures). Environments where the private key
    is never extractable (KMS, HSM, TPM) implement ``Signer`` instead
    (see ADR-0018).
    """

    def get_key_pair(self) -> KeyPair:
        raise NotImplementedError


class GeneratingKeyProvider:
    """Generates a fresh Ed25519 keypair for development and bootstrap use only.

    The keypair is stable for the lifetime of the provider.

    It is explicitly prohibited in production: constructing one when
    ``AGENTRECEIPTS_PRODUCTION=true`` raises :class:`ProductionKeyProviderError`
    before any key is generated.
    """

    def __init__(self) -> None:
        global _dev_warning_emitted

        if os.environ.get(_PRODUCTION_ENV_VAR) == "true":
            raise ProductionKeyProviderError(
                "GeneratingKeyProvider is disabled in production "
                "(AGENTRECEIPTS_PRODUCTION=true): provision a keypair "
                "out-of-band and load it via a file, env-var, or "
                "secret-store key provider"
            )

        with _dev_warning_lock:
            if not _dev_warning_emitted:
                _dev_warning_emitted = True
                print(_DEV_WARNING, file=sys.stderr)

        self._key_pair = generate_key_pair()

    def get_key_pair(self) -> KeyPair:
        """Return the keypair generated when the provider was constructed."""
        return replace(self._key_pair)
