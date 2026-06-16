"""AWS KMS-backed :class:`Signer` for Agent Receipts.

``KMSSigner`` is an Ed25519 signer whose private key never leaves AWS KMS.
Signature operations are delegated to ``kms:Sign`` and the public key is fetched
once via ``kms:GetPublicKey`` and cached for the signer's lifetime. It mirrors
the Go SDK's ``aws`` module.

Requires the optional ``aws`` extra (``pip install obsigna[aws]``) only
when building the default client; an injected client needs no AWS SDK.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

SIGNING_ALGORITHM = "ED25519_SHA_512"
"""Pure Ed25519 (RFC 8032): KMS performs the SHA-512 hash internally, so the
signature verifies with a standard Ed25519 verifier. Do not switch to
``ED25519_PH_SHA_512`` (pre-hashed)."""

MESSAGE_TYPE = "RAW"


@runtime_checkable
class Signer(Protocol):
    """The Agent Receipts signing abstraction from ADR-0018.

    Implementations sign canonical receipt bytes without exposing the private
    key. ``get_public_key`` returns the raw 32-byte Ed25519 public key (RFC 8032
    §5.1.5) used by verifiers. The core package does not yet define this
    protocol; it is declared here so adapters satisfy a single contract.
    """

    def sign(self, message: bytes) -> bytes:
        """Return the raw Ed25519 signature over ``message``."""
        raise NotImplementedError

    def get_public_key(self) -> bytes:
        """Return the raw 32-byte Ed25519 public key (RFC 8032 §5.1.5)."""
        raise NotImplementedError


class KMSClient(Protocol):
    """The subset of the boto3 KMS client that :class:`KMSSigner` depends on.

    A boto3 ``kms`` client satisfies it; tests inject a mock. Deliberately narrow
    so the dependency surface — and the mock — stay small.
    """

    def sign(
        self,
        *,
        KeyId: str,
        Message: bytes,
        SigningAlgorithm: str,
        MessageType: str,
    ) -> Mapping[str, Any]:
        raise NotImplementedError

    def get_public_key(self, *, KeyId: str) -> Mapping[str, Any]:
        raise NotImplementedError


class KMSSignerError(Exception):
    """Adapter-level error (malformed KMS response, non-Ed25519 key).

    Errors raised by the AWS SDK (``botocore`` ``ClientError`` and friends) are
    surfaced verbatim and are NOT wrapped in this type, so callers can still
    distinguish throttling, access-denied, and key-not-found.
    """


def _default_client(region: str | None, timeout: float | None) -> KMSClient:
    try:
        import boto3  # pyright: ignore[reportMissingTypeStubs]
        from botocore.config import (  # pyright: ignore[reportMissingTypeStubs]
            Config,
        )
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        msg = (
            "kms signer: boto3 is required to build the default KMS client; "
            "install it with 'pip install obsigna[aws]'"
        )
        raise ImportError(msg) from exc

    kwargs: dict[str, object] = {}
    if region is not None:
        kwargs["region_name"] = region
    if timeout is not None:
        kwargs["config"] = Config(connect_timeout=timeout, read_timeout=timeout)
    return cast(
        "KMSClient",
        boto3.client("kms", **kwargs),  # pyright: ignore[reportUnknownMemberType]
    )


def _raw_ed25519_from_spki(der: bytes) -> bytes:
    """Decode the DER-encoded SPKI KMS returns into the raw 32-byte Ed25519 key.

    Rejects keys that are not Ed25519 — i.e. a KMS key that is not
    ``ECC_NIST_EDWARDS25519``.
    """
    try:
        key = load_der_public_key(der)
    except Exception as exc:  # noqa: BLE001 - any decode failure is a bad key
        msg = "kms signer: failed to parse SPKI public key"
        raise KMSSignerError(msg) from exc
    if not isinstance(key, Ed25519PublicKey):
        msg = (
            f"kms signer: key is not Ed25519 (got {type(key).__name__}); "
            "use an ECC_NIST_EDWARDS25519 KMS key"
        )
        raise KMSSignerError(msg)
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


class KMSSigner:
    """Signs Agent Receipts with an Ed25519 KMS key.

    The private key never leaves KMS; this holds only the key identifier, a KMS
    client, and a cached copy of the public key. Safe for concurrent use.
    """

    def __init__(
        self,
        key_id: str,
        *,
        client: KMSClient | None = None,
        region: str | None = None,
        timeout: float | None = None,
    ) -> None:
        """Construct a signer for ``key_id``.

        ``key_id`` is a key ID, key ARN, alias name, or alias ARN — passed to AWS
        unchanged. The key must be an ``ECC_NIST_EDWARDS25519`` (Ed25519) key with
        ``SIGN_VERIFY`` usage. Credentials come from the AWS SDK's default
        provider chain (instance role, IRSA, environment, shared profile).

        ``region`` and ``timeout`` configure the default client and are rejected
        alongside an injected ``client`` (apply them to that client yourself).
        ``timeout`` (seconds) sets the boto3 connect/read timeout; the AWS SDK
        already retries, so no extra retry layer is added.
        """
        if not key_id:
            msg = "kms signer: key_id must not be empty"
            raise ValueError(msg)
        if timeout is not None and timeout < 0:
            msg = f"kms signer: timeout must not be negative, got {timeout}"
            raise ValueError(msg)
        if client is not None and (region is not None or timeout is not None):
            msg = (
                "kms signer: region/timeout configure the default client; omit "
                "them when injecting a client"
            )
            raise ValueError(msg)

        self._key_id = key_id
        self._client = (
            client if client is not None else _default_client(region, timeout)
        )
        self._lock = threading.Lock()
        self._pub_key: bytes | None = None

    def sign(self, message: bytes) -> bytes:
        """Return the raw Ed25519 signature over ``message``, computed in KMS.

        Calls ``kms:Sign`` with ``SigningAlgorithm=ED25519_SHA_512`` and
        ``MessageType=RAW``. AWS SDK errors propagate unchanged.
        """
        resp = self._client.sign(
            KeyId=self._key_id,
            Message=message,
            SigningAlgorithm=SIGNING_ALGORITHM,
            MessageType=MESSAGE_TYPE,
        )
        sig = resp.get("Signature")
        if not isinstance(sig, (bytes, bytearray)):
            msg = "kms signer: KMS Sign returned no signature"
            raise KMSSignerError(msg)
        return bytes(sig)

    def get_public_key(self) -> bytes:
        """Return the raw 32-byte Ed25519 public key (RFC 8032 §5.1.5).

        The first call fetches via ``kms:GetPublicKey`` and caches the result;
        later calls return it without contacting AWS. A failed fetch is not
        cached, so a later call retries. AWS SDK errors propagate unchanged. The
        returned ``bytes`` are immutable, so callers cannot corrupt the cache.
        """
        with self._lock:
            if self._pub_key is not None:
                return self._pub_key
            resp = self._client.get_public_key(KeyId=self._key_id)
            der = resp.get("PublicKey")
            if not isinstance(der, (bytes, bytearray)):
                msg = "kms signer: KMS GetPublicKey returned no public key"
                raise KMSSignerError(msg)
            self._pub_key = _raw_ed25519_from_spki(bytes(der))
            return self._pub_key
