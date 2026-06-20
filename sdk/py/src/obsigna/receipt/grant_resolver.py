"""Grounded-principal conformance tier (ADR-0038, spec §7.9).

Provides the GrantResolver interface and VerifyGroundedPrincipalTier gate
that deployments claiming the grounded-principal tier must wire into their
verification pipelines.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from obsigna.receipt.types import AgentReceipt


@dataclass
class GrantInfo:
    """The resolved representation of an externally-minted authorization grant
    (e.g. an RFC 8693 OBO token or a Grantex grant token).

    ``subject`` MUST be populated by all resolvers. The remaining fields are
    advisory and MAY be omitted when the resolver's backend does not expose
    them.
    """

    # MUST be populated: the principal on whose behalf the grant was issued.
    # MUST equal credentialSubject.principal.id for the tier check to pass.
    subject: str
    # Authorization scopes active under the grant.
    scopes: list[str] = field(default_factory=list[str])
    # When the authorization server minted the grant.
    issued_at: datetime | None = None
    # When the grant expires.
    expires_at: datetime | None = None
    # Identifies the authorization server that minted the grant.
    issuer: str | None = None


class GrantResolver(abc.ABC):
    """Resolves an authorization grant reference to its minted grant,
    confirming the named principal delegated authority to the agent.

    Input:
    - ``grant_ref``: the ``authorization.grant_ref`` value from the receipt.
    - ``principal_id``: the ``credentialSubject.principal.id`` from the
      receipt (supplied as a hint; implementations MAY use it to select a
      cached entry).

    Output: the resolved ``GrantInfo``. Raise any ``Exception`` on resolution
    failure (network error, token not found, token revoked, etc.).

    Implementations MAY perform network I/O (token introspection, OIDC
    userinfo). Caching is an implementation concern.

    The SDK ships this interface only. Integrators supply a resolver for their
    authorization server (RFC 8693 token introspection, OIDC, Grantex). The
    project does not endorse a single authorization server, mirroring the
    ADR-0007 stance on DID methods.
    """

    @abc.abstractmethod
    def resolve_grant(self, grant_ref: str, principal_id: str) -> GrantInfo:
        """Resolve *grant_ref* to a GrantInfo, or raise on failure."""


class GroundedOutcome(StrEnum):
    """Outcome of a grounded-principal tier check on a single receipt
    (spec §7.9, ADR-0038).
    """

    # A high/critical receipt lacks a resolvable grant_ref.
    # Corresponds to UNGROUNDED_PRINCIPAL in spec §7.9.
    UNGROUNDED_PRINCIPAL = "UNGROUNDED_PRINCIPAL"
    # The resolved grant's subject does not equal the receipt's principal.id.
    # Corresponds to PRINCIPAL_GRANT_MISMATCH in spec §7.9.
    PRINCIPAL_GRANT_MISMATCH = "PRINCIPAL_GRANT_MISMATCH"


@dataclass
class GroundedPrincipalViolation:
    """A grounded-principal tier failure for a single receipt."""

    # Position of the offending receipt in the input list.
    index: int
    # The receipt's id field.
    receipt_id: str
    # The receipt's credentialSubject.principal.id.
    principal_id: str
    # The authorization.grant_ref value (may be empty for UNGROUNDED_PRINCIPAL
    # violations where no grant_ref is present).
    grant_ref: str
    # The specific failure outcome.
    outcome: GroundedOutcome
    # Human-readable description, including resolver error messages.
    detail: str


def verify_grounded_principal_tier(
    receipts: list[AgentReceipt],
    resolver: GrantResolver | None,
) -> list[GroundedPrincipalViolation]:
    """Apply the grounded-principal conformance tier checks (spec §7.9,
    ADR-0038 D1–D3) to a set of receipts.

    For each receipt whose ``action.risk_level`` is ``"high"`` or
    ``"critical"``:

    1. If ``authorization.grant_ref`` is absent or empty →
       ``UNGROUNDED_PRINCIPAL``.
    2. If the resolver raises → ``UNGROUNDED_PRINCIPAL``.
    3. If the resolved grant's ``subject`` ≠ ``principal.id`` →
       ``PRINCIPAL_GRANT_MISMATCH``.

    Receipts at ``risk_level`` ``"low"`` or ``"medium"`` are not checked.

    When *resolver* is ``None``, no checks are performed and an empty list is
    returned — this is the correct behaviour for base-tier verifiers that have
    not configured a resolver (ADR-0038 D3: "absence of a resolver in the
    base tier is not a verification failure").

    All violations are collected and returned; the function does not stop at
    the first failure so callers get a complete picture of the tier's state.
    """
    if resolver is None:
        return []

    violations: list[GroundedPrincipalViolation] = []

    for i, r in enumerate(receipts):
        risk_level = r.credentialSubject.action.risk_level
        if risk_level not in ("high", "critical"):
            continue

        principal_id = r.credentialSubject.principal.id
        auth = r.credentialSubject.authorization
        grant_ref = (auth.grant_ref or "") if auth is not None else ""

        # Step 1: grant_ref must be present and non-empty.
        if not grant_ref:
            violations.append(
                GroundedPrincipalViolation(
                    index=i,
                    receipt_id=r.id,
                    principal_id=principal_id,
                    grant_ref="",
                    outcome=GroundedOutcome.UNGROUNDED_PRINCIPAL,
                    detail=(
                        f"authorization.grant_ref is absent on a {risk_level} receipt"
                    ),
                )
            )
            continue

        # Step 2: resolve the grant.
        try:
            grant = resolver.resolve_grant(grant_ref, principal_id)
        except Exception as exc:  # noqa: BLE001
            violations.append(
                GroundedPrincipalViolation(
                    index=i,
                    receipt_id=r.id,
                    principal_id=principal_id,
                    grant_ref=grant_ref,
                    outcome=GroundedOutcome.UNGROUNDED_PRINCIPAL,
                    detail=f"grant resolution failed: {exc}",
                )
            )
            continue

        # Step 3: subject must equal principal.id.
        if grant.subject != principal_id:
            violations.append(
                GroundedPrincipalViolation(
                    index=i,
                    receipt_id=r.id,
                    principal_id=principal_id,
                    grant_ref=grant_ref,
                    outcome=GroundedOutcome.PRINCIPAL_GRANT_MISMATCH,
                    detail=(
                        f"grant subject {grant.subject!r} does not match "
                        f"principal.id {principal_id!r}"
                    ),
                )
            )

    return violations
