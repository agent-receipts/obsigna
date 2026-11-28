"""Grounded-principal conformance tier (spec v0.7.0 §7.9, ADR-0038, ADR-0041).

Provides the GrantResolver interface and verify_grounded_principal_tier, which
deployments claiming the grounded-principal tier wire into their verification
pipelines.
"""

from __future__ import annotations

import abc
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, cast

from obsigna.receipt._receipt_time import parse_receipt_time_ms

if TYPE_CHECKING:
    from obsigna.receipt.types import AgentReceipt, Authorization

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MILLISECOND = timedelta(milliseconds=1)


class Revocation(StrEnum):
    """A resolved grant's revocation status (spec §7.9.1)."""

    # Not revoked as of resolution, which covers any earlier action.
    NOT_REVOKED = "not_revoked"
    # Revoked; GrantInfo.revoked_at carries the time when the resolver knows it.
    REVOKED = "revoked"
    # The resolver cannot see revocation, e.g. it only verifies a JWT.
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class GrantInfo:
    """The resolved representation of an externally-minted authorization grant,
    such as an RFC 8693 token-exchange token or a Grantex grant token
    (spec §7.9.1, ADR-0041 D2).

    Times must be timezone-aware. A grant that is missing a required field, has
    empty ``scopes``, has a naive time, has ``expires_at`` not after
    ``valid_from``, or has ``revoked_at`` without ``Revocation.REVOKED`` is
    malformed, and the verifier treats it as a resolution failure.
    """

    # The principal the grant was issued for. Must equal principal.id.
    subject: str
    # The scopes the grant conferred. Non-empty.
    scopes: list[str]
    # When the grant took effect. For a JWT: nbf when present, otherwise iat.
    valid_from: datetime
    # The grant's revocation status. Report UNKNOWN when it cannot be seen.
    revocation: Revocation
    # The authorization server that minted the grant.
    issuer: str
    # When the grant expires. None means no expiry.
    expires_at: datetime | None = None
    # When the grant was revoked, if known. Only with Revocation.REVOKED.
    revoked_at: datetime | None = None


class GrantResolver(abc.ABC):
    """Resolves an authorization grant reference to the grant's terms
    (spec §7.9.1).

    - ``grant_ref``: the ``authorization.grant_ref`` value from the receipt.
    - ``principal_id``: the receipt's ``credentialSubject.principal.id``,
      supplied as a hint; implementations MAY use it to select a cached entry.

    A grant that has expired or been revoked is still a resolved grant: when the
    resolver can establish its terms it must return them, not raise. Raise only
    when the grant cannot be found, the backend cannot be reached, or its
    response cannot be interpreted. A resolver that learns only that a grant is
    inactive, without its terms (as with plain RFC 7662 token introspection),
    must raise. Document whether your resolver returns the terms of lapsed
    grants and whether it can see revocation.

    The SDK ships this interface only; integrators supply a resolver for their
    authorization server, mirroring the ADR-0007 stance on DID methods.
    """

    @abc.abstractmethod
    def resolve_grant(self, grant_ref: str, principal_id: str) -> GrantInfo:
        """Resolve *grant_ref* to a GrantInfo, or raise on resolution failure."""


class GroundedOutcome(StrEnum):
    """Failure outcomes of the grounded-principal tier (spec §7.9.6)."""

    # No grant_ref, or the grant cannot be resolved or is malformed.
    UNGROUNDED_PRINCIPAL = "UNGROUNDED_PRINCIPAL"
    # The grant's subject does not equal principal.id.
    PRINCIPAL_GRANT_MISMATCH = "PRINCIPAL_GRANT_MISMATCH"
    # The grant was not in force at the action time.
    GRANT_NOT_VALID_AT_ACTION_TIME = "GRANT_NOT_VALID_AT_ACTION_TIME"
    # The verifier cannot tell whether the grant was in force at the action time.
    GRANT_VALIDITY_UNRESOLVED = "GRANT_VALIDITY_UNRESOLVED"
    # authorization.scopes contains a scope the grant does not confer.
    GRANT_SCOPE_EXCEEDED = "GRANT_SCOPE_EXCEEDED"


class GroundedWarningCode(StrEnum):
    """Warnings raised alongside a grounded-tier result (spec §7.9.4)."""

    # authorization.granted_at differs from the grant's valid_from.
    GRANTED_AT_DISAGREES = "GRANTED_AT_DISAGREES"
    # authorization.expires_at differs from the grant's expiry, including none.
    EXPIRES_AT_DISAGREES = "EXPIRES_AT_DISAGREES"


@dataclass(frozen=True)
class GroundedWarning:
    """A warning raised alongside a grounded-tier result. It never changes the
    outcome."""

    code: GroundedWarningCode
    detail: str


@dataclass
class GroundedResult:
    """The grounded-principal tier result for one checked receipt."""

    # Position of the receipt in the input list.
    index: int
    # The receipt's id field.
    receipt_id: str
    # The receipt's credentialSubject.principal.id.
    principal_id: str
    # authorization.grant_ref; empty when absent.
    grant_ref: str = ""
    # None when the receipt is grounded.
    outcome: GroundedOutcome | None = None
    # Explains the outcome. For a grounded receipt it states that validity was
    # established at the issuer-asserted action time (§7.9.3).
    detail: str = ""
    # Raised once the grant has resolved, whatever the outcome.
    warnings: list[GroundedWarning] = field(default_factory=list[GroundedWarning])

    @property
    def grounded(self) -> bool:
        """Whether the receipt passed every check."""
        return self.outcome is None


def verify_grounded_principal_tier(
    receipts: list[AgentReceipt],
    resolver: GrantResolver | None,
    *,
    clock_skew_ms: int = 0,
) -> list[GroundedResult]:
    """Apply the grounded-principal tier checks (spec v0.7.0 §7.9, ADR-0038 and
    ADR-0041) and return one result for every receipt checked: those at risk
    level ``"high"`` or ``"critical"``. Low and medium receipts produce no
    result.

    For each checked receipt the steps run in order, and the first failure is
    the outcome: grant presence, grant resolution (including the
    malformed-grant rules), subject match, validity at the action time, and
    scope containment.

    *clock_skew_ms* is the tolerance δ around the action time (§7.9.3),
    floored to a whole millisecond. A negative, non-finite or non-numeric value
    raises ``ValueError``. A ``None`` resolver means the
    verifier is in the base tier: no checks run and the result is empty.
    """
    # Checked as an object: callers without type checking can pass anything.
    skew = cast("object", clock_skew_ms)
    if (
        isinstance(skew, bool)
        or not isinstance(skew, int | float)
        or (isinstance(skew, float) and not math.isfinite(skew))
        or skew < 0
    ):
        msg = "grounded-tier clock_skew_ms must be a finite, non-negative number"
        raise ValueError(msg)
    skew_ms = math.floor(skew)
    if resolver is None:
        return []

    results: list[GroundedResult] = []
    for i, r in enumerate(receipts):
        risk_level = r.credentialSubject.action.risk_level
        if risk_level not in ("high", "critical"):
            continue
        result = GroundedResult(
            index=i,
            receipt_id=r.id,
            principal_id=r.credentialSubject.principal.id,
        )
        _check_grounded(r, resolver, skew_ms, result)
        results.append(result)
    return results


def _fail(result: GroundedResult, outcome: GroundedOutcome, detail: str) -> None:
    result.outcome = outcome
    result.detail = detail


def _check_grounded(
    r: AgentReceipt, resolver: GrantResolver, skew_ms: int, result: GroundedResult
) -> None:
    auth = r.credentialSubject.authorization
    if auth is None or not auth.grant_ref:
        risk_level = r.credentialSubject.action.risk_level
        _fail(
            result,
            GroundedOutcome.UNGROUNDED_PRINCIPAL,
            f"authorization.grant_ref is absent on a {risk_level} receipt",
        )
        return
    result.grant_ref = auth.grant_ref

    try:
        grant = resolver.resolve_grant(auth.grant_ref, result.principal_id)
    except Exception as exc:  # noqa: BLE001
        _fail(
            result,
            GroundedOutcome.UNGROUNDED_PRINCIPAL,
            f"grant resolution failed: {exc}",
        )
        return
    malformed = _malformed_grant(grant)
    if malformed is not None:
        _fail(
            result,
            GroundedOutcome.UNGROUNDED_PRINCIPAL,
            f"resolved grant is malformed: {malformed}",
        )
        return
    result.warnings = _grant_field_warnings(auth, grant)

    if grant.subject != result.principal_id:
        _fail(
            result,
            GroundedOutcome.PRINCIPAL_GRANT_MISMATCH,
            f"grant subject {grant.subject!r} does not match "
            f"principal.id {result.principal_id!r}",
        )
        return

    t = parse_receipt_time_ms(r.credentialSubject.action.timestamp)
    if t is None:
        _fail(
            result,
            GroundedOutcome.GRANT_VALIDITY_UNRESOLVED,
            "action.timestamp is not a readable RFC 3339 date-time",
        )
        return
    window = _check_validity_window(grant, t, skew_ms)
    if window is not None:
        _fail(result, *window)
        return

    for scope in auth.scopes:
        if scope not in grant.scopes:
            _fail(
                result,
                GroundedOutcome.GRANT_SCOPE_EXCEEDED,
                f"authorization.scopes contains {scope!r}, "
                "which the grant does not confer",
            )
            return
    result.detail = "grounded at the issuer-asserted action time"


def _ms(dt: datetime) -> int:
    """Milliseconds since the Unix epoch, floored (§7.9 time comparison)."""
    return (dt - _EPOCH) // _MILLISECOND


def _aware(dt: object) -> bool:
    return isinstance(dt, datetime) and dt.utcoffset() is not None


def _malformed_grant(g: object) -> str | None:  # noqa: PLR0911
    """Why a resolved grant is malformed (§7.9.1), or None."""
    if not isinstance(g, GrantInfo):
        return "the resolver did not return a GrantInfo"
    # Fields are checked as objects: a resolver without type checking can put
    # anything in them.
    subject, scopes, issuer = (
        cast("object", v) for v in (g.subject, g.scopes, g.issuer)
    )
    if not isinstance(subject, str) or not subject:
        return "subject is missing"
    if (
        not isinstance(scopes, list | tuple)
        or not scopes
        or not all(isinstance(s, str) for s in cast("list[object]", scopes))
    ):
        return "scopes is missing, empty or not a list of strings"
    if not _aware(g.valid_from):
        return "valid_from is missing or has no timezone"
    if not isinstance(issuer, str) or not issuer:
        return "issuer is missing"
    if not g.revocation:
        return "revocation is missing"
    if g.revocation not in tuple(Revocation):
        return (
            f"revocation {g.revocation!r} is not one of not_revoked, revoked, unknown"
        )
    if g.expires_at is not None and not _aware(g.expires_at):
        return "expires_at has no timezone"
    if g.revoked_at is not None and not _aware(g.revoked_at):
        return "revoked_at has no timezone"
    if g.expires_at is not None and _ms(g.expires_at) <= _ms(g.valid_from):
        return "expires_at is not after valid_from"
    if g.revoked_at is not None and g.revocation != Revocation.REVOKED:
        return f"revoked_at is set but revocation is {g.revocation}"
    return None


def _check_validity_window(
    g: GrantInfo, t: int, skew_ms: int
) -> tuple[GroundedOutcome, str] | None:
    """Apply §7.9.3 to action time *t* (ms since the epoch); None when in force."""
    start = _ms(g.valid_from)
    ends: list[int] = []
    if g.expires_at is not None:
        ends.append(_ms(g.expires_at))
    if g.revocation == Revocation.REVOKED and g.revoked_at is not None:
        ends.append(_ms(g.revoked_at))
    end = min(ends) if ends else None

    lo, hi = t - skew_ms, t + skew_ms
    empty_window = end is not None and end <= start
    overlaps = not empty_window and hi >= start and (end is None or lo < end)
    if not overlaps:
        return (
            GroundedOutcome.GRANT_NOT_VALID_AT_ACTION_TIME,
            "the grant was not in force at the issuer-asserted action time",
        )
    inside = lo >= start and (end is None or hi < end)
    if not inside:
        return (
            GroundedOutcome.GRANT_VALIDITY_UNRESOLVED,
            "the action time is within the clock-skew tolerance of a grant boundary",
        )
    if g.revocation == Revocation.UNKNOWN:
        return (
            GroundedOutcome.GRANT_VALIDITY_UNRESOLVED,
            "the resolver cannot see whether the grant was revoked",
        )
    if g.revocation == Revocation.REVOKED and g.revoked_at is None:
        return (
            GroundedOutcome.GRANT_VALIDITY_UNRESOLVED,
            "the grant was revoked at an unknown time",
        )
    return None


def _grant_field_warnings(auth: Authorization, g: GrantInfo) -> list[GroundedWarning]:
    """Compare the receipt's stated grant fields with the grant (§7.9.4).

    A stated value that is not a readable RFC 3339 date-time raises no warning.
    """
    warnings: list[GroundedWarning] = []
    granted_at = parse_receipt_time_ms(auth.granted_at)
    if granted_at is not None and granted_at != _ms(g.valid_from):
        warnings.append(
            GroundedWarning(
                GroundedWarningCode.GRANTED_AT_DISAGREES,
                "authorization.granted_at differs from the grant's valid_from",
            )
        )
    expires_at = parse_receipt_time_ms(auth.expires_at)
    if expires_at is not None and (
        g.expires_at is None or expires_at != _ms(g.expires_at)
    ):
        warnings.append(
            GroundedWarning(
                GroundedWarningCode.EXPIRES_AT_DISAGREES,
                "authorization.expires_at differs from the grant's expiry",
            )
        )
    return warnings
