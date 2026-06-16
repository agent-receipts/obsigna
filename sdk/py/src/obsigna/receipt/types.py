"""Agent Receipt schema types.

These types model the Agent Receipt as a W3C Verifiable Credential.
Both the full and minimal receipt variants share the same type — optional
fields are marked with ``None`` defaults.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_serializer, model_validator

if TYPE_CHECKING:
    from obsigna.receipt.disclosure import DisclosureEnvelope

CONTEXT: list[str] = [
    "https://www.w3.org/ns/credentials/v2",
    "https://agentreceipts.ai/context/v2",
]

CREDENTIAL_TYPE: list[str] = [
    "VerifiableCredential",
    "AgentReceipt",
]

VERSION = "0.5.0"

RiskLevel = Literal["low", "medium", "high", "critical"]

OutcomeStatus = Literal["success", "failure", "pending"]


class Operator(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str


class Runtime(BaseModel):
    """Open container for runtime/observability metadata the issuing runtime
    attaches to an action (ADR-0026).

    Intentionally extensible: ``agent_id`` and ``agent_type`` are documented
    members, but the JSON-LD context types this ``@json`` and the schema does
    not close it, so additional runtime keys (e.g. future trace-context
    identifiers) may be added without a protocol-version bump. ``extra="allow"``
    preserves unknown keys on round-trip. Absent for the root agent.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    agent_id: str | None = None
    agent_type: str | None = None


class Issuer(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: str | None = None
    name: str | None = None
    operator: Operator | None = None
    model: str | None = None
    session_id: str | None = None
    runtime: Runtime | None = None


class Principal(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: str | None = None


class ActionTarget(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    system: str
    resource: str | None = None


class PeerCredential(BaseModel):
    """OS-attested peer process metadata captured by the daemon (ADR-0010).

    Present only on receipts emitted through a daemon; absent on direct SDK
    emissions. Daemon-attested, not agent-claimed.

    ``uid`` and ``gid`` are POSIX-only — they are absent on platforms where
    UIDs/GIDs do not apply (e.g. Windows). ``exe_path`` is best-effort and
    may be absent on systems where the daemon cannot resolve it (locked-down
    sandboxes, missing ``/proc``, etc.).
    """

    model_config = ConfigDict(populate_by_name=True)

    platform: str
    """OS platform identifier (e.g. ``"darwin"``, ``"linux"``, ``"windows"``)."""

    pid: int
    """Peer process ID. POSIX ``pid_t`` width (32-bit signed integer)."""

    uid: int | None = None
    """Peer process effective UID. POSIX-only; absent on Windows."""

    gid: int | None = None
    """Peer process effective GID. POSIX-only; absent on Windows."""

    exe_path: str | None = None
    """Best-effort absolute path of the peer process executable."""


class EmitterMetadata(BaseModel):
    """Daemon-observed emitter-side metadata (ADR-0010).

    Currently used for synthetic ``events_dropped`` receipts. Daemon-attested,
    not agent-claimed.
    """

    model_config = ConfigDict(populate_by_name=True)

    drop_count: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Count of audit events the emitter dropped from its in-process "
            "buffer before flushing to the daemon. Non-negative (minimum: 0)."
        ),
    )

    @model_validator(mode="after")
    def _check_not_empty(self) -> EmitterMetadata:
        """Reject all-None construction so ``EmitterMetadata()`` is never silent.

        Every field on this model is optional, so Pydantic happily builds an
        empty instance. The instance then serializes to ``{}`` and, because
        ``exclude_none=True`` only strips the inner None, the empty dict
        survives canonicalization and perturbs the receipt hash (see
        https://github.com/agent-receipts/ar/issues/509). No legitimate use
        of empty ``EmitterMetadata`` exists, so we fail fast at construction.

        Fires on both direct construction and ``model_validate`` paths;
        ``model_construct`` still bypasses by Pydantic design, but that
        method is an opt-in escape hatch for callers that already promise
        validity. ``type(self).model_fields`` is the class-level accessor —
        the instance form ``self.model_fields`` is deprecated in Pydantic
        v2.11+.
        """
        if all(getattr(self, name) is None for name in type(self).model_fields):
            msg = (
                "EmitterMetadata requires at least one non-None field; "
                "omit the field entirely instead of passing an empty instance"
            )
            raise ValueError(msg)
        return self


class Action(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    type: str
    tool_name: str | None = None
    risk_level: RiskLevel
    target: ActionTarget | None = None
    parameters_hash: str | None = None
    parameters_disclosure: DisclosureEnvelope | None = Field(
        default=None,
        description=(
            "HPKE asymmetric encryption envelope for intentionally revealed "
            "parameter values (ADR-0012 amendment, v0.3.0+). The signed "
            "receipt commits to the ciphertext; only the holder of the "
            "forensic private key can recover the plaintext. Included in "
            "the canonical hash when present. The Python SDK only emits the "
            "v1 envelope shape — legacy v0.2.x flat-map receipts must be "
            "ingested via schema validation rather than this model."
        ),
    )
    peer_credential: PeerCredential | None = None
    """Daemon-attested peer process metadata (ADR-0010). Set by the daemon
    at the SDK↔daemon boundary; absent on direct SDK emissions."""

    emitter_metadata: EmitterMetadata | None = None
    """Daemon-observed emitter-side metadata (ADR-0010). Currently used for
    synthetic ``events_dropped`` receipts."""

    timestamp: str
    trusted_timestamp: str | None = None

    idempotency_key: str | None = Field(default=None, min_length=1)
    """Stable identifier for the logical operation this action represents
    (e.g. a request ID). When an agent retries a tool call, the same key is
    stamped on every receipt for that operation so auditors can distinguish a
    legitimate retry from a duplicated emission. Absent when no stable source
    exists; MUST be a non-empty string when present. See spec §7.3.6 and
    ADR-0019 §S5."""


class Intent(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    conversation_hash: str | None = None
    prompt_preview: str | None = None
    prompt_preview_truncated: bool | None = None
    reasoning_hash: str | None = None


class StateChange(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    before_hash: str
    after_hash: str


class Outcome(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    status: OutcomeStatus
    error: str | None = None
    reversible: bool | None = None
    reversal_method: str | None = None
    reversal_window_seconds: int | None = None
    reversal_of: str | None = None
    state_change: StateChange | None = None
    response_hash: str | None = None


class Authorization(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    scopes: list[str]
    granted_at: str
    expires_at: str | None = None
    grant_ref: str | None = None


class Chain(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    sequence: int
    previous_receipt_hash: str | None
    chain_id: str
    terminal: Literal[True] | None = None
    # Issuer-asserted termination reason. Only meaningful alongside
    # terminal=True; the verifier-derived "unknown" classification is never
    # written on the wire. See spec §7.3.3.
    status: Literal["complete", "interrupted"] | None = None

    @model_validator(mode="after")
    def _check_status_implies_terminal(self) -> Chain:
        """Enforce spec §7.3.3 at validation time.

        `chain.status` MUST coexist with `chain.terminal: True`. This guards
        the deserialization path: a Chain parsed from external JSON with
        `status` but no `terminal` would otherwise be accepted in-memory and
        could be passed to `verify_chain`. The Go SDK enforces the same
        invariant in the verifier; here we fail fast at model construction.
        """
        if self.status is not None and self.terminal is not True:
            msg = "chain.status requires chain.terminal: True (spec §7.3.3)"
            raise ValueError(msg)
        return self

    @model_serializer(mode="wrap")
    def _serialize(self, handler: Any) -> dict[str, Any]:
        """Enforce the spec §7.3.3 invariant at the serialization layer.

        Defensive belt-and-suspenders: even though the validator above
        rejects invalid models at construction, this serializer drops
        `status` if `terminal` is unset, mirroring the Go SDK's
        MarshalJSON behaviour. Direct mutation of a validated instance
        cannot produce a schema-invalid wire form.
        """
        data: dict[str, Any] = handler(self)
        if data.get("terminal") is not True and "status" in data:
            del data["status"]
        return data


class Delegator(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str


class Delegation(BaseModel):
    """Present on the first receipt of a subagent chain; absent on root chains."""

    model_config = ConfigDict(populate_by_name=True)

    parent_chain_id: str
    parent_receipt_id: str
    delegator: Delegator


class KeyRotation(BaseModel):
    """Key-rotation event (ADR-0015).

    Present only on a key_rotated receipt; absent on every other receipt. The
    receipt carrying it is signed with the OUTGOING key (``signed_with="old"``);
    ``new_public_key`` holds the incoming key inline so verifiers chain through
    the rotation without an external key registry. All seven fields are required
    when the object is present. See spec §7.3.7.
    """

    model_config = ConfigDict(populate_by_name=True)

    event_type: Literal["key_rotated"]
    new_public_key: str
    old_key_fingerprint: str
    new_key_fingerprint: str
    old_algorithm: str
    new_algorithm: str
    signed_with: Literal["old"]


class CredentialSubject(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    principal: Principal
    action: Action
    intent: Intent | None = None
    outcome: Outcome
    authorization: Authorization | None = None
    chain: Chain
    # Present only on a key_rotated receipt (ADR-0015); camelCase on the wire,
    # unlike its snake_case siblings.
    key_rotation: KeyRotation | None = Field(None, alias="keyRotation")
    correlation_id: str | None = Field(None, min_length=1)
    delegation: Delegation | None = None


class Proof(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    type: str
    created: str | None = None
    verificationMethod: str | None = None  # noqa: N815
    proofPurpose: str | None = None  # noqa: N815
    proofValue: str  # noqa: N815


class UnsignedAgentReceipt(BaseModel):
    """An Agent Receipt before signing — no proof field yet."""

    model_config = ConfigDict(populate_by_name=True)

    context: list[str] = Field(alias="@context")
    id: str
    type: list[str]
    version: str
    issuer: Issuer
    issuanceDate: str  # noqa: N815
    credentialSubject: CredentialSubject  # noqa: N815


class AgentReceipt(UnsignedAgentReceipt):
    """A signed Agent Receipt with Ed25519 proof."""

    proof: Proof


# Backwards compatibility aliases (deprecated)
ActionReceipt = AgentReceipt
UnsignedActionReceipt = UnsignedAgentReceipt


# Resolve the forward reference to DisclosureEnvelope: the import lives in a
# TYPE_CHECKING block (TC001) to keep the static-typing layer clean, but
# Pydantic v2 needs the runtime type to build the validator for Action. Doing
# the late import + rebuild here avoids both a circular import at module load
# (disclosure imports hash, hash references AgentReceipt in TYPE_CHECKING) and
# the ruff TC001 / TC003 lints.
from obsigna.receipt.disclosure import (  # noqa: E402
    DisclosureEnvelope as _DisclosureEnvelope,
)

Action.model_rebuild(_types_namespace={"DisclosureEnvelope": _DisclosureEnvelope})
