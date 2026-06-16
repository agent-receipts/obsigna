from obsigna.receipt.chain import (
    ChainVerification,
    ReceiptVerification,
    verify_chain,
)
from obsigna.receipt.create import CreateReceiptInput, create_receipt
from obsigna.receipt.hash import canonicalize, hash_receipt, sha256
from obsigna.receipt.key_provider import (
    GeneratingKeyProvider,
    KeyProvider,
    ProductionKeyProviderError,
)
from obsigna.receipt.signing import (
    KeyPair,
    generate_key_pair,
    sign_receipt,
    verify_receipt,
)
from obsigna.receipt.types import (
    CONTEXT,
    CREDENTIAL_TYPE,
    VERSION,
    Action,
    ActionTarget,
    AgentReceipt,
    Authorization,
    Chain,
    CredentialSubject,
    Intent,
    Issuer,
    KeyRotation,
    Operator,
    Outcome,
    Principal,
    Proof,
    Runtime,
    StateChange,
    UnsignedAgentReceipt,
)

# Backwards compatibility aliases (deprecated)
ActionReceipt = AgentReceipt
UnsignedActionReceipt = UnsignedAgentReceipt

__all__ = [
    # Types
    "Action",
    "ActionReceipt",
    "AgentReceipt",
    "ActionTarget",
    "Authorization",
    "Chain",
    "CredentialSubject",
    "Intent",
    "Issuer",
    "KeyRotation",
    "Operator",
    "Outcome",
    "Principal",
    "Proof",
    "Runtime",
    "StateChange",
    "UnsignedActionReceipt",
    "UnsignedAgentReceipt",
    # Constants
    "CONTEXT",
    "CREDENTIAL_TYPE",
    "VERSION",
    # Creation
    "CreateReceiptInput",
    "create_receipt",
    # Hashing
    "canonicalize",
    "hash_receipt",
    "sha256",
    # Signing
    "KeyPair",
    "generate_key_pair",
    "sign_receipt",
    "verify_receipt",
    # Key providers (ADR-0018; production guard per ADR-0019 §S2)
    "GeneratingKeyProvider",
    "KeyProvider",
    "ProductionKeyProviderError",
    # Chain
    "ChainVerification",
    "ReceiptVerification",
    "verify_chain",
]
