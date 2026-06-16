export {
	type ChainVerification,
	type ReceiptVerification,
	verifyChain,
} from "./chain.js";
export { type CreateReceiptInput, createReceipt } from "./create.js";
export {
	type DisclosureEnvelope,
	type DisclosureRecipient,
	decryptDisclosure,
	encryptDisclosure,
	type ForensicKeyPair,
	generateForensicKeyPair,
} from "./disclosure.js";
export { canonicalize, hashReceipt, sha256 } from "./hash.js";
export {
	GeneratingKeyProvider,
	type KeyProvider,
	ProductionKeyProviderError,
} from "./key-provider.js";
export {
	generateKeyPair,
	type KeyPair,
	signReceipt,
	verifyReceipt,
} from "./signing.js";

// Backwards-compatibility aliases — see src/index.ts for the same pattern.
import type {
	AgentReceipt as _AgentReceipt,
	UnsignedAgentReceipt as _UnsignedAgentReceipt,
} from "./types.js";
/**
 * @deprecated Use {@link AgentReceipt} instead. Renamed in 0.3.0; this
 * alias will be dropped before 1.0.
 */
export type ActionReceipt = _AgentReceipt;
/**
 * @deprecated Use {@link UnsignedAgentReceipt} instead. Renamed in 0.3.0;
 * this alias will be dropped before 1.0.
 */
export type UnsignedActionReceipt = _UnsignedAgentReceipt;
export {
	type Action,
	type ActionTarget,
	type AgentReceipt,
	type Authorization,
	type Chain,
	CONTEXT,
	CREDENTIAL_TYPE,
	type CredentialSubject,
	type EmitterMetadata,
	type Intent,
	type Issuer,
	type KeyRotation,
	type Operator,
	type Outcome,
	type OutcomeStatus,
	type PeerCredential,
	type Principal,
	type Proof,
	type RiskLevel,
	type StateChange,
	type UnsignedAgentReceipt,
	VERSION,
} from "./types.js";
