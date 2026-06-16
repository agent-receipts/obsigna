export {
	DAEMON_PROTOCOL_RANGE,
	DaemonEmitter,
	type DaemonEmitterOptions,
	defaultSocketPath,
	type EmitEvent,
	type EmitTool,
	EmitTransportError,
	MAX_FRAME_SIZE,
	SUPPORTED_FRAME_VERSION,
} from "./daemon-emitter.js";
export {
	BufferingEmitter,
	type BufferingEmitterConfig,
	CompositeEmitter,
	EmitError,
	type Emitter,
	FileWal,
	HttpEmitter,
	type HttpEmitterAuth,
	type HttpEmitterConfig,
	InMemoryEmitter,
	MemoryWal,
	type RetryConfig,
	type Wal,
	type WalDrainResult,
	WalEmitter,
	type WalEmitterConfig,
} from "./emitters/index.js";
export {
	type ChainVerification,
	type ReceiptVerification,
	verifyChain,
} from "./receipt/chain.js";
export { type CreateReceiptInput, createReceipt } from "./receipt/create.js";
export {
	type DisclosureEnvelope,
	type DisclosureRecipient,
	decryptDisclosure,
	encryptDisclosure,
	type ForensicKeyPair,
	generateForensicKeyPair,
} from "./receipt/disclosure.js";
export { canonicalize, hashReceipt, sha256 } from "./receipt/hash.js";
export {
	GeneratingKeyProvider,
	type KeyProvider,
	ProductionKeyProviderError,
} from "./receipt/key-provider.js";
export {
	generateKeyPair,
	type KeyPair,
	signReceipt,
	verifyReceipt,
} from "./receipt/signing.js";
export {
	ReceiptChain,
	type ReceiptChainEmitInput,
	type ReceiptChainOptions,
} from "./receipt-chain.js";

// Backwards-compatibility aliases kept as standalone `type` declarations so
// each symbol carries its own @deprecated JSDoc (IDE deprecation hints bind
// per name, not per export block — biome's organize-imports collapses
// `export type { X as Y, ... }` blocks together, which loses that mapping).
import type {
	AgentReceipt as _AgentReceipt,
	UnsignedAgentReceipt as _UnsignedAgentReceipt,
} from "./receipt/types.js";
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
	VERSION as RECEIPT_VERSION,
} from "./receipt/types.js";
export {
	openStore,
	openStoreReadOnly,
	type ReceiptQuery,
	ReceiptStore,
	type StoreStats,
} from "./store/store.js";
export { verifyStoredChain } from "./store/verify.js";
export {
	ALL_ACTIONS,
	FILESYSTEM_ACTIONS,
	getActionType,
	resolveActionType,
	SYSTEM_ACTIONS,
	UNKNOWN_ACTION,
} from "./taxonomy/actions.js";
export {
	type ClassificationResult,
	classifyToolCall,
} from "./taxonomy/classify.js";
export {
	loadTaxonomyConfig,
	type TaxonomyConfig,
} from "./taxonomy/config.js";
export type {
	ActionTypeEntry,
	TaxonomyMapping,
} from "./taxonomy/types.js";
export { VERSION } from "./version.js";
