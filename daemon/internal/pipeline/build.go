// Package pipeline maps an emitter frame plus an OS-attested peer credential
// into a signed AgentReceipt and persists it to the store. The daemon's hot
// path runs through here.
package pipeline

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agent-receipts/ar/daemon/internal/chain"
	"github.com/agent-receipts/ar/daemon/internal/keysource"
	"github.com/agent-receipts/ar/daemon/internal/socket"
	"github.com/agent-receipts/ar/sdk/go/receipt"
	"github.com/agent-receipts/ar/sdk/go/store"
	"github.com/agent-receipts/ar/sdk/go/taxonomy"
)

// multibaseBase64URL matches sdk/go/receipt/signing.go: receipts use base64url
// (multibase prefix "u") rather than the W3C default base58btc ("z").
const multibaseBase64URL = "u"

// maxIdentityFieldLen caps the byte length of the proxy-supplied identity
// fields (IssuerName, IssuerModel, OperatorID, OperatorName, IdempotencyKey,
// CorrelationID, AgentID, AgentType). The 1 MiB socket cap is the only other
// ceiling — this per-field limit catches runaway values early and keeps error
// messages legible.
const maxIdentityFieldLen = 256

// maxTargetResourceLen caps the byte length of TargetResource. File paths can
// reach 4096 bytes on Linux (PATH_MAX), so a separate, wider cap is used
// rather than the identity-field limit.
const maxTargetResourceLen = 4096

// SupportedFrameVersion is the only emitter-frame schema this daemon accepts.
// Bumping it requires a migration plan and a daemon-side translator for the
// old version; until that exists, accepting unknown versions would silently
// misinterpret future fields.
const SupportedFrameVersion = "1"

// SpokenFrameVersionMin and SpokenFrameVersionMax bound, inclusive, the set of
// emitter-frame schema versions this daemon can interpret — its "spoken range"
// in the ADR-0024 Gate #8 sense. Today the daemon speaks exactly one version,
// so min == max and the value equals SupportedFrameVersion; when a future
// version ships with a daemon-side translator for an older shape, the max
// widens and the accept check above widens with it. Gate #8 reads this range
// (via `obsigna-daemon --protocol-version`) and asserts it intersects
// the range each released SDK declares it can emit, so a release can never
// ship an SDK/daemon pair that cannot talk to each other. Keeping these as the
// single source of the daemon's spoken range — alongside a test that ties them
// to SupportedFrameVersion — stops the declaration drifting from the bytes the
// daemon actually accepts.
const (
	SpokenFrameVersionMin = 1
	SpokenFrameVersionMax = 1
)

// actionTypeEventsDropped is the action type for the daemon-synthesised
// events_dropped receipt. The "agent_receipts" namespace identifies the daemon
// as the source rather than a user-facing tool channel.
const actionTypeEventsDropped = "agent_receipts.events_dropped"

// actionTypeChainInterrupted is the action type for the daemon-synthesised
// terminal receipt emitted on SIGTERM/SIGINT when open chains exist.
const actionTypeChainInterrupted = "agent_receipts.chain_interrupted"

// EmitterFrame is the JSON payload emitters send. Mirrors ADR-0010 §"Schema
// split". Fields the emitter does not populate are zero/empty; the daemon
// fills in the authoritative chain/peer/id/ts_recv before signing.
//
// Input and Output carry the raw tool I/O. The daemon does NOT persist the
// raw bytes in the receipt; it canonicalises them (RFC 8785) and stores only
// the SHA-256 digests in action.parameters_hash and outcome.response_hash.
// A literal JSON null (or omitted field) means "no payload" and produces no
// hash — hashing the literal "null" would falsely commit the daemon to a
// value the emitter did not send.
//
// DropCount, when > 0, records events the emitter dropped (connect/write
// failures) before this successful send. The daemon inserts a synthetic
// events_dropped receipt with this count before the live receipt so the gap
// is visible in the chain.
type EmitterFrame struct {
	Version   string      `json:"v"`
	TsEmit    string      `json:"ts_emit"`
	SessionID string      `json:"session_id"`
	Channel   string      `json:"channel"`
	Tool      EmitterTool `json:"tool"`
	// ActionType, when set, is the taxonomic action type the emitter has already
	// resolved (e.g. "filesystem.file.delete"). The daemon uses it verbatim as
	// action.type and resolves risk_level from it via the taxonomy. When empty,
	// the daemon falls back to a synthetic "<channel>.<tool>" type that rarely
	// matches the taxonomy (so risk defaults to medium). Emitters that know the
	// real action type SHOULD set this — it is what makes risk-based controls
	// (e.g. parameter-disclosure "high") effective. The daemon resolves risk
	// itself rather than trusting an emitter-supplied risk, so an emitter cannot
	// downgrade risk to evade disclosure.
	ActionType     string          `json:"action_type,omitempty"`
	Input          json.RawMessage `json:"input,omitempty"`
	Output         json.RawMessage `json:"output,omitempty"`
	Error          string          `json:"error,omitempty"`
	Decision       string          `json:"decision"`
	DropCount      int64           `json:"drop_count,omitempty"`
	IssuerName     string          `json:"issuer_name,omitempty"`
	IssuerModel    string          `json:"issuer_model,omitempty"`
	OperatorID     string          `json:"operator_id,omitempty"`
	OperatorName   string          `json:"operator_name,omitempty"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	CorrelationID  string          `json:"correlation_id,omitempty"`
	AgentID        string          `json:"agent_id,omitempty"`
	AgentType      string          `json:"agent_type,omitempty"`
	// Model, Usage, and CaptureMethod carry runtime/observability metadata the
	// emitter derived for this call (Claude Code: from the session transcript).
	// The daemon maps them into issuer.runtime.{model,usage,capture_method}
	// (ADR-0026 open container). Usage is forwarded verbatim — the runtime's own
	// token-usage object, never recomputed. All optional.
	Model         string          `json:"model,omitempty"`
	Usage         json.RawMessage `json:"usage,omitempty"`
	CaptureMethod string          `json:"capture_method,omitempty"`
	// TargetSystem and TargetResource together identify the resource the action
	// operates on. The daemon maps them into action.target.{system,resource}.
	// For filesystem tools (Read, Write, Edit, MultiEdit) on the claude-code
	// channel, TargetSystem is "filesystem" and TargetResource is the file path.
	// Both are optional; omitted when the tool has no addressable resource.
	TargetSystem   string `json:"target_system,omitempty"`
	TargetResource string `json:"target_resource,omitempty"`
}

// EmitterTool identifies the tool the agent invoked.
type EmitterTool struct {
	Server string `json:"server,omitempty"`
	Name   string `json:"name"`
}

// pipelineStore is store.ReceiptStore extended with GetChainTailReceipt,
// which is needed by EmitTerminator but is not part of the exported SDK
// interface to avoid a source-breaking change for external implementers.
// *store.Store satisfies this interface; test fakes can embed it.
type pipelineStore interface {
	store.ReceiptStore
	GetChainTailReceipt(chainID string) (*receipt.AgentReceipt, error)
}

// Pipeline holds the daemon-owned dependencies (chain state, signer, store)
// shared across all incoming frames.
type Pipeline struct {
	State    *chain.State
	Keys     keysource.KeySource
	Store    pipelineStore
	IssuerID string // e.g. "did:agent-receipts-daemon:<host>"
	Now      func() time.Time
	TraceLog io.Writer            // Optional trace log for testing; nil = silent
	ErrorLog func(string, ...any) // Optional error logger; nil = silent

	// ForensicPublicKey is the X25519 public key used to encrypt action
	// parameters with HPKE (ADR-0012 envelope v1). 32 bytes; nil/empty means
	// parameters are hashed only (the default). When set, the parameters of
	// actions elected by DisclosurePolicy are encrypted before signing and
	// attached as action.parameters_disclosure. The private key is held offline
	// by the forensic responder.
	ForensicPublicKey []byte

	// DisclosurePolicy governs which actions disclose their parameters when a
	// ForensicPublicKey is configured (false | true | "high" | string[], per
	// ADR-0012). The zero value discloses nothing.
	DisclosurePolicy DisclosurePolicy

	// Redactor is applied to text fields before they are persisted in the
	// receipt body. Today that means outcome.error only; input and output are
	// never stored as raw text — only their SHA-256 hashes go into
	// parameters_hash / response_hash, so those hashes are always over the
	// original emitter payload. Nil = no redaction.
	Redactor *Redactor

	// traceMu serialises writes to TraceLog. Process is invoked concurrently
	// from the listener accept loop, so unguarded fmt.Fprintf calls would
	// interleave bytes from different frames in the buffer (and race the
	// underlying io.Writer state). The mutex is independent of State's
	// chain-allocation lock, so tracing doesn't contend with sequence
	// allocation; however it does block the processing of that frame.
	traceMu sync.Mutex

	// rootChainID is the chain ID for the root (session) chain; fixed after New.
	rootChainID string
	// agentChains maps agent_id to its per-subagent chain state. Protected by
	// agentChainsMu. Frames with a non-empty agent_id are routed here; frames
	// with no agent_id go to State (the root chain).
	agentChains   map[string]*chain.State
	agentChainsMu sync.RWMutex
}

// New returns a Pipeline. Callers configure IssuerID; Now defaults to
// time.Now.UTC.
func New(s *chain.State, ks keysource.KeySource, store pipelineStore, issuerID string) *Pipeline {
	return &Pipeline{
		State:       s,
		Keys:        ks,
		Store:       store,
		IssuerID:    issuerID,
		Now:         func() time.Time { return time.Now().UTC() },
		TraceLog:    nil,
		rootChainID: s.ChainID(),
		agentChains: make(map[string]*chain.State),
	}
}

// getOrCreateAgentState returns the chain.State and, when appropriate, a
// Delegation to backlink to the root chain.
//
// Frames with no agent_id → (p.State, nil, nil): root chain, no delegation.
// Frames with a known agent_id → (existing state, delegation?, nil): delegation
// is non-nil only while the chain's first receipt has not yet been committed
// (NextSeq still 1). This covers retries after a rollback and the
// processWithDrop→processLive fallback — both leave NextSeq at 1 with no
// committed receipt, and both must carry the delegation on the eventual first
// receipt of the subagent chain.
// Frames with a new agent_id → (new state, &Delegation{...}, nil) on creation.
//
// DB I/O (LoadFromStore, buildDelegation) is performed outside the write lock
// so agentChainsMu is never held across blocking store queries.
func (p *Pipeline) getOrCreateAgentState(agentID string) (*chain.State, *receipt.Delegation, error) {
	if agentID == "" {
		return p.State, nil, nil
	}
	// Fast path: chain already exists for this agent.
	p.agentChainsMu.RLock()
	s, ok := p.agentChains[agentID]
	p.agentChainsMu.RUnlock()
	if ok {
		// Re-derive delegation when the first receipt has not yet been committed.
		// NextSeq stays at 1 after a Rollback, so a failed build/sign/insert
		// attempt on what is logically the first receipt leaves the chain in a
		// state where the next attempt must still carry the delegation.
		if s.NextSeq() != 1 {
			return s, nil, nil
		}
		del, err := p.buildDelegation()
		if err != nil {
			return nil, nil, err
		}
		return s, del, nil
	}

	// Slow path: load from store outside the write lock so blocking I/O does not
	// hold agentChainsMu and serialize all concurrent frame goroutines.
	//
	// Chain ID is deterministic: base chain + "/agent/" + agent_id.
	// This lets the daemon resume an agent chain across restarts when the same
	// agent reconnects within a session.
	chainID := p.rootChainID + "/agent/" + agentID
	s, err := chain.LoadFromStore(p.Store, chainID)
	if err != nil {
		return nil, nil, fmt.Errorf("load agent chain %q: %w", chainID, err)
	}
	var del *receipt.Delegation
	if s.NextSeq() == 1 {
		del, err = p.buildDelegation()
		if err != nil {
			return nil, nil, err
		}
	}

	// Install under write lock; double-check to detect a concurrent creator.
	p.agentChainsMu.Lock()
	defer p.agentChainsMu.Unlock()
	if existing, ok := p.agentChains[agentID]; ok {
		// Lost the creation race. Reuse the delegation we already computed if the
		// winner's chain is still at seq 1 (first receipt not yet committed);
		// otherwise the first receipt already landed without our delegation object.
		if existing.NextSeq() == 1 {
			return existing, del, nil
		}
		return existing, nil, nil
	}
	p.agentChains[agentID] = s
	return s, del, nil
}

// buildDelegation queries the root chain tail and returns a Delegation for use
// on the first receipt of a new subagent chain. Returns nil, nil when the root
// chain has no receipts yet — delegation is optional per spec.
func (p *Pipeline) buildDelegation() (*receipt.Delegation, error) {
	tail, err := p.Store.GetChainTailReceipt(p.rootChainID)
	if err != nil {
		return nil, fmt.Errorf("get root chain tail for delegation: %w", err)
	}
	if tail == nil {
		return nil, nil
	}
	return &receipt.Delegation{
		ParentChainID:   p.rootChainID,
		ParentReceiptID: tail.ID,
		Delegator:       receipt.Delegator{ID: p.IssuerID},
	}, nil
}

// Process is the daemon's per-frame entrypoint. It parses the frame, allocates
// the next chain slot(s), builds and signs the AgentReceipt(s), persists them
// via store.Insert, and commits the chain allocation. A non-nil return always
// means the live receipt was NOT persisted.
//
// When the frame carries a positive DropCount, Process uses chain.AllocatePair
// to reserve two consecutive slots under one mutex acquisition, guaranteeing
// the synthetic events_dropped receipt and the live receipt are adjacent in the
// chain even under concurrent emitter connections. If the synthetic insert
// fails, Process logs the error and falls back to a normal single-slot insert
// for the live receipt — the gap becomes invisible in that edge case but the
// live receipt is still preserved.
func (p *Pipeline) Process(f socket.Frame) error {
	var frame EmitterFrame
	if err := json.Unmarshal(f.Payload, &frame); err != nil {
		return fmt.Errorf("decode emitter frame: %w", err)
	}
	if err := validateFrame(&frame); err != nil {
		return fmt.Errorf("invalid emitter frame: %w", err)
	}

	p.trace("frame received: session=%s channel=%s tool=%s drop_count=%d",
		frame.SessionID, frame.Channel, frame.Tool.Name, frame.DropCount)

	if frame.DropCount > 0 {
		return p.processWithDrop(&frame, f.Peer)
	}
	return p.processLive(&frame, f.Peer)
}

// processWithDrop inserts a synthetic events_dropped receipt immediately
// followed by the live receipt, holding one AllocatePair lock across both
// inserts so they are guaranteed adjacent. On synthetic failure it logs and
// falls back to processLive for the live receipt alone.
//
// Panic safety: pair.Rollback() is deferred immediately after AllocatePair so
// any panic before CommitFirst releases the mutex. After CommitFirst, the
// returned liveAlloc shares the same release Once so deferring liveAlloc.Rollback()
// covers panics in the second phase; pair.Rollback() becomes a no-op.
func (p *Pipeline) processWithDrop(frame *EmitterFrame, peer socket.PeerCred) error {
	state, delegation, err := p.getOrCreateAgentState(frame.AgentID)
	if err != nil {
		return err
	}
	chainID := state.ChainID()

	pair := state.AllocatePair()
	defer pair.Rollback() // panic-safety: no-op after CommitFirst

	// Delegation belongs on the first receipt in the chain. Guard by the
	// actual allocated sequence so that if a concurrent goroutine committed
	// seq 1 between getOrCreateAgentState and AllocatePair, we do not
	// incorrectly attach delegation to a non-first receipt.
	dropDelegation := delegation
	if pair.FirstSeq != 1 {
		dropDelegation = nil
	}

	synthetic, synHash, err := p.buildAndSignDropReceipt(
		frame.DropCount, frame.SessionID, peer, pair.FirstSeq, pair.FirstPrev, chainID, dropDelegation)
	if err != nil {
		pair.Rollback()
		p.logError("build events_dropped receipt (drop_count=%d session=%s): %v",
			frame.DropCount, frame.SessionID, err)
		return p.processLive(frame, peer)
	}
	p.trace("events_dropped receipt: session=%s drop_count=%d seq=%d",
		frame.SessionID, frame.DropCount, pair.FirstSeq)

	if err := p.Store.Insert(synthetic, synHash); err != nil {
		pair.Rollback()
		p.logError("insert events_dropped receipt (drop_count=%d session=%s): %v",
			frame.DropCount, frame.SessionID, err)
		return p.processLive(frame, peer)
	}

	// CommitFirst advances the chain past the synthetic slot and returns the
	// allocation for the live receipt. The mutex remains held so no other
	// frame can interleave between the two receipts.
	liveAlloc := pair.CommitFirst(synHash)
	defer liveAlloc.Rollback() // panic-safety; pair.Rollback defer is now a no-op

	// The live receipt is always the second in the pair (seq FirstSeq+1) so
	// delegation never belongs here regardless of agent chain state.
	live, liveHash, err := p.buildAndSign(frame, peer, liveAlloc, chainID, nil)
	if err != nil {
		liveAlloc.Rollback() // releases lock; chain is at pair.FirstSeq+1
		return err
	}
	p.trace("receipt signed: seq=%d hash=%s", liveAlloc.Sequence, liveHash)

	if err := p.Store.Insert(live, liveHash); err != nil {
		liveAlloc.Rollback()
		return fmt.Errorf("insert receipt: %w", err)
	}
	p.trace("receipt stored: seq=%d", liveAlloc.Sequence)

	liveAlloc.Commit(liveHash)
	return nil
}

// processLive allocates one chain slot, builds, inserts, and commits the live
// receipt. Used for frames with DropCount == 0 and as fallback when the
// synthetic insert fails.
func (p *Pipeline) processLive(frame *EmitterFrame, peer socket.PeerCred) error {
	state, delegation, err := p.getOrCreateAgentState(frame.AgentID)
	if err != nil {
		return err
	}

	alloc := state.Allocate()
	defer alloc.Rollback()

	// Guard by actual sequence: a concurrent goroutine may have committed
	// seq 1 between getOrCreateAgentState and Allocate, so check the
	// allocated sequence rather than the earlier NextSeq observation.
	if alloc.Sequence != 1 {
		delegation = nil
	}

	signed, hash, err := p.buildAndSign(frame, peer, alloc, state.ChainID(), delegation)
	if err != nil {
		return err
	}
	p.trace("receipt signed: seq=%d hash=%s", alloc.Sequence, hash)

	if err := p.Store.Insert(signed, hash); err != nil {
		return fmt.Errorf("insert receipt: %w", err)
	}
	p.trace("receipt stored: seq=%d", alloc.Sequence)

	alloc.Commit(hash)
	return nil
}

// logError calls ErrorLog if it is set. Used for non-fatal conditions where
// Process still returns nil (e.g., synthetic receipt failure with live receipt
// committed). Callers hold no locks when calling this.
func (p *Pipeline) logError(format string, args ...any) {
	if p.ErrorLog == nil {
		return
	}
	p.ErrorLog(format, args...)
}

// trace writes a trace line to TraceLog if it's not nil. Safe to call
// concurrently — see Pipeline.traceMu.
func (p *Pipeline) trace(format string, args ...interface{}) {
	if p.TraceLog == nil {
		return
	}
	p.traceMu.Lock()
	defer p.traceMu.Unlock()
	fmt.Fprintf(p.TraceLog, format+"\n", args...)
}

func validateFrame(f *EmitterFrame) error {
	if f.Version == "" {
		return fmt.Errorf("missing v")
	}
	if f.Version != SupportedFrameVersion {
		return fmt.Errorf("unsupported frame version %q (this daemon accepts %q)", f.Version, SupportedFrameVersion)
	}
	if f.SessionID == "" {
		return fmt.Errorf("missing session_id")
	}
	// ts_emit is part of the documented Phase 1 wire schema. The daemon
	// doesn't trust it for the receipt timestamp (action.timestamp,
	// issuanceDate, proof.created all come from p.Now()), but requiring a
	// well-formed value pins the emitter contract — silently accepting
	// "" or junk text would let a buggy emitter ship without anyone
	// noticing. RFC3339[Nano] match the format the README documents.
	if f.TsEmit == "" {
		return fmt.Errorf("missing ts_emit")
	}
	if _, err := time.Parse(time.RFC3339Nano, f.TsEmit); err != nil {
		// time.RFC3339Nano accepts both RFC3339 and the nanosecond extension.
		return fmt.Errorf("ts_emit %q is not RFC3339/RFC3339Nano: %w", f.TsEmit, err)
	}
	if f.Channel == "" {
		return fmt.Errorf("missing channel")
	}
	if f.Tool.Name == "" {
		return fmt.Errorf("missing tool.name")
	}
	switch f.Decision {
	case "":
		return fmt.Errorf("missing decision")
	case "allowed", "denied", "pending":
		// ok
	default:
		return fmt.Errorf("unknown decision %q (want allowed|denied|pending)", f.Decision)
	}
	if f.DropCount < 0 {
		return fmt.Errorf("drop_count %d is negative", f.DropCount)
	}
	// Validate proxy-supplied identity fields: cap length and enforce
	// operator consistency (operator_name requires operator_id per spec).
	if len(f.IssuerName) > maxIdentityFieldLen {
		return fmt.Errorf("issuer_name exceeds %d bytes (got %d)", maxIdentityFieldLen, len(f.IssuerName))
	}
	if len(f.IssuerModel) > maxIdentityFieldLen {
		return fmt.Errorf("issuer_model exceeds %d bytes (got %d)", maxIdentityFieldLen, len(f.IssuerModel))
	}
	if len(f.OperatorID) > maxIdentityFieldLen {
		return fmt.Errorf("operator_id exceeds %d bytes (got %d)", maxIdentityFieldLen, len(f.OperatorID))
	}
	if len(f.OperatorName) > maxIdentityFieldLen {
		return fmt.Errorf("operator_name exceeds %d bytes (got %d)", maxIdentityFieldLen, len(f.OperatorName))
	}
	if f.OperatorName != "" && f.OperatorID == "" {
		return fmt.Errorf("operator_name set without operator_id")
	}
	if len(f.IdempotencyKey) > maxIdentityFieldLen {
		return fmt.Errorf("idempotency_key exceeds %d bytes (got %d)", maxIdentityFieldLen, len(f.IdempotencyKey))
	}
	if len(f.CorrelationID) > maxIdentityFieldLen {
		return fmt.Errorf("correlation_id exceeds %d bytes (got %d)", maxIdentityFieldLen, len(f.CorrelationID))
	}
	if len(f.AgentID) > maxIdentityFieldLen {
		return fmt.Errorf("agent_id exceeds %d bytes (got %d)", maxIdentityFieldLen, len(f.AgentID))
	}
	if strings.ContainsAny(f.AgentID, "/\x00") {
		return fmt.Errorf("agent_id must not contain '/' or null bytes")
	}
	if len(f.AgentType) > maxIdentityFieldLen {
		return fmt.Errorf("agent_type exceeds %d bytes (got %d)", maxIdentityFieldLen, len(f.AgentType))
	}
	if len(f.Model) > maxIdentityFieldLen {
		return fmt.Errorf("model exceeds %d bytes (got %d)", maxIdentityFieldLen, len(f.Model))
	}
	if len(f.CaptureMethod) > maxIdentityFieldLen {
		return fmt.Errorf("capture_method exceeds %d bytes (got %d)", maxIdentityFieldLen, len(f.CaptureMethod))
	}
	if len(f.TargetSystem) > maxIdentityFieldLen {
		return fmt.Errorf("target_system exceeds %d bytes (got %d)", maxIdentityFieldLen, len(f.TargetSystem))
	}
	if len(f.TargetResource) > maxTargetResourceLen {
		return fmt.Errorf("target_resource exceeds %d bytes (got %d)", maxTargetResourceLen, len(f.TargetResource))
	}
	// target_system and target_resource must both be set or both absent.
	// A half-populated target would produce ActionTarget{System:""} or
	// ActionTarget{Resource:""} in the signed receipt because ActionTarget.System
	// carries no omitempty tag.
	if (f.TargetSystem != "") != (f.TargetResource != "") {
		return fmt.Errorf("target_system and target_resource must both be set or both absent")
	}
	// Input and Output are accepted as any valid JSON value (object, array,
	// primitive, or null). json.Unmarshal into EmitterFrame already validated
	// JSON syntax, so anything reaching this point is well-formed. The hash
	// computation happens in buildAndSign; null/empty are skipped there.
	return nil
}

// mcpOutputIsError reports whether an MCP tool response carries
// `"isError": true`. The MCP `CallToolResult` envelope signals tool-level
// failure with this flag; the surrounding JSON-RPC call still succeeds, so
// f.Error is empty and the daemon would otherwise stamp outcome.status as
// "success". See ADR-0010 and the MCP spec (CallToolResult).
//
// Gated on channel == "mcp" because the envelope is MCP-specific: other
// channels may use a top-level `isError` field with different semantics, and
// the daemon must not silently reinterpret them. Returns false on parse
// failure, non-object output, missing field, or a non-true value — only an
// explicit boolean true escalates to failure.
func mcpOutputIsError(channel string, raw json.RawMessage) bool {
	if channel != "mcp" || !hasJSONPayload(raw) {
		return false
	}
	var env struct {
		IsError *bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return false
	}
	return env.IsError != nil && *env.IsError
}

// hasJSONPayload reports whether raw is a JSON value other than null.
// Whitespace and the literal "null" both count as no-payload.
func hasJSONPayload(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false
	}
	return !bytes.Equal(trimmed, []byte("null"))
}

// canonicalSHA256 canonicalises raw per RFC 8785 and returns the
// "sha256:<hex>" digest. Callers MUST check hasJSONPayload first: a literal
// JSON null reaches receipt.Canonicalize and hashes "null", which would
// falsely commit the daemon to a value the emitter did not send.
//
// raw is passed to receipt.Canonicalize directly; json.RawMessage's
// MarshalJSON returns its bytes verbatim, so Canonicalize's existing
// marshal+unmarshal handles the parse without us doing an extra unmarshal
// here. (Empty RawMessage is not a callable shape — Canonicalize would
// return EOF — but hasJSONPayload rejects it before we get here.)
//
// Errors are real and expected: a JSON number like `1e400` is syntactically
// valid (so it survives EmitterFrame's outer Unmarshal as a token) but
// overflows float64 when Canonicalize re-parses into Go's `any`. The daemon
// MUST surface that as a per-frame error and keep running; a panic here
// would let any authenticated emitter DoS the daemon — and the orphaned
// chain.State allocation, even with the deferred-Rollback guard in Process,
// would still mean Process never returns to the listener loop for the bad
// frame.
func canonicalSHA256(raw json.RawMessage) (string, error) {
	canonical, err := receipt.Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("canonicalize: %w", err)
	}
	return receipt.SHA256Hash(canonical), nil
}

// encryptDisclosure encrypts the emitter input into an HPKE disclosure envelope
// addressed to the configured forensic public key (ADR-0012). The recipient kid
// is the key's canonical fingerprint (ADR-0015), so a forensic tool holding the
// matching private key can locate this receipt without a key registry.
//
// It returns nil on any failure (non-object input, HPKE error) after logging,
// so the caller falls back to a hash-only receipt rather than dropping the
// event. The hash is computed independently by the caller and is unaffected.
func (p *Pipeline) encryptDisclosure(input json.RawMessage) *receipt.DisclosureEnvelope {
	var params map[string]any
	if err := json.Unmarshal(input, &params); err != nil {
		// Disclosure requires a JSON object (HPKE plaintext is the canonical
		// object); arrays/primitives cannot be disclosed. Hash-only fallback.
		p.logError("disclosure skipped (input is not a JSON object): %v", err)
		return nil
	}
	kid, err := receipt.ForensicKeyFingerprint(p.ForensicPublicKey)
	if err != nil {
		p.logError("disclosure skipped (forensic key fingerprint failed): %v", err)
		return nil
	}
	env, err := receipt.EncryptDisclosure(params, p.ForensicPublicKey, kid)
	if err != nil {
		p.logError("disclosure skipped (encryption failed): %v", err)
		return nil
	}
	return env
}

func (p *Pipeline) buildAndSign(
	f *EmitterFrame,
	peer socket.PeerCred,
	alloc chain.Allocation,
	chainID string,
	delegation *receipt.Delegation,
) (receipt.AgentReceipt, string, error) {
	now := p.Now().Format(time.RFC3339)

	// receipt.Chain.Sequence is `int`, which is 32-bit on 32-bit platforms.
	// Refuse rather than silently overflow into a negative or wrapped value
	// that would corrupt chain verification downstream.
	if alloc.Sequence > int64(math.MaxInt) {
		return receipt.AgentReceipt{}, "", fmt.Errorf("chain sequence %d exceeds int range on this platform (max %d)", alloc.Sequence, math.MaxInt)
	}

	// validateFrame already restricted f.Decision to the supported set, so the
	// switch never falls through.
	// A non-empty error field means the tool call ran but the upstream returned
	// an error; even though the proxy permitted the call (decision="allowed"),
	// the execution outcome is a failure.
	var status receipt.OutcomeStatus
	switch f.Decision {
	case "allowed":
		if f.Error != "" || mcpOutputIsError(f.Channel, f.Output) {
			status = receipt.StatusFailure
		} else {
			status = receipt.StatusSuccess
		}
	case "denied":
		status = receipt.StatusFailure
	case "pending":
		status = receipt.StatusPending
	}

	// Prefer an emitter-declared taxonomic action type; it is what lets the
	// daemon resolve a real risk level (and thus makes risk-based disclosure
	// effective). Fall back to a synthetic "<channel>[.<server>].<tool>" type
	// when the emitter does not declare one — that type rarely matches the
	// taxonomy, so risk defaults to medium (see below).
	actionType := f.ActionType
	if actionType == "" {
		actionType = f.Channel + "." + f.Tool.Name
		if f.Tool.Server != "" {
			actionType = f.Channel + "." + f.Tool.Server + "." + f.Tool.Name
		}
	}

	// OS-attested peer credentials populate action.peer_credential — the
	// dedicated typed field landed by spec v0.3.0 (ADR-0010 + PR #496). The
	// daemon vouches for these values via signature; they are present only on
	// receipts emitted through the daemon and absent on direct-SDK emissions
	// (where the SDK has no privileged channel to attest peer identity).
	peerCred := buildPeerCred(peer)

	// Risk derives from the taxonomy. A synthetic fallback type like
	// "mcp_proxy.github.list_repos" does not match any built-in entry, so
	// ResolveActionType falls back to UnknownAction (RiskMedium) — a safer
	// default than RiskLow. An emitter-declared action_type (above) that maps to
	// a taxonomy entry yields its real risk, which is what makes risk-based
	// disclosure ("high") fire correctly.
	risk := taxonomy.ResolveActionType(actionType).RiskLevel

	action := receipt.Action{
		Type:           actionType,
		ToolName:       f.Tool.Name,
		RiskLevel:      risk,
		Timestamp:      now,
		PeerCredential: peerCred,
		IdempotencyKey: f.IdempotencyKey,
	}
	if f.TargetSystem != "" && f.TargetResource != "" {
		action.Target = &receipt.ActionTarget{
			System:   f.TargetSystem,
			Resource: f.TargetResource,
		}
	}
	if hasJSONPayload(f.Input) {
		hash, err := canonicalSHA256(f.Input)
		if err != nil {
			return receipt.AgentReceipt{}, "", fmt.Errorf("hash input: %w", err)
		}
		action.ParametersHash = hash

		// Forensic disclosure (ADR-0012): when a forensic public key is
		// configured and the policy elects this action, encrypt the parameters
		// to that key and attach the HPKE envelope. The hash above always
		// commits to the original canonical bytes, so tamper-evidence does not
		// depend on disclosure; the envelope is additive, recoverable only by
		// the holder of the matching private key.
		//
		// Encryption is best-effort: any failure (bad key, non-object input,
		// HPKE error) falls back to hash-only for this receipt and logs, rather
		// than dropping the event. A privacy-preserving hash-only receipt keeps
		// the chain gap-free; refusing the event would punch a hole in the audit
		// trail, which is the worse outcome for an audit system.
		if len(p.ForensicPublicKey) == 32 &&
			p.DisclosurePolicy.ShouldDisclose(actionType, risk) {
			if env := p.encryptDisclosure(f.Input); env != nil {
				action.ParametersDisclosure = env
			}
		}
	}

	// Redaction MUST happen AFTER hashing. The hash commits to the raw
	// canonical bytes; redaction only sanitises the human-readable string
	// fields written into the receipt body. The error field is not hashed, so
	// it is redacted unconditionally when a Redactor is set.
	errText := f.Error
	if p.Redactor != nil {
		errText = p.Redactor.Redact(errText)
	}

	outcome := receipt.Outcome{
		Status: status,
		Error:  errText,
	}
	if hasJSONPayload(f.Output) {
		// Hash Output here rather than via receipt.CreateInput.ResponseBody
		// (which panics on bad JSON). f.Output is emitter-controlled and may
		// be syntactically valid JSON yet still fail re-unmarshal — see
		// canonicalSHA256 doc — so the daemon MUST surface that as an error,
		// not a crash.
		hash, err := canonicalSHA256(f.Output)
		if err != nil {
			return receipt.AgentReceipt{}, "", fmt.Errorf("hash output: %w", err)
		}
		outcome.ResponseHash = hash
	}

	return p.signAndHash(receipt.CreateInput{
		Issuer:        issuerFromFrame(f, p.IssuerID),
		Principal:     principalFromPeer(peer),
		Action:        action,
		Outcome:       outcome,
		CorrelationID: f.CorrelationID,
		Delegation:    delegation,
		Chain: receipt.Chain{
			Sequence:            int(alloc.Sequence),
			PreviousReceiptHash: alloc.PrevHash,
			ChainID:             chainID,
		},
	}, now)
}

// issuerFromFrame builds the receipt Issuer from the emitter frame and the
// daemon's own DID. Name, Model, and Operator come from the proxy; they are
// empty/nil when an old proxy that predates this field set emits the frame.
func issuerFromFrame(f *EmitterFrame, daemonID string) receipt.Issuer {
	var op *receipt.Operator
	if f.OperatorID != "" {
		op = &receipt.Operator{ID: f.OperatorID, Name: f.OperatorName}
	}
	// issuer.runtime is the ADR-0026 open container for runtime/observability
	// metadata. agent_id/agent_type identify a sub-agent (and gate chain
	// routing); model/usage/capture_method are observability fields the emitter
	// derived for the call (e.g. from the session transcript) and, unlike the
	// agent identity, apply to root-chain receipts too. So runtime is emitted
	// whenever ANY of these are present — a root receipt now carries it when it
	// has transcript-derived model/usage even though it has no agent_id.
	// Forward usage verbatim, but only a real JSON payload — a literal null or
	// empty must not be stored as the runtime's reported usage.
	hasUsage := hasJSONPayload(f.Usage)
	var runtime *receipt.Runtime
	if f.AgentID != "" || f.Model != "" || f.CaptureMethod != "" || hasUsage {
		runtime = &receipt.Runtime{
			AgentID:       f.AgentID,
			AgentType:     f.AgentType,
			Model:         f.Model,
			CaptureMethod: f.CaptureMethod,
		}
		if hasUsage {
			runtime.Usage = f.Usage
		}
	}
	return receipt.Issuer{
		ID:        daemonID,
		Type:      "AgentReceiptsDaemon",
		Name:      f.IssuerName,
		Model:     f.IssuerModel,
		Operator:  op,
		SessionID: f.SessionID,
		Runtime:   runtime,
	}
}

// buildAndSignDropReceipt constructs a synthetic events_dropped receipt.
// seq and prevHash come directly from PairAlloc.FirstSeq/FirstPrev rather
// than from a chain.Allocation, avoiding the ambiguous no-op Allocation that
// would be needed to represent the first PairAlloc slot.
//
// Drop receipts are synthetic — the proxy didn't supply identity for the
// gap, so Name/Model/Operator are deliberately left empty (vs. live
// receipts which get them from the frame via issuerFromFrame).
func (p *Pipeline) buildAndSignDropReceipt(
	dropCount int64,
	sessionID string,
	peer socket.PeerCred,
	seq int64,
	prevHash *string,
	chainID string,
	delegation *receipt.Delegation,
) (receipt.AgentReceipt, string, error) {
	now := p.Now().Format(time.RFC3339)

	if seq > int64(math.MaxInt) {
		return receipt.AgentReceipt{}, "", fmt.Errorf("chain sequence %d exceeds int range on this platform (max %d)", seq, math.MaxInt)
	}

	return p.signAndHash(receipt.CreateInput{
		Issuer: receipt.Issuer{
			ID:        p.IssuerID,
			Type:      "AgentReceiptsDaemon",
			SessionID: sessionID,
		},
		Principal:  principalFromPeer(peer),
		Delegation: delegation,
		Action: receipt.Action{
			Type:           actionTypeEventsDropped,
			ToolName:       "events_dropped",
			RiskLevel:      receipt.RiskLow,
			Timestamp:      now,
			PeerCredential: buildPeerCred(peer),
			EmitterMetadata: &receipt.EmitterMetadata{
				DropCount: dropCount,
			},
		},
		Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
		Chain: receipt.Chain{
			Sequence:            int(seq),
			PreviousReceiptHash: prevHash,
			ChainID:             chainID,
		},
	}, now)
}

// buildPeerCred converts a socket.PeerCred into a receipt.PeerCredential. UID
// and GID use pointer semantics so root (uid=0 / gid=0) serialises as
// `"uid":0` rather than being silently dropped by omitempty. On platforms with
// no POSIX UID/GID concept (anything other than linux/darwin today), both
// fields are left nil — the absent-field semantics the spec prescribes for
// Windows and similar platforms.
func buildPeerCred(peer socket.PeerCred) *receipt.PeerCredential {
	pc := &receipt.PeerCredential{
		Platform: peer.Platform,
		PID:      peer.PID,
		ExePath:  peer.ExePath,
	}
	if peer.Platform == "linux" || peer.Platform == "darwin" {
		pc.UID = ptrUint32(peer.UID)
		pc.GID = ptrUint32(peer.GID)
	}
	return pc
}

func ptrUint32(v uint32) *uint32 { return &v }

// lookupUID resolves a POSIX uid to an OS user. It is a package var so tests can
// stub the host user database and stay deterministic across machines.
var lookupUID = user.LookupId

// principalFromPeer derives the receipt Principal from kernel-attested peer
// credentials. Absent an emitter-supplied principal, the OS user that ran the
// emitting process is the best attested stand-in for "on whose authority": it is
// the same LOCAL_PEERCRED/SO_PEERCRED identity the daemon already vouches for in
// action.peer_credential, so the principal inherits that field's tamper-evidence
// instead of trusting an emitter self-report.
//
// The kernel-attested uid is the stable fact and is preserved verbatim in
// action.peer_credential. This resolves it to the host's login name for a
// human-readable principal (did:user:<login>) — the name is the daemon's lookup
// of an attested uid on its own host, not an emitter self-report. It falls back
// to the numeric did:user:<platform>:<uid> when the host user database has no
// entry (containers, directory-only users, deleted accounts), so the principal
// is always at least the attested uid. The platform gate mirrors buildPeerCred:
// platforms without a POSIX uid — and synthetic receipts with no connecting peer
// — fall back to the did:user:unknown sentinel.
//
// The derived DID names the OS user, not a configured human or mandate. Mapping
// a uid to a named principal or an authorization grant is a higher layer that
// builds on this attested floor.
func principalFromPeer(peer socket.PeerCred) receipt.Principal {
	if peer.Platform != "linux" && peer.Platform != "darwin" {
		return receipt.Principal{ID: "did:user:unknown"}
	}
	if u, err := lookupUID(strconv.FormatUint(uint64(peer.UID), 10)); err == nil && u.Username != "" {
		return receipt.Principal{ID: "did:user:" + u.Username}
	}
	return receipt.Principal{ID: fmt.Sprintf("did:user:%s:%d", peer.Platform, peer.UID)}
}

// EmitTerminator emits interrupted-chain terminal receipts for all open chains
// (root chain and any per-agent chains). It is called once, synchronously,
// after the IPC listener has shut down and all in-flight frames have been
// processed — all chain state mutexes are free.
//
// ctx should carry a short deadline (~200ms). Deadline/cancel errors are
// non-fatal — the verifier's "unknown" classification is the documented
// fallback for chains that never receive a terminator. Store or signing
// failures are returned wrapped so the caller can surface them as fatal.
func (p *Pipeline) EmitTerminator(ctx context.Context) error {
	// Terminate agent chains first, then the root chain.
	p.agentChainsMu.RLock()
	agentStates := make([]*chain.State, 0, len(p.agentChains))
	for _, s := range p.agentChains {
		agentStates = append(agentStates, s)
	}
	p.agentChainsMu.RUnlock()

	// Attempt all chains; a single failing agent chain must not prevent the
	// remaining chains (or the root chain) from receiving their terminators.
	// Return the first error after all attempts complete.
	var firstErr error
	for _, s := range agentStates {
		if err := p.emitTerminatorForChain(ctx, s); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := p.emitTerminatorForChain(ctx, p.State); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// emitTerminatorForChain emits an interrupted-chain terminal receipt for s if
// it has at least one receipt and is not already terminated.
func (p *Pipeline) emitTerminatorForChain(ctx context.Context, s *chain.State) error {
	// Fast path: no receipts in this chain.
	if s.NextSeq() == 1 {
		return nil
	}

	// Check whether the chain's tail is already a terminal receipt. This
	// covers the cross-restart case where a previous daemon run emitted an
	// interrupted terminator that is now the tail.
	chainID := s.ChainID()
	tail, err := p.Store.GetChainTailReceipt(chainID)
	if err != nil {
		return fmt.Errorf("check chain tail: %w", err)
	}
	if tail == nil {
		return nil
	}
	if tail.CredentialSubject.Chain.Terminal != nil && *tail.CredentialSubject.Chain.Terminal {
		return nil
	}

	// Respect the caller's deadline before touching shared state.
	// Prefer ctx.Err() when set; fall back to a wall-clock check because timer
	// goroutines can lag, making ctx.Err() alone unreliable for sub-ms deadlines.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("deadline exceeded before terminator: %w", ctxErr)
	}
	if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
		return fmt.Errorf("deadline exceeded before terminator: %w", context.DeadlineExceeded)
	}

	alloc := s.Allocate()
	defer alloc.Rollback()

	if alloc.Sequence > int64(math.MaxInt) {
		return fmt.Errorf("chain sequence %d exceeds int range on this platform (max %d)", alloc.Sequence, math.MaxInt)
	}

	now := p.Now().Format(time.RFC3339)
	signed, hash, err := p.signAndHash(receipt.CreateInput{
		Issuer: receipt.Issuer{
			ID:   p.IssuerID,
			Type: "AgentReceiptsDaemon",
		},
		Principal: receipt.Principal{ID: "did:user:unknown"},
		Action: receipt.Action{
			Type:      actionTypeChainInterrupted,
			ToolName:  "chain_interrupted",
			RiskLevel: receipt.RiskLow,
			Timestamp: now,
		},
		Outcome: receipt.Outcome{Status: receipt.StatusSuccess},
		Chain: receipt.Chain{
			Sequence:            int(alloc.Sequence),
			PreviousReceiptHash: alloc.PrevHash,
			ChainID:             chainID,
		},
		Terminal:          true,
		TerminationStatus: receipt.ChainStatusInterrupted,
	}, now)
	if err != nil {
		return fmt.Errorf("build terminator: %w", err)
	}

	// Check deadline again before the store write.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("deadline exceeded before store write: %w", ctxErr)
	}
	if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
		return fmt.Errorf("deadline exceeded before store write: %w", context.DeadlineExceeded)
	}

	if err := p.Store.Insert(signed, hash); err != nil {
		return fmt.Errorf("insert terminator: %w", err)
	}

	alloc.Commit(hash)
	return nil
}

// signAndHash builds, signs, and hashes one receipt. It is the common tail
// shared by buildAndSign and buildAndSignDropReceipt — both construct a
// CreateInput, set the issuance timestamp, and then need identical
// canonicalize → sign → hash steps.
func (p *Pipeline) signAndHash(in receipt.CreateInput, now string) (receipt.AgentReceipt, string, error) {
	unsigned := receipt.Create(in)
	// receipt.Create stamps IssuanceDate from time.Now() internally. Replace it
	// with our deterministic now so action.timestamp, issuanceDate, and
	// proof.created all share a single value (and tests can override Now).
	unsigned.IssuanceDate = now

	canonical, err := receipt.Canonicalize(unsigned)
	if err != nil {
		return receipt.AgentReceipt{}, "", fmt.Errorf("canonicalize: %w", err)
	}
	sig, err := p.Keys.Sign([]byte(canonical))
	if err != nil {
		return receipt.AgentReceipt{}, "", fmt.Errorf("sign: %w", err)
	}

	signed := receipt.AgentReceipt{
		Context:           unsigned.Context,
		ID:                unsigned.ID,
		Type:              unsigned.Type,
		Version:           unsigned.Version,
		Issuer:            unsigned.Issuer,
		IssuanceDate:      unsigned.IssuanceDate,
		CredentialSubject: unsigned.CredentialSubject,
		Proof: receipt.Proof{
			Type:               "Ed25519Signature2020",
			Created:            now,
			VerificationMethod: p.Keys.VerificationMethod(),
			ProofPurpose:       "assertionMethod",
			ProofValue:         multibaseBase64URL + base64.RawURLEncoding.EncodeToString(sig),
		},
	}

	hash, err := receipt.HashReceipt(signed)
	if err != nil {
		return receipt.AgentReceipt{}, "", fmt.Errorf("hash receipt: %w", err)
	}
	return signed, hash, nil
}
