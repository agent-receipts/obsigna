// Package emitter is a thin fire-and-forget client for the agent-receipts
// daemon's local Unix-domain socket. Emit forwards a tool-call frame to the
// daemon, which captures peer credentials, canonicalises (RFC 8785), signs
// (Ed25519), and persists the receipt. The emitter does NO crypto, NO
// canonicalisation, and holds NO chain state — those moved to the daemon
// per ADR-0010 (daemon process separation, 2026-05-03).
//
// Concurrency: Emit is safe to call from multiple goroutines on a single
// Emitter instance. A mutex serialises the length-prefix + body write so
// concurrent calls cannot interleave bytes on the same socket connection.
// The dial step happens OUTSIDE the mutex so a slow accept (up to
// dialTimeout) cannot stall sibling Emit calls past their fire-and-forget
// budget; only the framed write itself holds the lock.
//
// Failure model: Emit MUST NOT block the agent on the daemon, and it MUST NOT
// hide a transport failure it observed. When the socket is unreachable (daemon
// not started, socket file missing, broken connection) Emit logs a debug-level
// drop via the configured slog.Logger and returns a non-nil error within
// milliseconds — per ADR-0025, a known transport failure is surfaced to the
// caller, never silently swallowed. "Non-blocking" and "silent" are distinct:
// Emit stays bounded by dialTimeout + writeTimeout while still reporting the
// outcome. WithBestEffort opts back into loss-tolerant emission (Emit returns
// nil on transport failure) for callers that knowingly accept dropped events.
// The in-chain events_dropped marker still requires a live daemon to record it
// (ADR-0010); ADR-0025 adds the caller-visible signal that holds even when no
// daemon exists.
//
// Drop counter: every failed send (dial timeout, write timeout, broken
// connection) increments an atomic counter. On the next successful send the
// accumulated count is included in the frame's drop_count field and reset to
// zero, letting the daemon insert a synthetic events_dropped receipt that
// makes the gap visible in the chain. Narrow loss window: if the emitter
// process crashes after a drop but before a subsequent successful send, the
// accumulated count is lost and the gap remains permanently invisible.
package emitter

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// MaxFrameSize must agree with the daemon's socket.MaxFrameSize (1 MiB).
// Bodies larger than this are rejected at Emit; the daemon would refuse
// them at read time anyway.
const MaxFrameSize = 1 << 20

// MaxIdentityFieldLen is the maximum byte length of each identity field
// (IssuerName, IssuerModel, OperatorID, OperatorName). The daemon enforces
// the same limit; the emitter validates client-side so violations surface
// before the write rather than as silent daemon-side rejections.
const MaxIdentityFieldLen = 256

// MaxTargetResourceLen is the maximum byte length of Target.Resource. File
// paths can reach 4096 bytes on Linux (PATH_MAX), so a wider cap is used
// rather than MaxIdentityFieldLen. The daemon enforces the same limit.
const MaxTargetResourceLen = 4096

// SupportedFrameVersion mirrors the daemon's pipeline.SupportedFrameVersion.
// The wire format is versioned; bumping it requires a daemon-side
// translator, so a single supported value is the only safe contract.
const SupportedFrameVersion = "1"

// DaemonProtocolMin and DaemonProtocolMax bound, inclusive, the emitter-frame
// schema versions this SDK can speak to the daemon — its declared daemon-
// protocol range in the ADR-0024 Gate #8 sense. Today the SDK emits exactly one
// version (SupportedFrameVersion), so min == max and the value equals it. Gate
// #8 reads this range from the published SDK and asserts it intersects the
// released daemon's spoken range, so a release cannot ship an SDK/daemon pair
// that cannot talk to each other.
const (
	DaemonProtocolMin = 1
	DaemonProtocolMax = 1
)

// dialTimeout caps how long Emit blocks attempting to reach the daemon.
// 25ms is well under the fire-and-forget budget but still tolerant of
// slow filesystems on contended hosts; net.DialTimeout on AF_UNIX
// typically returns in microseconds when the socket is present.
const dialTimeout = 25 * time.Millisecond

// writeTimeout caps how long a single frame write can block. Local
// AF_UNIX writes of <1 MiB normally complete in microseconds; this
// deadline exists to enforce the fire-and-forget contract if a
// pathological case (full kernel send buffer, frozen daemon) appears.
const writeTimeout = 100 * time.Millisecond

// ErrTransport marks an error returned by Emit as a transport-layer failure
// (dial, write, or write-deadline expiry) surfaced per ADR-0025. Callers use
// errors.Is(err, ErrTransport) to distinguish a transport failure — which a
// retry or a durability wrapper (WAL) may recover — from a caller-bug error
// (invalid event, closed emitter, oversized frame) that a retry cannot fix.
var ErrTransport = errors.New("emitter: transport failure")

// Tool identifies the tool the agent invoked. Server is optional — SDK
// channels often have no server qualifier — and produces an action.type
// of "channel.name" rather than "channel.server.name".
type Tool struct {
	Server string
	Name   string
}

// Target identifies the system and resource the action operates on.
// System names a resource domain (e.g. "filesystem"); Resource is the
// path or identifier within that domain (e.g. a file path).
type Target struct {
	System   string
	Resource string
}

// Event is one tool invocation forwarded to the daemon. Input and Output
// are raw JSON bytes; the daemon canonicalises them (RFC 8785) and writes
// only the SHA-256 digest to the receipt. Either may be nil to indicate
// no payload.
type Event struct {
	Channel  string
	Tool     Tool
	Input    json.RawMessage
	Output   json.RawMessage
	Error    string
	Decision string

	// optional issuer/operator identity fields — forwarded to the daemon so
	// it can stamp receipt.Issuer.Name, receipt.Issuer.Model, and
	// receipt.Issuer.Operator. When empty, the Emitter's Defaults are used.
	IssuerName   string
	IssuerModel  string
	OperatorID   string
	OperatorName string

	// IdempotencyKey is a stable identifier for the logical operation this
	// event represents (e.g. the wrapped JSON-RPC request id). The daemon
	// stamps it onto action.idempotency_key so retries of the same operation
	// share a value and auditors can distinguish a legitimate retry from a
	// duplicated emission. Optional; omitted from the frame when empty.
	// See spec §7.3.6 and ADR-0019 §S5.
	IdempotencyKey string

	// CorrelationID links related receipts for the same logical tool invocation.
	// Populated from the runtime's tool-use correlation token (Claude Code:
	// tool_use_id). The daemon stamps it onto credentialSubject.correlation_id.
	// Optional; omitted from the frame when empty.
	CorrelationID string

	// AgentID identifies the subagent that generated this event (Claude Code:
	// agent_id). The daemon uses it to route frames to per-agent chains and to
	// populate delegation.parent_chain_id on the first receipt of a new agent.
	// Optional; omitted from the frame when empty (root agent).
	AgentID string

	// AgentType is the runtime-reported agent type label (Claude Code:
	// agent_type, e.g. "general-purpose"). Optional; omitted when empty.
	AgentType string

	// Model is the model the runtime observed producing this tool call (Claude
	// Code: derived from the session transcript). The daemon stamps it onto
	// issuer.runtime.model — observability metadata distinct from IssuerModel,
	// which populates the identity-bearing issuer.model. Optional; omitted when
	// empty.
	Model string

	// Usage is the token-usage object exactly as the runtime reported it
	// (input/output/cache tokens), forwarded verbatim to issuer.runtime.usage.
	// Must be valid JSON or nil; a non-nil empty slice is rejected at Emit.
	// Optional; omitted when nil.
	Usage json.RawMessage

	// CaptureMethod records how Model/Usage were captured (Claude Code:
	// "transcript"), stamped onto issuer.runtime.capture_method so transcript-
	// derived receipts are distinguishable from other ingesters. Optional;
	// omitted when empty.
	CaptureMethod string

	// Target identifies the resource the action operates on (e.g. a file path
	// for filesystem tools). Optional; omitted from the frame when System and
	// Resource are both empty.
	Target Target
}

// Option configures an Emitter at construction.
type Option func(*config)

type config struct {
	socketPath string
	sessionID  string
	logger     *slog.Logger
	bestEffort bool
	defaults   Identity
}

// Identity holds issuer/operator fields that the Emitter stamps on every
// frame where the corresponding Event field is empty. Set once at construction
// via WithIdentity; per-event overrides take precedence.
type Identity struct {
	IssuerName   string
	IssuerModel  string
	OperatorID   string
	OperatorName string
}

// WithSocketPath overrides the daemon socket path. When unset, the path
// is resolved from the AGENTRECEIPTS_SOCKET environment variable, then
// the per-OS default (see DefaultSocketPath).
//
// Callers that supply an explicit path bypass platform detection entirely
// and take responsibility for ensuring the path is reachable on the
// target OS. This is intentional: WithSocketPath works on any platform,
// including those where DefaultSocketPath returns an empty string.
func WithSocketPath(path string) Option {
	return func(c *config) { c.socketPath = path }
}

// WithSessionID forwards a host- or parent-process-supplied session
// identifier instead of generating a fresh UUID v4. Per ADR-0010 OQ4
// (amendment 2026-05-06), the host's session id is preferred when
// available so a single agent loop produces one logical session across
// every emitter inside it. An empty string is treated as "no host id
// provided" and New falls back to a generated UUID, since the daemon
// rejects frames with an empty session_id.
func WithSessionID(id string) Option {
	return func(c *config) { c.sessionID = id }
}

// WithLogger sets the slog.Logger used for drop diagnostics. Defaults to
// slog.Default(). Pass slog.New(slog.NewTextHandler(io.Discard, nil)) to
// silence drop logs entirely (e.g. in tests).
func WithLogger(l *slog.Logger) Option {
	return func(c *config) { c.logger = l }
}

// WithBestEffort opts out of the default emit failure contract (ADR-0025):
// Emit returns nil on dial and write failures instead of surfacing them as
// errors. Use only when the caller knowingly accepts silently dropped events
// — a high-throughput, loss-tolerant path where receipt completeness is not
// required. The default (without this option) surfaces transport failure, so
// audit-critical callers get the safe behaviour without opting in.
//
// Drops are still logged at debug level and still increment the drop counter,
// so a live daemon can record the gap as a synthetic events_dropped receipt on
// the next successful send.
func WithBestEffort() Option {
	return func(c *config) { c.bestEffort = true }
}

// WithIdentity sets default issuer/operator fields that are stamped on every
// frame. Per-event fields on Event take precedence over these defaults.
// Typically set once at construction from host auto-detection or CLI flags.
func WithIdentity(id Identity) Option {
	return func(c *config) { c.defaults = id }
}

// DaemonEmitter is the daemon-socket client. Construct with NewDaemon, fire
// events with Emit, release the socket with Close. Safe for concurrent Emit.
//
// Per ADR-0020 step 1, this type is the legacy daemon-socket adapter and
// its Emit(ctx, Event) signature takes an unsigned tool-call event frame —
// not an AgentReceipt. It therefore does NOT implement the new Emitter
// interface defined in github.com/agent-receipts/ar/sdk/go/emitters. Step 2
// of the migration (daemon learns to ingest signed receipts) is tracked
// separately.
type DaemonEmitter struct {
	// dropCount accumulates failed sends. Swapped to zero when a frame is
	// successfully written; the captured value is embedded in that frame's
	// drop_count field so the daemon can record the gap as a synthetic receipt.
	// Uses atomic.Int64 so concurrent logDrop calls never corrupt state.
	dropCount atomic.Int64

	socketPath string
	sessionID  string
	logger     *slog.Logger
	bestEffort bool
	defaults   Identity

	mu     sync.Mutex
	conn   net.Conn
	closed bool
}

// NewDaemon returns a DaemonEmitter with the given options applied. The
// session_id is fixed for the lifetime of the returned DaemonEmitter
// (ADR-0010 OQ4): every Emit, including those after a daemon reconnect,
// carries the same value. Call Close to release the socket.
//
// NewDaemon does NOT dial the daemon — dialing is lazy on the first Emit
// so that constructing an emitter cannot fail because the daemon happens
// to be down at the moment.
func NewDaemon(opts ...Option) (*DaemonEmitter, error) {
	cfg := config{}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.socketPath == "" {
		cfg.socketPath = DefaultSocketPath()
	}
	if cfg.socketPath == "" {
		return nil, fmt.Errorf("emitter: no default socket path on %s; pass WithSocketPath", runtime.GOOS)
	}
	if cfg.sessionID == "" {
		cfg.sessionID = uuid.NewString()
	}
	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}
	return &DaemonEmitter{
		socketPath: cfg.socketPath,
		sessionID:  cfg.sessionID,
		logger:     cfg.logger,
		bestEffort: cfg.bestEffort,
		defaults:   cfg.defaults,
	}, nil
}

// SessionID returns the stable per-emitter session identifier. Useful for
// tests and for callers that want to log or correlate the value the
// daemon is recording on every receipt.
func (e *DaemonEmitter) SessionID() string { return e.sessionID }

// frame mirrors daemon/internal/pipeline.EmitterFrame field-for-field.
// Defined locally so the emitter does not import a daemon-internal
// package; the wire format is the contract, not the type definition.
type frame struct {
	Version        string          `json:"v"`
	TsEmit         string          `json:"ts_emit"`
	SessionID      string          `json:"session_id"`
	Channel        string          `json:"channel"`
	Tool           frameTool       `json:"tool"`
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
	Model          string          `json:"model,omitempty"`
	Usage          json.RawMessage `json:"usage,omitempty"`
	CaptureMethod  string          `json:"capture_method,omitempty"`
	TargetSystem   string          `json:"target_system,omitempty"`
	TargetResource string          `json:"target_resource,omitempty"`
}

type frameTool struct {
	Server string `json:"server,omitempty"`
	Name   string `json:"name"`
}

// Emit sends one event to the daemon. By default (ADR-0025) it surfaces
// transport failure: when the daemon is unreachable a dial or write failure is
// logged at debug level, the conn is reset for re-dial on the next Emit, and a
// non-nil error is returned. WithBestEffort opts out, returning nil on those
// transport failures. Emit also returns an error for caller bugs (Emitter
// closed, oversized frame, invalid event fields, malformed Input/Output JSON —
// situations a retry could not fix) or when ctx is already cancelled on entry
// or is cancelled while dialling; those are unaffected by WithBestEffort.
func (e *DaemonEmitter) Emit(ctx context.Context, ev Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ev.Channel == "" {
		return errors.New("emitter: missing channel")
	}
	if ev.Tool.Name == "" {
		return errors.New("emitter: missing tool.name")
	}
	switch ev.Decision {
	case "allowed", "denied", "pending":
		// ok
	default:
		return fmt.Errorf("emitter: invalid decision %q (want allowed|denied|pending)", ev.Decision)
	}
	// Reject clearly oversized Input/Output before the more expensive
	// json.Unmarshal pass. The daemon caps frames at MaxFrameSize anyway, so
	// there is no point paying the Unmarshal cost on payloads that could never
	// fit on the wire.
	if ev.Input != nil && len(ev.Input) == 0 {
		return fmt.Errorf("emitter: Input is a non-nil empty slice; pass nil to indicate no payload")
	}
	if ev.Output != nil && len(ev.Output) == 0 {
		return fmt.Errorf("emitter: Output is a non-nil empty slice; pass nil to indicate no payload")
	}
	if ev.Usage != nil && len(ev.Usage) == 0 {
		return fmt.Errorf("emitter: Usage is a non-nil empty slice; pass nil to indicate no usage")
	}
	if len(ev.Input)+len(ev.Output)+len(ev.Usage) > MaxFrameSize {
		return fmt.Errorf("emitter: combined Input+Output+Usage payload exceeds MaxFrameSize (%d bytes)", MaxFrameSize)
	}
	// json.Valid only checks lexical syntax — `1e400` parses as a token but
	// overflows float64, so the daemon's RFC 8785 canonicalisation (which
	// re-unmarshals into Go values) would reject it. Use Unmarshal here to
	// gate exactly what the daemon can canonicalise; better to fail fast at
	// the caller than to silently drop on the daemon side.
	if len(ev.Input) > 0 {
		if err := json.Unmarshal(ev.Input, new(interface{})); err != nil {
			return fmt.Errorf("emitter: Input is not valid or representable JSON: %w", err)
		}
	}
	if len(ev.Output) > 0 {
		if err := json.Unmarshal(ev.Output, new(interface{})); err != nil {
			return fmt.Errorf("emitter: Output is not valid or representable JSON: %w", err)
		}
	}
	// Usage is forwarded verbatim into the receipt; gate it on the same
	// representable-JSON check as Input/Output so a malformed token object
	// fails fast at the caller rather than on the daemon's canonicalisation.
	if len(ev.Usage) > 0 {
		if err := json.Unmarshal(ev.Usage, new(interface{})); err != nil {
			return fmt.Errorf("emitter: Usage is not valid or representable JSON: %w", err)
		}
	}

	// Capture accumulated drops and reset the counter to zero. If this send
	// succeeds the daemon receives the count; if it fails, pendingDrops is
	// restored (see the failure paths below) so it isn't lost.
	pendingDrops := e.dropCount.Swap(0)

	// Merge per-event identity fields over the emitter-level defaults.
	issuerName := e.defaults.IssuerName
	if ev.IssuerName != "" {
		issuerName = ev.IssuerName
	}
	issuerModel := e.defaults.IssuerModel
	if ev.IssuerModel != "" {
		issuerModel = ev.IssuerModel
	}
	operatorID := e.defaults.OperatorID
	if ev.OperatorID != "" {
		operatorID = ev.OperatorID
	}
	operatorName := e.defaults.OperatorName
	if ev.OperatorName != "" {
		operatorName = ev.OperatorName
	}

	// Validate merged identity before marshalling. operator_name requires
	// operator_id (daemon enforces the same rule; catching it here surfaces
	// a clear error instead of a silent daemon-side rejection).
	if operatorName != "" && operatorID == "" {
		e.dropCount.Add(pendingDrops)
		return fmt.Errorf("emitter: operator_name requires operator_id")
	}
	// Target.System and Target.Resource must both be set or both empty.
	// A half-populated Target produces ActionTarget{System:""} or
	// ActionTarget{Resource:""} in the signed receipt — the daemon enforces
	// the same rule in validateFrame; catching it here surfaces a clear error
	// at the call site before the write.
	if (ev.Target.System != "") != (ev.Target.Resource != "") {
		e.dropCount.Add(pendingDrops)
		return fmt.Errorf("emitter: Target.System and Target.Resource must both be set or both empty")
	}
	if len(ev.Target.System) > MaxIdentityFieldLen {
		e.dropCount.Add(pendingDrops)
		return fmt.Errorf("emitter: target_system exceeds %d bytes (got %d)", MaxIdentityFieldLen, len(ev.Target.System))
	}
	if len(ev.Target.Resource) > MaxTargetResourceLen {
		e.dropCount.Add(pendingDrops)
		return fmt.Errorf("emitter: target_resource exceeds %d bytes (got %d)", MaxTargetResourceLen, len(ev.Target.Resource))
	}
	// Mirror the daemon's per-field length cap so oversized values are caught
	// at the emitter rather than silently rejected by the daemon after the write.
	for _, f := range [9]struct{ name, val string }{
		{"issuer_name", issuerName},
		{"issuer_model", issuerModel},
		{"operator_id", operatorID},
		{"operator_name", operatorName},
		{"idempotency_key", ev.IdempotencyKey},
		{"correlation_id", ev.CorrelationID},
		{"agent_id", ev.AgentID},
		{"model", ev.Model},
		{"capture_method", ev.CaptureMethod},
	} {
		if len(f.val) > MaxIdentityFieldLen {
			e.dropCount.Add(pendingDrops)
			return fmt.Errorf("emitter: %s exceeds %d bytes (got %d)", f.name, MaxIdentityFieldLen, len(f.val))
		}
	}

	body, err := json.Marshal(frame{
		Version:        SupportedFrameVersion,
		TsEmit:         time.Now().UTC().Format(time.RFC3339Nano),
		SessionID:      e.sessionID,
		Channel:        ev.Channel,
		Tool:           frameTool{Server: ev.Tool.Server, Name: ev.Tool.Name},
		Input:          ev.Input,
		Output:         ev.Output,
		Error:          ev.Error,
		Decision:       ev.Decision,
		DropCount:      pendingDrops,
		IssuerName:     issuerName,
		IssuerModel:    issuerModel,
		OperatorID:     operatorID,
		OperatorName:   operatorName,
		IdempotencyKey: ev.IdempotencyKey,
		CorrelationID:  ev.CorrelationID,
		AgentID:        ev.AgentID,
		AgentType:      ev.AgentType,
		Model:          ev.Model,
		Usage:          ev.Usage,
		CaptureMethod:  ev.CaptureMethod,
		TargetSystem:   ev.Target.System,
		TargetResource: ev.Target.Resource,
	})
	if err != nil {
		// Marshal failure is a caller bug, not a transient outage. Restore
		// the pending drops so they survive this call.
		e.dropCount.Add(pendingDrops)
		return fmt.Errorf("emitter: marshal frame: %w", err)
	}
	if len(body) > MaxFrameSize {
		// Surface oversize as a returned error rather than silent drop:
		// the daemon would reject the frame at read time too, so this
		// is a logic bug in the caller, not a transient outage.
		e.dropCount.Add(pendingDrops)
		return fmt.Errorf("emitter: frame too large: %d bytes (max %d)", len(body), MaxFrameSize)
	}

	// Snapshot connection state under a brief lock. Holding e.mu across
	// the dial would serialise every concurrent Emit on a single dial's
	// 25ms timeout, blowing the per-call fire-and-forget budget under
	// load; instead we only lock for the snapshot, the optional install,
	// and the framed write.
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		e.dropCount.Add(pendingDrops)
		return errors.New("emitter: closed")
	}
	needDial := e.conn == nil
	e.mu.Unlock()

	if needDial {
		dialed, err := e.dial(ctx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				e.dropCount.Add(pendingDrops)
				return ctxErr
			}
			e.dropCount.Add(pendingDrops)
			e.logDrop(ctx, "dial", err)
			if e.bestEffort {
				return nil
			}
			return fmt.Errorf("%w: dial %s: %w", ErrTransport, e.socketPath, err)
		}
		// Install with a check-and-set: if a sibling Emit dialled and
		// installed first while we were dialling, prefer the established
		// connection and discard ours. Costs one redundant dial in the
		// race window — cheaper than serialising every Emit on a single
		// dial. If the emitter was closed while we were dialling, drop
		// our conn so it does not leak past Close.
		e.mu.Lock()
		switch {
		case e.closed:
			e.mu.Unlock()
			_ = dialed.Close()
			e.dropCount.Add(pendingDrops)
			return errors.New("emitter: closed")
		case e.conn == nil:
			e.conn = dialed
		default:
			// Loser of the dial race. Close the redundant conn after
			// releasing the mutex so we do not block sibling Emits on
			// the kernel close path.
			defer func() { _ = dialed.Close() }()
		}
		e.mu.Unlock()
	}

	// Hold e.mu across the write so concurrent Emits cannot interleave
	// length-prefix + body bytes on the same conn. The write deadline
	// caps how long the write itself blocks in the pathological case
	// (frozen daemon with a full kernel send buffer). logDrop and
	// conn.Close run outside the lock to avoid blocking sibling Emits
	// on I/O while the mutex is held.
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		e.dropCount.Add(pendingDrops)
		return errors.New("emitter: closed")
	}
	conn := e.conn
	if conn == nil {
		// A sibling Emit's write failed and reset e.conn between our
		// dial-install and write-lock acquisition. Re-dialing inline
		// would double the worst-case Emit latency on every outage
		// (ADR-0010 prefers next-Emit re-dial); drop and let the next
		// Emit re-establish.
		e.mu.Unlock()
		e.dropCount.Add(pendingDrops)
		siblingErr := errors.New("connection reset by sibling Emit")
		e.logDrop(ctx, "write", siblingErr)
		if e.bestEffort {
			return nil
		}
		return fmt.Errorf("%w: write: %w", ErrTransport, siblingErr)
	}
	if err := e.writeFrame(ctx, conn, body); err != nil {
		// A failed write almost always means the daemon went away. Drop
		// the conn so the next Emit re-dials transparently. Per ADR-0010
		// the redial happens on the FOLLOWING Emit, not as an inline
		// retry — an inline retry would double the worst-case Emit
		// latency on every actual outage.
		// Nil conn before unlocking so sibling Emits see it gone; then
		// call logDrop and conn.Close outside the lock (both can block
		// on I/O — holding e.mu across them would stall sibling Emits).
		e.conn = nil
		e.mu.Unlock()
		e.dropCount.Add(pendingDrops)
		e.logDrop(ctx, "write", err)
		_ = conn.Close()
		if e.bestEffort {
			return nil
		}
		return fmt.Errorf("%w: write frame: %w", ErrTransport, err)
	}
	e.mu.Unlock()
	return nil
}

// Close releases the underlying connection. After Close, subsequent Emit
// calls return an error. Safe to call multiple times. Any drop count
// accumulated but not yet flushed to the daemon is abandoned on Close.
func (e *DaemonEmitter) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	conn := e.conn
	e.conn = nil
	e.mu.Unlock()
	if conn == nil {
		return nil
	}
	if err := conn.Close(); err != nil {
		return fmt.Errorf("emitter: close: %w", err)
	}
	return nil
}

// dial opens a new connection to the daemon socket. Runs OUTSIDE e.mu so
// concurrent Emit calls don't serialise on a single 25ms dialTimeout.
// DialContext is used (not net.DialTimeout) so a caller-supplied ctx with
// a tighter deadline cuts the dial short.
func (e *DaemonEmitter) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, "unix", e.socketPath)
}

// writeFrame writes one length-prefixed frame to conn. The caller must
// hold e.mu so concurrent writes cannot interleave bytes on the same
// connection (the 4-byte header and body must reach the daemon as one
// contiguous sequence).
func (e *DaemonEmitter) writeFrame(ctx context.Context, conn net.Conn, body []byte) error {
	// The effective write deadline is min(now+writeTimeout, ctx.Deadline()).
	// Without honouring ctx here, a caller's tighter deadline could be
	// silently extended up to writeTimeout, breaking the fire-and-forget
	// budget callers expect when they pass a ctx with a deadline.
	deadline := time.Now().Add(writeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if err := writeAll(conn, hdr[:]); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if err := writeAll(conn, body); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	return nil
}

// writeAll handles the io.Writer short-write contract. Local AF_UNIX
// streams almost always complete in one Write, but a partial write
// would corrupt the length-prefix framing the daemon relies on, so the
// loop is correctness, not paranoia.
func writeAll(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if n > 0 {
			buf = buf[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// saturatingIncr increments c by 1, capping at math.MaxInt64 so the counter
// never wraps negative. The daemon rejects frames with drop_count < 0, so an
// overflowed counter would make all subsequent emits fail validation.
func saturatingIncr(c *atomic.Int64) {
	for {
		v := c.Load()
		if v == math.MaxInt64 {
			return
		}
		if c.CompareAndSwap(v, v+1) {
			return
		}
	}
}

func (e *DaemonEmitter) logDrop(ctx context.Context, stage string, err error) {
	saturatingIncr(&e.dropCount)
	e.logger.LogAttrs(ctx, slog.LevelDebug, "agent-receipts emitter dropped event",
		slog.String("stage", stage),
		slog.String("socket", e.socketPath),
		slog.String("err", err.Error()),
	)
}

// DefaultSocketPath returns the per-OS default path for the daemon socket.
// This is the canonical resolution shared by the emitter (client side) and
// the daemon binary (daemon.DefaultSocketPath delegates here). Keeping a
// single implementation prevents the silent drift that surfaced in issue
// #545, where a binary-specific default could resolve to /tmp while the
// other resolved $TMPDIR.
//
// AGENTRECEIPTS_SOCKET is consulted first on every host — including
// platforms where the daemon does not run — so an explicit override is
// always honoured. New continues to reject an empty result on
// unsupported platforms, so callers without an override there still see
// a clear "pass WithSocketPath explicitly" error.
//
// The platform gate below the env-var check applies only to automatic
// default path resolution. Callers that pass WithSocketPath to New
// bypass this function entirely and can use any path on any OS —
// platform detection is not their concern.
//
//   - Any platform: AGENTRECEIPTS_SOCKET if set.
//   - macOS: $XDG_DATA_HOME/agent-receipts/events.sock (XDG_DATA_HOME
//     defaults to ~/.local/share). HOME-based so the daemon and any
//     emitter resolve to the same path regardless of how they were
//     spawned — a GUI-launched proxy that loses TMPDIR no longer drifts
//     to /tmp while the daemon keeps the per-user temp dir (issue #545).
//   - Linux: $XDG_RUNTIME_DIR/agentreceipts/events.sock when
//     XDG_RUNTIME_DIR is set, else /run/agentreceipts/events.sock.
//   - Other platforms: empty string unless AGENTRECEIPTS_SOCKET supplies
//     a path. New returns an error in the empty case; callers must pass
//     WithSocketPath explicitly.
func DefaultSocketPath() string {
	// AGENTRECEIPTS_SOCKET is consulted first so an explicit override is
	// honoured on every host — including darwin runs where xdgDataHome
	// cannot resolve HOME, and platforms where the daemon does not run
	// but the caller has supplied a path. New still gates real platform
	// support elsewhere, so an unsupported host without an env override
	// continues to fail clearly.
	if p := os.Getenv("AGENTRECEIPTS_SOCKET"); p != "" {
		return p
	}
	return platformDefaultSocketPath()
}
