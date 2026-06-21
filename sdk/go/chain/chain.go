// Package chain provides [ReceiptChain], a stateful, serialised builder for a
// single hash-linked receipt chain (ADR-0020, issue #488).
//
// Client-side chaining requires that receipt N is fully signed and its hash
// computed before receipt N+1 is constructed. A sequential agent satisfies
// this automatically, but an agent that fires parallel tool calls would race
// on the shared chain head (sequence + previous_receipt_hash) and produce
// colliding sequence numbers or a forked hash link.
//
// ReceiptChain owns that mutable head and serialises construction + signing +
// hashing + delivery through a single mutex, so concurrent [ReceiptChain.Emit]
// calls are sequenced at the receipt layer even when the tool calls that
// triggered them ran in parallel. Concurrent calls are not an error — they
// block until the in-flight one completes — but the first time overlap is
// detected a warning is logged, since concurrent emission usually means the
// caller assumed parallel chains are supported. They are not in v1; a future
// ADR may add forked sub-chains.
//
// The head advances (sequence + previous hash) as soon as a receipt is signed
// and hashed — before delivery — so a delivery failure leaves the chain intact
// and linkable. Pair with a WAL-backed emitter for at-least-once delivery (see
// ADR-0020 §"At-least-once delivery and the WAL").
package chain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"obsigna.dev/sdk/go/emitters"
	"obsigna.dev/sdk/go/receipt"
)

// EmitInput holds the per-receipt inputs accepted by [ReceiptChain.Emit]. It
// mirrors [receipt.CreateInput] minus Chain: the chain head is owned by the
// ReceiptChain and must not be supplied per call.
type EmitInput struct {
	Issuer        receipt.Issuer
	Principal     receipt.Principal
	Action        receipt.Action
	Outcome       receipt.Outcome
	Intent        *receipt.Intent
	Authorization *receipt.Authorization
	// ResponseBody is the pre-redacted response body to hash (redact → hash →
	// sign). Forwarded to [receipt.Create]; see its docs.
	ResponseBody json.RawMessage
	// Terminal marks this as the final receipt in the chain.
	Terminal bool
	// TerminationStatus sets chain.status when Terminal is true and the value
	// is a valid wire value (spec §7.3.3); otherwise dropped by receipt.Create.
	TerminationStatus receipt.ChainStatus
	// CorrelationID links related receipts for the same logical tool invocation.
	// See receipt.CredentialSubject.CorrelationID.
	CorrelationID string
}

// Options configures a [ReceiptChain].
type Options struct {
	// ChainID is stamped on every receipt's chain.chain_id. Required.
	ChainID string
	// PrivateKeyPEM is the Ed25519 PKCS#8 PEM key used to sign receipts.
	// Required.
	PrivateKeyPEM string
	// VerificationMethod is recorded on each receipt's proof. Required.
	VerificationMethod string
	// Emitter delivers each signed receipt. Required.
	Emitter emitters.Emitter
	// StartSequence is the sequence number for the first receipt. Defaults to
	// 1 when zero; must not be negative (the spec requires sequence >= 1). Set
	// when resuming an existing chain.
	StartSequence int
	// PreviousReceiptHash links the first emitted receipt to an existing
	// chain. Defaults to nil (a fresh chain).
	PreviousReceiptHash *string
	// Logger receives the one-shot concurrency warning. Defaults to
	// [slog.Default]. The warning fires at most once per ReceiptChain.
	Logger *slog.Logger
}

const concurrentEmitMessage = "concurrent Emit() detected on a ReceiptChain; " +
	"receipt construction is serialised at the receipt layer (ADR-0020), " +
	"parallel tool calls cannot build receipts concurrently in v1 — concurrent " +
	"calls are serialised in an unspecified order under contention"

// ReceiptChain is a stateful, serialised builder for one hash-linked chain.
// Construct one per chain with [New]. It is safe for concurrent use.
type ReceiptChain struct {
	chainID            string
	privateKeyPEM      string
	verificationMethod string
	emitter            emitters.Emitter
	logger             *slog.Logger

	mu           sync.Mutex // serialises construct + sign + hash + advance + deliver
	sequence     int
	previousHash *string
	closed       bool // set once a terminal receipt is signed; rejects further Emit

	stateMu sync.Mutex // guards active + warned
	active  int
	warned  bool
}

// New builds a [ReceiptChain]. It returns an error when a required option is
// missing.
func New(opts Options) (*ReceiptChain, error) {
	switch {
	case opts.ChainID == "":
		return nil, errors.New("chain: ChainID is required")
	case opts.PrivateKeyPEM == "":
		return nil, errors.New("chain: PrivateKeyPEM is required")
	case opts.VerificationMethod == "":
		return nil, errors.New("chain: VerificationMethod is required")
	case opts.Emitter == nil:
		return nil, errors.New("chain: Emitter is required")
	case opts.StartSequence < 0:
		return nil, errors.New("chain: StartSequence must not be negative (spec requires sequence >= 1)")
	}
	seq := opts.StartSequence
	if seq == 0 {
		seq = 1
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	var prevHash *string
	if opts.PreviousReceiptHash != nil {
		s := *opts.PreviousReceiptHash
		prevHash = &s
	}
	return &ReceiptChain{
		chainID:            opts.ChainID,
		privateKeyPEM:      opts.PrivateKeyPEM,
		verificationMethod: opts.VerificationMethod,
		emitter:            opts.Emitter,
		logger:             logger,
		sequence:           seq,
		previousHash:       prevHash,
	}, nil
}

// ChainID returns the chain_id stamped on every receipt this chain emits.
func (c *ReceiptChain) ChainID() string { return c.chainID }

// NextSequence returns the sequence number the next emitted receipt will carry.
func (c *ReceiptChain) NextSequence() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sequence
}

// PreviousReceiptHash returns the hash the next receipt will link to (nil
// before the first receipt is emitted).
func (c *ReceiptChain) PreviousReceiptHash() *string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.previousHash == nil {
		return nil
	}
	h := *c.previousHash
	return &h
}

// Emit builds, signs, hash-links, and delivers one receipt, returning the
// signed receipt. Calls are serialised: receipt N is fully constructed and its
// head committed before receipt N+1 begins, even under concurrent Emit.
//
// On a delivery error the head has already advanced and the signed receipt is
// returned alongside the error; pair with a WAL-backed emitter when delivery
// durability matters.
//
// Emitting a receipt with Terminal set closes the chain: any subsequent Emit
// returns an error rather than linking a receipt after the terminal one (which
// [receipt.VerifyChain] would reject as a protocol violation).
func (c *ReceiptChain) Emit(ctx context.Context, input EmitInput) (receipt.AgentReceipt, error) {
	c.stateMu.Lock()
	c.active++
	warn := c.active > 1 && !c.warned
	if warn {
		c.warned = true
	}
	c.stateMu.Unlock()
	if warn {
		c.logger.Warn(concurrentEmitMessage, slog.String("chain_id", c.chainID))
	}
	defer func() {
		c.stateMu.Lock()
		c.active--
		c.stateMu.Unlock()
	}()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return receipt.AgentReceipt{}, errors.New("chain: terminal receipt already emitted; chain is closed")
	}

	ch := receipt.Chain{
		Sequence:            c.sequence,
		PreviousReceiptHash: c.previousHash,
		ChainID:             c.chainID,
	}
	unsigned := receipt.Create(receipt.CreateInput{
		Issuer:            input.Issuer,
		Principal:         input.Principal,
		Action:            input.Action,
		Outcome:           input.Outcome,
		Chain:             ch,
		Intent:            input.Intent,
		Authorization:     input.Authorization,
		ResponseBody:      input.ResponseBody,
		Terminal:          input.Terminal,
		TerminationStatus: input.TerminationStatus,
		CorrelationID:     input.CorrelationID,
	})
	signed, err := receipt.Sign(unsigned, c.privateKeyPEM, c.verificationMethod)
	if err != nil {
		return receipt.AgentReceipt{}, fmt.Errorf("chain: sign receipt: %w", err)
	}
	h, err := receipt.HashReceipt(signed)
	if err != nil {
		return receipt.AgentReceipt{}, fmt.Errorf("chain: hash receipt: %w", err)
	}
	// Advance the head from the just-signed receipt before delivery so a
	// delivery failure cannot fork or stall the chain (ADR-0020 WAL model).
	c.previousHash = &h
	c.sequence++
	// A terminal receipt closes the chain: nothing may link after it.
	if input.Terminal {
		c.closed = true
	}

	if err := c.emitter.Emit(ctx, signed); err != nil {
		return signed, fmt.Errorf("chain: emit receipt: %w", err)
	}
	return signed, nil
}
