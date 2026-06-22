package emitters

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"obsigna.dev/sdk/go/receipt"
)

// Strategy selects how Emit treats the call: synchronously waiting for
// the collector ack ([StrategySync], the default), or scheduling a
// goroutine and returning immediately ([StrategyFireAndForget]).
type Strategy string

const (
	// StrategySync waits for the collector ack (or retry budget exhaustion)
	// before Emit returns. At-least-once up to the retry budget.
	StrategySync Strategy = "sync"
	// StrategyFireAndForget schedules a goroutine and returns nil
	// immediately. No delivery guarantee. Call [HttpEmitter.Drain] before
	// shutdown to wait for in-flight deliveries.
	StrategyFireAndForget Strategy = "fire-and-forget"
)

// HttpEmitterAuth is implemented by every authentication variant accepted
// by [HttpEmitter]. The concrete types are [APIKeyAuth], [BearerAuth],
// [MTLSAuth], and [NoAuth].
type HttpEmitterAuth interface {
	httpEmitterAuth()
}

// APIKeyAuth sends Header: Value on every request.
type APIKeyAuth struct {
	Header string
	Value  string
}

func (APIKeyAuth) httpEmitterAuth() {}

// BearerAuth sends Authorization: Bearer <Token>.
type BearerAuth struct {
	Token string
}

func (BearerAuth) httpEmitterAuth() {}

// MTLSAuth establishes a mutual-TLS connection using the given client
// certificate. Cert and Key are PEM-encoded bytes.
type MTLSAuth struct {
	Cert []byte
	Key  []byte
}

func (MTLSAuth) httpEmitterAuth() {}

// NoAuth is the default. The HTTP client sends no auth headers and uses
// the system trust store for TLS validation.
type NoAuth struct{}

func (NoAuth) httpEmitterAuth() {}

// RetryConfig describes the exponential-backoff policy used by
// [HttpEmitter] on 5xx and network errors. MaxAttempts includes the first
// attempt.
type RetryConfig struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

// HttpEmitterConfig configures an [HttpEmitter].
//
// Auth notes: APIKeyAuth sets a caller-chosen header (e.g. X-Api-Key)
// and is intended for custom non-Authorization headers. For
// standard `Authorization: Bearer …` use [BearerAuth] — it keeps the
// wire shape canonical and is what most collectors expect.
type HttpEmitterConfig struct {
	// Endpoint is the collector URL receiving POSTs. Required.
	Endpoint string

	// Auth is the authentication variant. Defaults to NoAuth.
	Auth HttpEmitterAuth

	// Strategy is [StrategySync] (default) or [StrategyFireAndForget].
	// Empty string is treated as [StrategySync] for backwards compat.
	Strategy Strategy

	// Retry overrides the exponential-backoff policy. Defaults to 5
	// attempts with a 100ms base and 10s cap.
	Retry RetryConfig

	// Timeout is the per-request budget. Defaults to 5s.
	Timeout time.Duration

	// Logger is used for fire-and-forget drop diagnostics. Defaults to a
	// discard logger; pass slog.Default() (or any handler) to surface
	// drops at debug level.
	Logger *slog.Logger

	// HTTPClient overrides the underlying http.Client. Defaults to a
	// client with the configured timeout (and TLS config built from
	// MTLSAuth, if present). Test code can pass a mocked client.
	HTTPClient *http.Client
}

// HttpEmitter POSTs signed receipts to a collector endpoint over HTTP(S).
//
// Wire contract (per ADR-0020 §"Collector contract"):
//
//	POST <endpoint>
//	Content-Type: application/ld+json
//	Body: JSON-serialised AgentReceipt
//
//	201 Created    -> resolve
//	409 Conflict   -> resolve (duplicate id is idempotent re-delivery)
//	400 Bad Request-> EmitError, no retry
//	5xx / network  -> retry with exponential backoff + jitter
//
// Strategies:
//
//   - [StrategySync] (default): Emit returns after the collector
//     acknowledges or after the retry budget is exhausted.
//   - [StrategyFireAndForget]: Emit schedules a goroutine and returns
//     immediately; the goroutine's error is logged at debug and never
//     surfaced to the caller.
//
// !!! FIRE-AND-FORGET CRASH-LOSS RISK !!!
// In [StrategyFireAndForget] mode the background goroutine may not have
// completed delivery before the process exits, in which case the
// receipt is lost on the wire. Call [HttpEmitter.Drain] on graceful
// shutdown to wait for in-flight deliveries.
type HttpEmitter struct {
	endpoint string
	auth     HttpEmitterAuth
	strategy Strategy
	retry    RetryConfig
	logger   *slog.Logger
	client   *http.Client

	// pendingMu guards `pending`. We do NOT use sync.WaitGroup here because
	// concurrent Add() and Wait() against the same WaitGroup is a documented
	// misuse (a positive delta after Wait observes a zero counter races with
	// Wait's return). Tracking per-task channels under a mutex is race-free:
	// Emit appends a channel and closes it on completion; Drain snapshots
	// the slice under the lock and then waits on each channel outside it.
	pendingMu sync.Mutex
	pending   []chan struct{}
}

const (
	defaultMaxAttempts = 5
	defaultBaseDelay   = 100 * time.Millisecond
	defaultMaxDelay    = 10 * time.Second
	defaultTimeout     = 5 * time.Second
)

// EmitError is returned when the retry budget is exhausted or a
// non-retryable response is received.
type EmitError struct {
	Status int    // HTTP status code, or 0 if no response was received.
	Msg    string // Human-readable error description.
	Cause  error  // Underlying transport error, if any.
}

// Error implements the error interface.
func (e *EmitError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Msg, e.Cause)
	}
	return e.Msg
}

// Unwrap returns the underlying cause for errors.Is / errors.As.
func (e *EmitError) Unwrap() error { return e.Cause }

// NewHTTP constructs an [HttpEmitter] from the given config.
func NewHTTP(cfg HttpEmitterConfig) (*HttpEmitter, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("HttpEmitter: Endpoint is required")
	}

	strategy := cfg.Strategy
	if strategy == "" {
		strategy = StrategySync
	}
	if strategy != StrategySync && strategy != StrategyFireAndForget {
		return nil, fmt.Errorf("HttpEmitter: invalid strategy %q (want sync or fire-and-forget)", strategy)
	}

	auth := cfg.Auth
	if auth == nil {
		auth = NoAuth{}
	}

	retry := cfg.Retry
	if retry.MaxAttempts == 0 {
		retry.MaxAttempts = defaultMaxAttempts
	}
	if retry.BaseDelay == 0 {
		retry.BaseDelay = defaultBaseDelay
	}
	if retry.MaxDelay == 0 {
		retry.MaxDelay = defaultMaxDelay
	}
	// Validate the resolved retry budget. MaxAttempts < 1 would make the
	// retry loop run zero times and return "0 attempts exhausted" without
	// ever issuing the request; negative delays are nonsense.
	if retry.MaxAttempts < 1 {
		return nil, fmt.Errorf("HttpEmitter: Retry.MaxAttempts must be >= 1 (got %d)", retry.MaxAttempts)
	}
	if retry.BaseDelay < 0 || retry.MaxDelay < 0 {
		return nil, fmt.Errorf("HttpEmitter: retry delays must be non-negative (BaseDelay=%v, MaxDelay=%v)", retry.BaseDelay, retry.MaxDelay)
	}
	if retry.BaseDelay > retry.MaxDelay {
		return nil, fmt.Errorf("HttpEmitter: Retry.BaseDelay (%v) must be <= Retry.MaxDelay (%v)", retry.BaseDelay, retry.MaxDelay)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	if !strings.HasPrefix(cfg.Endpoint, "https://") {
		// ADR-0020 requires HTTPS in production. We accept http:// for
		// loopback and tests but warn so misconfigurations don't slip
		// through silently. Use slog.Default() in addition to the
		// caller's logger so the warning is visible even when the
		// caller configured an io.Discard logger.
		msg := "HttpEmitter: endpoint is not HTTPS; receipts will travel unencrypted"
		attr := slog.String("endpoint", cfg.Endpoint)
		logger.Warn(msg, attr)
		if cfg.Logger == nil {
			slog.Default().Warn(msg, attr)
		}
	}

	client := cfg.HTTPClient
	if client == nil {
		c := &http.Client{Timeout: timeout}
		if m, ok := auth.(MTLSAuth); ok {
			cert, err := tls.X509KeyPair(m.Cert, m.Key)
			if err != nil {
				return nil, fmt.Errorf("HttpEmitter: load mTLS keypair: %w", err)
			}
			c.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				},
			}
		}
		client = c
	}

	return &HttpEmitter{
		endpoint: cfg.Endpoint,
		auth:     auth,
		strategy: strategy,
		retry:    retry,
		logger:   logger,
		client:   client,
	}, nil
}

// Emit delivers r to the collector. In [StrategySync] mode it waits
// for the ack (or the retry budget to be exhausted). In
// [StrategyFireAndForget] mode it schedules a goroutine and returns nil
// immediately; call [HttpEmitter.Drain] before process exit if you want
// to wait for in-flight deliveries.
func (e *HttpEmitter) Emit(ctx context.Context, r receipt.AgentReceipt) error {
	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("HttpEmitter: marshal receipt: %w", err)
	}

	if e.strategy == StrategyFireAndForget {
		done := make(chan struct{})
		e.pendingMu.Lock()
		e.pending = append(e.pending, done)
		e.pendingMu.Unlock()
		go func() {
			defer func() {
				close(done)
				e.pendingMu.Lock()
				for i, ch := range e.pending {
					if ch == done {
						e.pending = append(e.pending[:i], e.pending[i+1:]...)
						break
					}
				}
				e.pendingMu.Unlock()
			}()
			if err := e.deliver(context.Background(), body); err != nil {
				e.logger.Debug("HttpEmitter dropped receipt (fire-and-forget)",
					slog.String("endpoint", e.endpoint),
					slog.String("err", err.Error()),
				)
			}
		}()
		return nil
	}

	return e.deliver(ctx, body)
}

// Drain waits for every fire-and-forget delivery scheduled so far to
// complete. Returns nil once every tracked task channel is closed, or
// the context's error if ctx is done first. Tasks scheduled after Drain
// starts are NOT awaited by this call — they belong to the next Drain.
// Safe to call when no fire-and-forget deliveries are pending.
func (e *HttpEmitter) Drain(ctx context.Context) error {
	e.pendingMu.Lock()
	snapshot := make([]chan struct{}, len(e.pending))
	copy(snapshot, e.pending)
	e.pendingMu.Unlock()
	for _, ch := range snapshot {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (e *HttpEmitter) deliver(ctx context.Context, body []byte) error {
	var lastErr error
	var lastStatus int

	for attempt := 1; attempt <= e.retry.MaxAttempts; attempt++ {
		status, err := e.doRequest(ctx, body)
		if err != nil {
			lastErr = err
			lastStatus = 0
			if attempt >= e.retry.MaxAttempts {
				break
			}
			if waitErr := sleep(ctx, e.backoff(attempt)); waitErr != nil {
				return waitErr
			}
			continue
		}

		switch {
		case status == 201 || status == 409:
			return nil
		case status == 400:
			return &EmitError{
				Status: 400,
				Msg:    fmt.Sprintf("HttpEmitter: 400 Bad Request from %s", e.endpoint),
			}
		case status >= 500 && status < 600:
			lastErr = fmt.Errorf("HTTP %d", status)
			lastStatus = status
			if attempt >= e.retry.MaxAttempts {
				break
			}
			if waitErr := sleep(ctx, e.backoff(attempt)); waitErr != nil {
				return waitErr
			}
			continue
		default:
			// 401, 403, 404, other 4xx are non-retryable.
			return &EmitError{
				Status: status,
				Msg:    fmt.Sprintf("HttpEmitter: unexpected HTTP %d from %s", status, e.endpoint),
			}
		}
	}

	return &EmitError{
		Status: lastStatus,
		Msg:    fmt.Sprintf("HttpEmitter: %d attempts exhausted for %s", e.retry.MaxAttempts, e.endpoint),
		Cause:  lastErr,
	}
}

func (e *HttpEmitter) doRequest(ctx context.Context, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("HttpEmitter: build request for %s: %w", e.endpoint, err)
	}
	req.Header.Set("Content-Type", "application/ld+json")
	switch a := e.auth.(type) {
	case APIKeyAuth:
		req.Header.Set(a.Header, a.Value)
	case BearerAuth:
		req.Header.Set("Authorization", "Bearer "+a.Token)
	case MTLSAuth, NoAuth:
		// No header to add — mTLS works at the transport layer.
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("HttpEmitter: POST %s: %w", e.endpoint, err)
	}
	// Drain and close so the underlying connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// backoff returns the wait time before the next attempt using
// exponential growth with full jitter, capped at MaxDelay.
func (e *HttpEmitter) backoff(attempt int) time.Duration {
	exp := e.retry.BaseDelay * time.Duration(1<<(attempt-1))
	if exp > e.retry.MaxDelay {
		exp = e.retry.MaxDelay
	}
	if exp <= 0 {
		return 0
	}
	// rand.N samples in [0, exp).
	return rand.N(exp)
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
