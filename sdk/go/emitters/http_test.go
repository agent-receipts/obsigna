package emitters_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"obsigna.dev/sdk/go/emitters"
)

// collector wraps an httptest.Server with helpers for capturing inbound
// requests and dynamically choosing the response per attempt.
type collector struct {
	*httptest.Server
	mu        sync.Mutex
	requests  []capturedRequest
	responder func(req capturedRequest, attempt int) int
}

type capturedRequest struct {
	Method  string
	Headers http.Header
	Body    []byte
}

func newCollector() *collector {
	c := &collector{
		responder: func(_ capturedRequest, _ int) int { return http.StatusCreated },
	}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		req := capturedRequest{Method: r.Method, Headers: r.Header.Clone(), Body: body}
		c.mu.Lock()
		c.requests = append(c.requests, req)
		attempt := len(c.requests)
		responder := c.responder
		c.mu.Unlock()
		w.WriteHeader(responder(req, attempt))
	}))
	return c
}

func (c *collector) setResponder(fn func(capturedRequest, int) int) {
	c.mu.Lock()
	c.responder = fn
	c.mu.Unlock()
}

func (c *collector) Requests() []capturedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]capturedRequest, len(c.requests))
	copy(out, c.requests)
	return out
}

func TestHttpEmitter_PostsApplicationLDJSONOn201(t *testing.T) {
	c := newCollector()
	defer c.Close()

	em, err := emitters.NewHTTP(emitters.HttpEmitterConfig{Endpoint: c.URL})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if err := em.Emit(context.Background(), fakeReceipt("urn:r:1")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	reqs := c.Requests()
	if len(reqs) != 1 {
		t.Fatalf("len(requests) = %d; want 1", len(reqs))
	}
	if got := reqs[0].Headers.Get("Content-Type"); got != "application/ld+json" {
		t.Errorf("Content-Type = %q; want application/ld+json", got)
	}
	if !contains(reqs[0].Body, `"id":"urn:r:1"`) {
		t.Errorf("request body missing receipt id: %s", reqs[0].Body)
	}
}

func TestHttpEmitter_409TreatedAsSuccess(t *testing.T) {
	c := newCollector()
	defer c.Close()
	c.setResponder(func(_ capturedRequest, _ int) int { return http.StatusConflict })

	em, err := emitters.NewHTTP(emitters.HttpEmitterConfig{Endpoint: c.URL})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if err := em.Emit(context.Background(), fakeReceipt("r")); err != nil {
		t.Fatalf("Emit on 409: %v", err)
	}
	if len(c.Requests()) != 1 {
		t.Errorf("expected 1 request, got %d", len(c.Requests()))
	}
}

func TestHttpEmitter_400NoRetry(t *testing.T) {
	c := newCollector()
	defer c.Close()
	c.setResponder(func(_ capturedRequest, _ int) int { return http.StatusBadRequest })

	em, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: c.URL,
		Retry: emitters.RetryConfig{
			MaxAttempts: 5, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	err = em.Emit(context.Background(), fakeReceipt("r"))
	if err == nil {
		t.Fatalf("Emit on 400 returned nil error")
	}
	var ee *emitters.EmitError
	if !errors.As(err, &ee) {
		t.Fatalf("error is %T; want *EmitError", err)
	}
	if ee.Status != 400 {
		t.Errorf("EmitError.Status = %d; want 400", ee.Status)
	}
	if len(c.Requests()) != 1 {
		t.Errorf("expected 1 request, got %d", len(c.Requests()))
	}
}

func TestHttpEmitter_5xxThenSuccess(t *testing.T) {
	c := newCollector()
	defer c.Close()
	c.setResponder(func(_ capturedRequest, attempt int) int {
		if attempt < 3 {
			return http.StatusServiceUnavailable
		}
		return http.StatusCreated
	})

	em, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: c.URL,
		Retry: emitters.RetryConfig{
			MaxAttempts: 5, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if err := em.Emit(context.Background(), fakeReceipt("r")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := len(c.Requests()); got < 3 {
		t.Errorf("expected >=3 attempts, got %d", got)
	}
}

func TestHttpEmitter_5xxExhaustsBudget(t *testing.T) {
	c := newCollector()
	defer c.Close()
	c.setResponder(func(_ capturedRequest, _ int) int { return http.StatusBadGateway })

	em, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: c.URL,
		Retry: emitters.RetryConfig{
			MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	err = em.Emit(context.Background(), fakeReceipt("r"))
	var ee *emitters.EmitError
	if !errors.As(err, &ee) {
		t.Fatalf("error is %T (%v); want *EmitError", err, err)
	}
	if ee.Status != 502 {
		t.Errorf("EmitError.Status = %d; want 502", ee.Status)
	}
	if got := len(c.Requests()); got != 3 {
		t.Errorf("attempts = %d; want 3", got)
	}
}

func TestHttpEmitter_APIKeyAuthHeader(t *testing.T) {
	c := newCollector()
	defer c.Close()
	em, _ := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: c.URL,
		Auth:     emitters.APIKeyAuth{Header: "X-Api-Key", Value: "secret"},
	})
	if err := em.Emit(context.Background(), fakeReceipt("r")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := c.Requests()[0].Headers.Get("X-Api-Key"); got != "secret" {
		t.Errorf("X-Api-Key = %q; want %q", got, "secret")
	}
}

func TestHttpEmitter_BearerAuthHeader(t *testing.T) {
	c := newCollector()
	defer c.Close()
	em, _ := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: c.URL,
		Auth:     emitters.BearerAuth{Token: "tok-xyz"},
	})
	if err := em.Emit(context.Background(), fakeReceipt("r")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := c.Requests()[0].Headers.Get("Authorization"); got != "Bearer tok-xyz" {
		t.Errorf("Authorization = %q; want %q", got, "Bearer tok-xyz")
	}
}

func TestHttpEmitter_NoAuthHeader(t *testing.T) {
	c := newCollector()
	defer c.Close()
	em, _ := emitters.NewHTTP(emitters.HttpEmitterConfig{Endpoint: c.URL})
	if err := em.Emit(context.Background(), fakeReceipt("r")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := c.Requests()[0].Headers.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q; want empty", got)
	}
}

func TestHttpEmitter_MTLSConfigBuildsTLSAgent(t *testing.T) {
	// Generate a one-shot self-signed cert+key with crypto/tls helpers so we
	// can pin the X509KeyPair loading without contacting a real mTLS server.
	cert, key := generateSelfSignedPEM(t)

	em, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: "https://example.invalid/receipts",
		Auth:     emitters.MTLSAuth{Cert: cert, Key: key},
	})
	if err != nil {
		t.Fatalf("NewHTTP with MTLSAuth: %v", err)
	}
	if em == nil {
		t.Fatalf("emitter is nil")
	}
}

func TestHttpEmitter_MTLSInvalidCertRejected(t *testing.T) {
	_, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: "https://example.invalid/receipts",
		Auth:     emitters.MTLSAuth{Cert: []byte("not a cert"), Key: []byte("not a key")},
	})
	if err == nil {
		t.Fatalf("NewHTTP accepted invalid mTLS material")
	}
}

func TestHttpEmitter_FireAndForgetReturnsImmediately(t *testing.T) {
	c := newCollector()
	defer c.Close()
	release := make(chan struct{})
	c.setResponder(func(_ capturedRequest, _ int) int {
		<-release
		return http.StatusCreated
	})

	em, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: c.URL,
		Strategy: "fire-and-forget",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}

	start := time.Now()
	if err := em.Emit(context.Background(), fakeReceipt("r")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	elapsed := time.Since(start)
	close(release)
	if elapsed > 100*time.Millisecond {
		t.Errorf("fire-and-forget blocked for %v; want <100ms", elapsed)
	}
}

func TestHttpEmitter_FireAndForgetSwallowsErrors(t *testing.T) {
	c := newCollector()
	defer c.Close()
	var attempts atomic.Int32
	c.setResponder(func(_ capturedRequest, _ int) int {
		attempts.Add(1)
		return http.StatusInternalServerError
	})

	em, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: c.URL,
		Strategy: "fire-and-forget",
		Retry: emitters.RetryConfig{
			MaxAttempts: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	// Emit must not return an error even though delivery fails.
	if err := em.Emit(context.Background(), fakeReceipt("r")); err != nil {
		t.Fatalf("Emit (fire-and-forget) returned %v; want nil", err)
	}
	// Give the background goroutine a moment to attempt delivery.
	deadline := time.Now().Add(2 * time.Second)
	for attempts.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if attempts.Load() == 0 {
		t.Errorf("background goroutine did not attempt delivery")
	}
}

func TestHttpEmitter_EmptyEndpointRejected(t *testing.T) {
	if _, err := emitters.NewHTTP(emitters.HttpEmitterConfig{}); err == nil {
		t.Fatalf("NewHTTP with empty endpoint did not error")
	}
}

func TestHttpEmitter_InvalidStrategyRejected(t *testing.T) {
	if _, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: "http://x",
		Strategy: "lol",
	}); err == nil {
		t.Fatalf("NewHTTP with invalid strategy did not error")
	}
}

func TestHttpEmitter_HTTPEndpointWarns(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	_, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: "http://example.com/receipts",
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if !strings.Contains(buf.String(), "not HTTPS") {
		t.Errorf("expected HTTP warning, got: %q", buf.String())
	}
}

func TestHttpEmitter_HTTPSEndpointDoesNotWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	_, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: "https://example.com/receipts",
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if strings.Contains(buf.String(), "not HTTPS") {
		t.Errorf("unexpected HTTPS warning: %q", buf.String())
	}
}

func TestHttpEmitter_DrainWaitsForFireAndForget(t *testing.T) {
	c := newCollector()
	defer c.Close()
	release := make(chan struct{})
	c.setResponder(func(_ capturedRequest, _ int) int {
		<-release
		return http.StatusCreated
	})

	em, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: c.URL,
		Strategy: emitters.StrategyFireAndForget,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if err := em.Emit(context.Background(), fakeReceipt("r")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	// Release the collector and call Drain; Drain must wait until the
	// background goroutine has completed delivery.
	go close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := em.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if got := len(c.Requests()); got != 1 {
		t.Errorf("requests after Drain = %d; want 1", got)
	}
}

func TestHttpEmitter_StrategyConstants(t *testing.T) {
	if emitters.StrategySync != "sync" {
		t.Errorf("StrategySync = %q; want sync", emitters.StrategySync)
	}
	if emitters.StrategyFireAndForget != "fire-and-forget" {
		t.Errorf("StrategyFireAndForget = %q; want fire-and-forget", emitters.StrategyFireAndForget)
	}
}

func TestHttpEmitter_ContextCancellationStopsDelivery(t *testing.T) {
	c := newCollector()
	defer c.Close()
	c.setResponder(func(_ capturedRequest, _ int) int { return http.StatusBadGateway })

	em, _ := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: c.URL,
		Retry: emitters.RetryConfig{
			MaxAttempts: 50, BaseDelay: 50 * time.Millisecond, MaxDelay: time.Second,
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := em.Emit(ctx, fakeReceipt("r"))
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("Emit with cancelled ctx err = %v; want context.Canceled", err)
	}
}

func TestHttpEmitter_RejectsInvalidRetryConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  emitters.RetryConfig
		want string
	}{
		{
			name: "negative max attempts",
			cfg:  emitters.RetryConfig{MaxAttempts: -1},
			want: "MaxAttempts",
		},
		{
			name: "negative base delay",
			cfg:  emitters.RetryConfig{MaxAttempts: 3, BaseDelay: -1, MaxDelay: 1},
			want: "non-negative",
		},
		{
			name: "base larger than max",
			cfg:  emitters.RetryConfig{MaxAttempts: 3, BaseDelay: 2 * time.Second, MaxDelay: time.Second},
			want: "BaseDelay",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
				Endpoint: "https://collector.example/receipts",
				Retry:    tc.cfg,
			})
			if err == nil {
				t.Fatalf("NewHTTP with %+v returned nil error; want error containing %q", tc.cfg, tc.want)
			}
			if !contains([]byte(err.Error()), tc.want) {
				t.Errorf("NewHTTP error = %q; want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestHttpEmitter_DrainSafeUnderConcurrentEmit(t *testing.T) {
	// Regression test for the WaitGroup-misuse race: concurrent Add
	// (from Emit) and Wait (from Drain) on the same sync.WaitGroup is
	// undefined and could panic. The channel-tracking implementation must
	// be safe to call Drain repeatedly while emit traffic continues.
	c := newCollector()
	defer c.Close()
	c.setResponder(func(_ capturedRequest, _ int) int { return http.StatusCreated })

	em, err := emitters.NewHTTP(emitters.HttpEmitterConfig{
		Endpoint: c.URL,
		Strategy: emitters.StrategyFireAndForget,
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}

	stop := make(chan struct{})
	emitters_done := make(chan struct{})
	go func() {
		defer close(emitters_done)
		for {
			select {
			case <-stop:
				return
			default:
				_ = em.Emit(context.Background(), fakeReceipt("r"))
			}
		}
	}()
	// Spin Drain a few times concurrently with Emit. If the implementation
	// were sync.WaitGroup, this would panic with "WaitGroup is reused
	// before previous Wait has returned" or similar.
	for i := 0; i < 5; i++ {
		if err := em.Drain(context.Background()); err != nil {
			t.Fatalf("Drain[%d]: %v", i, err)
		}
	}
	close(stop)
	<-emitters_done
}

// helpers --------------------------------------------------------------

func contains(haystack []byte, needle string) bool {
	return indexOf(haystack, needle) >= 0
}

func indexOf(haystack []byte, needle string) int {
	n := []byte(needle)
	for i := 0; i+len(n) <= len(haystack); i++ {
		if string(haystack[i:i+len(n)]) == needle {
			return i
		}
	}
	return -1
}
