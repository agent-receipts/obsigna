package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"obsigna.dev/sdk/go/receipt"
)

// Config holds collector server configuration.
type Config struct {
	// Addr is the listen address (e.g. "127.0.0.1:8787"). Required.
	Addr string

	// MaxBodyBytes caps the size of a single receipt POST body. Bodies larger
	// than this are rejected with 400. Zero falls back to DefaultMaxBodyBytes.
	MaxBodyBytes int64

	// ReadTimeout and WriteTimeout bound the HTTP server's I/O. Zero falls
	// back to sensible defaults.
	ReadTimeout, WriteTimeout time.Duration

	// Logger receives structured log records. Required.
	Logger *slog.Logger
}

// DefaultMaxBodyBytes is the request-body cap applied when Config.MaxBodyBytes
// is zero. 1 MiB is enough to cover signed receipts with HPKE-encrypted
// parameters_disclosure envelopes well beyond typical sizes while bounding
// memory exposure for adversarial clients.
const DefaultMaxBodyBytes int64 = 1 << 20

// acceptResponse is the wire body returned on 201 Created.
type acceptResponse struct {
	ID          string `json:"id"`
	ReceiptHash string `json:"receipt_hash"`
}

// errorResponse is the wire body returned for non-201 responses.
type errorResponse struct {
	Error string `json:"error"`
}

// NewServer wires the collector's routes onto a fresh http.Server. The caller
// is responsible for starting and shutting down the returned server.
func NewServer(cfg Config, store Store) (*http.Server, error) {
	if cfg.Addr == "" {
		return nil, errors.New("collector: Config.Addr is required")
	}
	if cfg.Logger == nil {
		return nil, errors.New("collector: Config.Logger is required")
	}
	if store == nil {
		return nil, errors.New("collector: Store is required")
	}
	if cfg.MaxBodyBytes < 0 {
		// A negative limit would make http.MaxBytesReader reject every
		// request, bricking the server. Reject the misconfiguration at
		// startup rather than at first-request time.
		return nil, fmt.Errorf("collector: Config.MaxBodyBytes must be non-negative, got %d", cfg.MaxBodyBytes)
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}

	mux := http.NewServeMux()
	mux.Handle("POST /receipts", &receiptHandler{
		store:        store,
		log:          cfg.Logger,
		maxBodyBytes: cfg.MaxBodyBytes,
	})
	mux.HandleFunc("GET /healthz", healthHandler(store, cfg.Logger))

	srv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  pickDuration(cfg.ReadTimeout, 10*time.Second),
		WriteTimeout: pickDuration(cfg.WriteTimeout, 10*time.Second),
		IdleTimeout:  60 * time.Second,
		// Route net/http's internal logger through slog so accept errors and
		// handler panics appear in the structured log stream rather than
		// breaking it with plain-text writes to stderr.
		ErrorLog: slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelError),
	}
	return srv, nil
}

func pickDuration(v, fallback time.Duration) time.Duration {
	if v == 0 {
		return fallback
	}
	return v
}

// Handler exposes the collector's request multiplexer for testing without
// binding a listener.
func Handler(cfg Config, store Store) (http.Handler, error) {
	srv, err := NewServer(cfg, store)
	if err != nil {
		return nil, err
	}
	return srv.Handler, nil
}

type receiptHandler struct {
	store        Store
	log          *slog.Logger
	maxBodyBytes int64
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func (h *receiptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Cap body size before reading. http.MaxBytesReader surfaces
	// http.MaxBytesError on the read side when the cap is exceeded.
	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)

	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			h.log.Warn("receipt rejected: body too large", "limit", h.maxBodyBytes)
			writeError(w, http.StatusBadRequest, "request body exceeds maximum size")
			return
		}
		h.log.Warn("receipt rejected: body read failed", slog.Any("err", err))
		writeError(w, http.StatusBadRequest, "malformed receipt")
		return
	}
	if len(rawBody) == 0 {
		writeError(w, http.StatusBadRequest, "request body is empty")
		return
	}

	// Decode the struct view for indexed columns and validation. The raw
	// bytes themselves are what we hand to the store — preserving any
	// forward-compat fields the Go struct does not know about. Per
	// ADR-0020 the collector is a dumb sink; rejecting on unknown fields
	// would couple SDK upgrades to collector upgrades, so DisallowUnknownFields
	// is intentionally not set.
	var ar receipt.AgentReceipt
	dec := json.NewDecoder(bytes.NewReader(rawBody))
	if err := dec.Decode(&ar); err != nil {
		// encoding/json's error text leaks internal Go struct field names
		// and types ("cannot unmarshal X into Go struct field
		// AgentReceipt.foo of type Y"), so the wire body stays generic;
		// the detailed error is preserved in the structured log.
		h.log.Warn("receipt rejected: malformed json", slog.Any("err", err))
		writeError(w, http.StatusBadRequest, "malformed receipt")
		return
	}
	// Reject trailing data after the receipt. A second JSON value in the
	// body almost always indicates a client bug; better to surface it than
	// silently store the first one. Decoder.More() is unreliable at the
	// top level (it returns false when the next non-whitespace byte is `]`
	// or `}`, so `{...} ]` would slip past), so attempt a second Decode and
	// require io.EOF — anything else (a parsed value, a syntax error,
	// stray bytes) means the body wasn't a single JSON object.
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		writeError(w, http.StatusBadRequest, "request body must contain exactly one JSON object")
		return
	}

	if err := validateReceiptStructure(ar); err != nil {
		h.log.Warn("receipt rejected: structural validation failed", "id", ar.ID, slog.Any("err", err))
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Hash the raw bytes, not the decoded struct: forward-compat fields the
	// Go struct does not know about MUST contribute to the hash, otherwise
	// the value we store and return diverges from what the agent computed
	// (and what an auditor will compute from the stored raw bytes).
	hash, err := receipt.HashRawReceipt(rawBody)
	if err != nil {
		// Canonicalisation failure here implies the receipt's JSON shape
		// passed Unmarshal but cannot be canonicalised. Treat as malformed.
		h.log.Warn("receipt rejected: canonicalization failed", "id", ar.ID, slog.Any("err", err))
		writeError(w, http.StatusBadRequest, "receipt canonicalization failed")
		return
	}

	if err := h.store.Insert(ar, rawBody, hash); err != nil {
		if errors.Is(err, ErrDuplicate) {
			h.log.Info("receipt already exists, returning 409", "id", ar.ID)
			writeJSON(w, http.StatusConflict, errorResponse{Error: "receipt id already exists"})
			return
		}
		h.log.Error("receipt insert failed", "id", ar.ID, slog.Any("err", err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	h.log.Info("receipt accepted",
		"id", ar.ID,
		"chain_id", ar.CredentialSubject.Chain.ChainID,
		"sequence", ar.CredentialSubject.Chain.Sequence,
	)
	writeJSON(w, http.StatusCreated, acceptResponse{ID: ar.ID, ReceiptHash: hash})
}

// validateReceiptStructure enforces the minimal shape required to make the
// store insert meaningful. The collector does not verify signatures (per
// ADR-0020) and does not validate semantic correctness — that is the
// auditor's job — but a receipt with no id, no chain, or no action is
// definitely malformed and the SDK should not retry it.
func validateReceiptStructure(r receipt.AgentReceipt) error {
	if r.ID == "" {
		return errors.New("receipt id is required")
	}
	if r.CredentialSubject.Chain.ChainID == "" {
		return errors.New("credentialSubject.chain.chain_id is required")
	}
	if r.CredentialSubject.Action.Type == "" {
		return errors.New("credentialSubject.action.type is required")
	}
	if r.Proof.ProofValue == "" {
		return errors.New("proof.proofValue is required (receipts must be signed before delivery)")
	}
	return nil
}

func healthHandler(store Store, log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Use a reserved id shape that no legitimate receipt could collide
		// with — a real receipt id would have to fabricate this exact urn
		// scheme, in which case Exists returning true still does not
		// invalidate the liveness signal (the store is still reachable).
		if _, err := store.Exists("urn:agent-receipts:collector:healthz"); err != nil {
			log.Error("healthz: store unreachable", slog.Any("err", err))
			writeError(w, http.StatusServiceUnavailable, "store unreachable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// Run starts the server and blocks until ctx is cancelled, then gracefully
// shuts it down with the supplied drain timeout. Returns nil on a clean
// shutdown, or the first non-shutdown error encountered.
func Run(ctx context.Context, srv *http.Server, drainTimeout time.Duration, log *slog.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		log.Info("collector listening", "addr", srv.Addr)
		err := srv.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("collector listen: %w", err)
		}
		return nil
	case <-ctx.Done():
		log.Info("collector shutting down", "drain_timeout", drainTimeout)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		shutdownErr := srv.Shutdown(shutdownCtx)
		// Wait for ListenAndServe to return regardless of Shutdown's outcome,
		// so a caller restarting the server doesn't race against a still-
		// bound socket. If Shutdown fails (drain timeout exceeded), surface
		// that error in preference to the listen-loop's ErrServerClosed.
		listenErr := <-errCh
		if shutdownErr != nil {
			return fmt.Errorf("collector shutdown: %w", shutdownErr)
		}
		if listenErr != nil {
			return fmt.Errorf("collector listen: %w", listenErr)
		}
		return nil
	}
}
