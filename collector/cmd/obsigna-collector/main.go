// Command obsigna-collector runs the agent-receipts reference HTTP collector.
//
// The collector accepts signed receipts at POST /receipts and persists them to
// a SQLite-backed store. It performs no signing, no chain construction, no
// signature verification, and no semantic validation — its contract is the
// dumb append-only sink described in ADR-0020.
//
// This is the primary collector entrypoint (ADR-0035), launched in production
// via `obsigna collector run` (ADR-0030, ADR-0034). The legacy `collector`
// binary (./cmd/collector) is a thin deprecation shim that execs into this one.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/agent-receipts/ar/collector"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z". Falls
// back to the module version from Go's build info (set automatically for
// binaries installed with `go install`), then to "dev". Mirrors the
// resolveVersion pattern used in daemon/cmd/obsigna-daemon/main.go.
var version string

func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

// defaultAddr binds to loopback by default so a `go run ./cmd/obsigna-collector` on a
// developer workstation does not expose an unauthenticated audit-trail
// endpoint to the network. Operators who want network reachability must opt
// in explicitly with --addr 0.0.0.0:8787 (or, preferably, sit a reverse
// proxy / mesh in front).
const defaultAddr = "127.0.0.1:8787"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	addr := flag.String("addr", envOrDefault("AGENTRECEIPTS_COLLECTOR_ADDR", defaultAddr), "HTTP listen address (default loopback; use 0.0.0.0:port to expose)")
	dbPath := flag.String("db", envOrDefault("AGENTRECEIPTS_COLLECTOR_DB", "collector.db"), "SQLite database path (use ':memory:' for ephemeral storage — not durable)")
	maxBody := flag.Int64("max-body-bytes", envInt64OrDefault(logger, "AGENTRECEIPTS_COLLECTOR_MAX_BODY_BYTES", collector.DefaultMaxBodyBytes), "Maximum request body size in bytes")
	drainTimeout := flag.Duration("drain-timeout", envDurationOrDefault(logger, "AGENTRECEIPTS_COLLECTOR_DRAIN_TIMEOUT", 10*time.Second), "Graceful shutdown timeout")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(resolveVersion())
		return
	}

	logger.Info("collector starting", "version", resolveVersion(), "addr", *addr, "db", *dbPath)

	store, err := collector.OpenSQLiteStore(*dbPath)
	if err != nil {
		logger.Error("failed to open store", slog.Any("err", err))
		os.Exit(1)
	}
	defer store.Close()

	srv, err := collector.NewServer(collector.Config{
		Addr:         *addr,
		MaxBodyBytes: *maxBody,
		Logger:       logger,
	}, store)
	if err != nil {
		logger.Error("failed to construct server", slog.Any("err", err))
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := collector.Run(ctx, srv, *drainTimeout, logger); err != nil {
		logger.Error("collector exited with error", slog.Any("err", err))
		os.Exit(1)
	}
	logger.Info("collector stopped cleanly")
}

func envOrDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// envInt64OrDefault parses an int64 from the named env var. On parse failure
// it logs a warning and falls back to def — silent fallback hides operator
// misconfigurations (e.g. setting MAX_BODY_BYTES=1MB and getting a 1 MiB
// default rather than 1 000 000 bytes).
func envInt64OrDefault(log *slog.Logger, name string, def int64) int64 {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	parsed, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		log.Warn("invalid env var, using default",
			"name", name, "value", v, "default", def, slog.Any("err", err))
		return def
	}
	return parsed
}

func envDurationOrDefault(log *slog.Logger, name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Warn("invalid env var, using default",
			"name", name, "value", v, "default", def, slog.Any("err", err))
		return def
	}
	return d
}
