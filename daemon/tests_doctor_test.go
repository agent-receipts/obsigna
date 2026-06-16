//go:build integration && (linux || darwin)

// Integration test for the `obsigna doctor` subcommand: drive the real
// check pipeline against a live daemon (real socket, real SQLite store, real
// peer-credential capture) and confirm the load-bearing round-trip check
// observes a synthetic event traverse emitter → socket → daemon → DB with a
// fresh peer credential attested for this process (issue #539).
package daemon_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/agent-receipts/ar/daemon"
	"github.com/agent-receipts/ar/daemon/internal/doctorcli"
)

// doctorReport mirrors doctorcli.Report for decoding the --json output without
// exporting internal types beyond what the package already exposes.
type doctorReport = doctorcli.Report

func runDoctor(t *testing.T, fix *daemon.DaemonFixture, extraArgs ...string) (int, doctorReport, string) {
	t.Helper()
	args := append([]string{
		"--json",
		"--socket", fix.Config.SocketPath,
		"--db", fix.Config.DBPath,
		"--public-key", fix.Config.PublicKeyPath,
		"--chain-id", fix.Config.ChainID,
	}, extraArgs...)

	var stdout, stderr bytes.Buffer
	code := doctorcli.Run(args, &stdout, &stderr, func(string) string { return "" })

	var report doctorReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("parse doctor JSON: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	return code, report, stderr.String()
}

func resultByName(report doctorReport, name string) (doctorcli.Result, bool) {
	for _, r := range report.Checks {
		if r.Check == name {
			return r, true
		}
	}
	return doctorcli.Result{}, false
}

// TestDoctorRoundtripAgainstLiveDaemon is the headline test: a real daemon, a
// real round-trip, and the requirement that the synthetic event lands with a
// peer credential the daemon attested for the doctor (test) process.
func TestDoctorRoundtripAgainstLiveDaemon(t *testing.T) {
	fix := daemon.StartDaemon(t)

	code, report, stderr := runDoctor(t, fix)

	rt, ok := resultByName(report, "round-trip")
	if !ok {
		t.Fatalf("round-trip check missing\nreport: %+v", report)
	}
	if rt.Status == doctorcli.StatusFail {
		t.Fatalf("round-trip failed: %s\nstderr: %s", rt.Reason, stderr)
	}

	// No check should fail against a healthy daemon; emitter-dial-path and
	// chain-head may warn (default dial path differs from the test socket; the
	// chain is freshly opened), which does not flip the exit code without
	// --warn-as-error.
	for _, r := range report.Checks {
		if r.Status == doctorcli.StatusFail {
			t.Errorf("unexpected failing check %q: %s", r.Check, r.Reason)
		}
	}
	if code != doctorcli.ExitOK {
		t.Fatalf("got exit %d, want %d\nreport: %+v\nstderr: %s", code, doctorcli.ExitOK, report, stderr)
	}
	if !report.OK {
		t.Errorf("report.OK should be true for a healthy daemon")
	}

	// The peer-credential check is the point of the round-trip: the daemon must
	// have attested OUR pid for the synthetic event.
	pid := os.Getpid()
	if !bytes.Contains([]byte(rt.Reason), []byte("fresh peer credential")) {
		t.Errorf("round-trip reason should mention the fresh peer credential, got %q", rt.Reason)
	}
	t.Logf("round-trip: %s (doctor pid=%d)", rt.Reason, pid)
}

// TestDoctorNoRoundtripSkips confirms --no-roundtrip writes no synthetic event
// to the chain and reports the round-trip check as a skipped warning.
func TestDoctorNoRoundtripSkips(t *testing.T) {
	fix := daemon.StartDaemon(t)

	// Baseline: emit one real event so the chain is non-empty, then count.
	if err := fix.EmitGoFrame(t, "sess-1", "mcp", "list", "github", "allowed"); err != nil {
		t.Fatalf("seed emit: %v", err)
	}
	before := fix.WaitForReceiptCount(t, 1, 2_000_000_000) // 2s

	_, report, _ := runDoctor(t, fix, "--no-roundtrip")

	rt, ok := resultByName(report, "round-trip")
	if !ok || rt.Status != doctorcli.StatusWarn {
		t.Fatalf("round-trip: want warn/skipped, got %+v", rt)
	}

	// No synthetic event should have been appended.
	after := fix.WaitForReceiptCount(t, len(before), 2_000_000_000)
	if len(after) != len(before) {
		t.Errorf("--no-roundtrip appended %d receipt(s); want none", len(after)-len(before))
	}
}
