package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// TestExecImageDefaultsToSyscallExec asserts the shim replaces its image rather
// than forking a child (ADR-0033): a fork would add a process to the client↔server
// stdio pipe and change the PID the MCP client spawned.
func TestExecImageDefaultsToSyscallExec(t *testing.T) {
	if reflect.ValueOf(execImage).Pointer() != reflect.ValueOf(syscall.Exec).Pointer() {
		t.Error("execImage must default to syscall.Exec so the shim replaces its image, never forks a child")
	}
}

// TestRunForwardsArgvAndEnviron stubs execImage to capture what the shim would
// exec: argv[0] is the resolved binary, the remaining argv is the shim's args
// verbatim (the proxy surface is identical, so there is no translation), and the
// deprecation notice goes to the provided writer.
func TestRunForwardsArgvAndEnviron(t *testing.T) {
	// Place an executable named obsigna-mcp beside this test binary so
	// resolveSibling finds it via os.Executable()'s directory.
	dir := t.TempDir()
	target := filepath.Join(dir, targetBinary)
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	var gotPath string
	var gotArgv []string
	execImage = func(path string, argv []string, _ []string) error {
		gotPath, gotArgv = path, argv
		return nil
	}
	t.Cleanup(func() { execImage = syscall.Exec })

	var stderr bytes.Buffer
	code := run([]string{"serve", "--name", "github"}, &stderr)
	if code != 0 {
		t.Fatalf("run exit = %d, want 0", code)
	}
	if filepath.Base(gotPath) != targetBinary {
		t.Errorf("exec path = %q, want a path to %q", gotPath, targetBinary)
	}
	wantArgv := []string{gotPath, "serve", "--name", "github"}
	if !reflect.DeepEqual(gotArgv, wantArgv) {
		t.Errorf("argv = %v, want %v", gotArgv, wantArgv)
	}
	if !strings.Contains(stderr.String(), "mcp-proxy is deprecated") {
		t.Errorf("missing deprecation notice on stderr: %q", stderr.String())
	}
}

// TestRunReportsMissingTarget covers the only error path: when obsigna-mcp can't
// be resolved, the shim reports it and returns non-zero rather than exiting 0.
func TestRunReportsMissingTarget(t *testing.T) {
	// An empty PATH and a temp working dir guarantee no obsigna-mcp is found.
	t.Setenv("PATH", t.TempDir())
	var stderr bytes.Buffer
	if code := run(nil, &stderr); code != 1 {
		t.Errorf("run exit = %d, want 1 when target is missing", code)
	}
	if !strings.Contains(stderr.String(), "cannot locate") {
		t.Errorf("stderr = %q, want a 'cannot locate' message", stderr.String())
	}
}

// TestShimDoesNotReimplementSurface keeps cmd/mcp-proxy a thin forwarder: it must
// carry the shim marker and must NOT import the proxy's internal packages (which
// would mean it had grown its own command surface again).
func TestShimDoesNotReimplementSurface(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), deprecationShimMarker) {
		t.Error("cmd/mcp-proxy is missing the deprecation-shim marker; it must remain a forwarding shim")
	}
	for _, pkg := range []string{"internal/proxy", "internal/audit", "internal/policy", "internal/host"} {
		if strings.Contains(string(src), pkg) {
			t.Errorf("cmd/mcp-proxy imports %q — the shim must forward to obsigna-mcp, not re-implement the surface", pkg)
		}
	}
}

// TestForwardingIntegration builds the shim and obsigna-mcp into one directory
// (the installed layout) and checks the shim execs obsigna-mcp: `mcp-proxy
// --version` is replaced by `obsigna-mcp --version`, so stdout carries
// obsigna-mcp's version line while the deprecation notice appears once on stderr
// and never on stdout.
func TestForwardingIntegration(t *testing.T) {
	if syscall.Getuid() < 0 {
		t.Skip("syscall.Exec unavailable on this platform")
	}
	dir := t.TempDir()
	shim := filepath.Join(dir, "mcp-proxy")
	real := filepath.Join(dir, "obsigna-mcp")
	goBuild(t, shim, "github.com/agent-receipts/ar/mcp-proxy/cmd/mcp-proxy")
	goBuild(t, real, "github.com/agent-receipts/ar/mcp-proxy/cmd/obsigna-mcp")

	out, errOut, code := runBin(t, shim, "--version")
	if code != 0 {
		t.Fatalf("mcp-proxy --version exit = %d (stderr: %q)", code, errOut)
	}
	if !strings.HasPrefix(out, "obsigna-mcp ") {
		t.Errorf("stdout = %q, want it to start with the obsigna-mcp version line (shim execs obsigna-mcp)", out)
	}
	const notice = "mcp-proxy is deprecated"
	if !strings.Contains(errOut, notice) {
		t.Errorf("deprecation notice missing from stderr: %q", errOut)
	}
	if strings.Contains(out, notice) {
		t.Errorf("deprecation notice leaked into stdout: %q", out)
	}
}

func goBuild(t *testing.T, out, pkg string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, pkg)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, combined)
	}
}

func runBin(t *testing.T, bin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	code = 0
	if err != nil {
		var ee *exec.ExitError
		if !asExit(err, &ee) {
			t.Fatalf("run %s %v: %v", bin, args, err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errOut.String(), code
}

func asExit(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}
