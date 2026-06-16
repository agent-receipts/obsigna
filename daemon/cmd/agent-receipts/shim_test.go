package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTranslate(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		want   []string
		wantOK bool
	}{
		{"verify maps 1:1", []string{"verify", "--db", "x"}, []string{"verify", "--db", "x"}, true},
		{"show maps 1:1", []string{"show", "--seq", "3"}, []string{"show", "--seq", "3"}, true},
		{"list moves under receipt", []string{"list", "--json"}, []string{"receipt", "list", "--json"}, true},
		{"verify-event moves under receipt", []string{"verify-event", "--seq", "2"}, []string{"receipt", "verify-event", "--seq", "2"}, true},
		{"doctor stays top-level", []string{"doctor"}, []string{"doctor"}, true},
		{"help flag", []string{"--help"}, []string{"--help"}, true},
		{"-h flag", []string{"-h"}, []string{"--help"}, true},
		{"help verb", []string{"help"}, []string{"--help"}, true},
		{"no args forwards bare", nil, nil, true},
		{"unknown is rejected", []string{"frobnicate"}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := translate(c.args)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if ok && !reflect.DeepEqual(got, c.want) {
				t.Fatalf("target = %v, want %v", got, c.want)
			}
		})
	}
}

// legacyCommands is the closed set the shim must keep working. Keep it in sync
// with the historical agent-receipts surface; the golden surface test owns the
// obsigna side.
func TestEveryLegacyCommandIsMapped(t *testing.T) {
	for _, cmd := range []string{"verify", "show", "list", "verify-event", "doctor"} {
		if _, ok := legacyMap[cmd]; !ok {
			t.Errorf("legacy command %q is no longer mapped by the shim", cmd)
		}
	}
}

// TestForwardingIntegration builds the shim and obsigna into one directory (the
// installed layout) and checks the shim forwards correctly: the deprecation
// notice appears once on STDERR and never on STDOUT, stdout is byte-identical to
// running obsigna directly, and the exit code is propagated.
func TestForwardingIntegration(t *testing.T) {
	dir := t.TempDir()
	shim := filepath.Join(dir, "agent-receipts")
	obsigna := filepath.Join(dir, "obsigna")
	goBuild(t, shim, "github.com/agent-receipts/ar/daemon/cmd/agent-receipts")
	goBuild(t, obsigna, "github.com/agent-receipts/ar/daemon/cmd/obsigna")

	absentDB := filepath.Join(dir, "absent.db")

	// `agent-receipts list` -> `obsigna receipt list`. Pointed at a missing DB
	// both error to stderr with exit 2 and empty stdout.
	shimOut, shimErr, shimCode := runBin(t, shim, "list", "--db", absentDB)
	obsOut, obsErr, obsCode := runBin(t, obsigna, "receipt", "list", "--db", absentDB)

	if shimCode != obsCode {
		t.Errorf("exit code: shim=%d obsigna=%d", shimCode, obsCode)
	}
	if shimOut != obsOut {
		t.Errorf("stdout differs:\n shim=%q\n obsigna=%q", shimOut, obsOut)
	}
	const notice = "agent-receipts is deprecated"
	if !strings.Contains(shimErr, notice) {
		t.Errorf("deprecation notice missing from stderr: %q", shimErr)
	}
	if strings.Contains(shimOut, notice) {
		t.Errorf("deprecation notice leaked into stdout: %q", shimOut)
	}
	if strings.Count(shimErr, notice) != 1 {
		t.Errorf("deprecation notice printed %d times, want exactly 1", strings.Count(shimErr, notice))
	}
	// The shim's stderr is the notice followed by obsigna's own stderr.
	if !strings.HasSuffix(shimErr, obsErr) {
		t.Errorf("shim stderr should end with obsigna's stderr.\n shim=%q\n obsigna=%q", shimErr, obsErr)
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
