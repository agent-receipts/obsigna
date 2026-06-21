package pipeline

import (
	"testing"

	"obsigna.dev/sdk/go/receipt"
)

func TestParseDisclosurePolicy(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
		// probe is an (actionType, risk) input; want is whether it discloses.
		probes []struct {
			actionType string
			risk       receipt.RiskLevel
			want       bool
		}
	}{
		{
			in: "", // default: off
			probes: []struct {
				actionType string
				risk       receipt.RiskLevel
				want       bool
			}{
				{"system.command.execute", receipt.RiskCritical, false},
				{"filesystem.file.read", receipt.RiskLow, false},
			},
		},
		{
			in: "false",
			probes: []struct {
				actionType string
				risk       receipt.RiskLevel
				want       bool
			}{{"anything", receipt.RiskCritical, false}},
		},
		{
			in: "true",
			probes: []struct {
				actionType string
				risk       receipt.RiskLevel
				want       bool
			}{
				{"system.command.execute", receipt.RiskCritical, true},
				{"filesystem.file.read", receipt.RiskLow, true},
			},
		},
		{
			in: "all",
			probes: []struct {
				actionType string
				risk       receipt.RiskLevel
				want       bool
			}{{"anything", receipt.RiskLow, true}},
		},
		{
			in: "high",
			probes: []struct {
				actionType string
				risk       receipt.RiskLevel
				want       bool
			}{
				{"a", receipt.RiskLow, false},
				{"a", receipt.RiskMedium, false},
				{"a", receipt.RiskHigh, true},
				{"a", receipt.RiskCritical, true},
			},
		},
		{
			in: "system.command.execute,filesystem.file.delete",
			probes: []struct {
				actionType string
				risk       receipt.RiskLevel
				want       bool
			}{
				{"system.command.execute", receipt.RiskLow, true},  // allowlisted even at low risk
				{"filesystem.file.delete", receipt.RiskHigh, true}, // allowlisted
				{"filesystem.file.read", receipt.RiskCritical, false}, // not listed, even at critical
			},
		},
		{
			in: "  high  ", // whitespace tolerance for keywords
			probes: []struct {
				actionType string
				risk       receipt.RiskLevel
				want       bool
			}{{"a", receipt.RiskHigh, true}},
		},
		{
			in: "1", // legacy boolean: strconv.ParseBool("1") used to mean true
			probes: []struct {
				actionType string
				risk       receipt.RiskLevel
				want       bool
			}{
				{"system.command.execute", receipt.RiskCritical, true},
				{"filesystem.file.read", receipt.RiskLow, true},
			},
		},
		{
			in: "0", // legacy boolean: strconv.ParseBool("0") used to mean false
			probes: []struct {
				actionType string
				risk       receipt.RiskLevel
				want       bool
			}{{"anything", receipt.RiskCritical, false}},
		},
		{in: "all,system.command.execute", wantErr: true}, // reserved keyword in list
		{in: "true,foo", wantErr: true},                   // reserved keyword in list
		{in: "foo,,bar", wantErr: true},                   // empty entry
		{in: "1,system.command.execute", wantErr: true},   // reserved legacy keyword in list
		{in: "0,system.command.execute", wantErr: true},   // reserved legacy keyword in list
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			pol, err := ParseDisclosurePolicy(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseDisclosurePolicy(%q): want error, got nil", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDisclosurePolicy(%q): %v", tc.in, err)
			}
			for _, pr := range tc.probes {
				got := pol.ShouldDisclose(pr.actionType, pr.risk)
				if got != pr.want {
					t.Errorf("ShouldDisclose(%q, %q) = %v, want %v",
						pr.actionType, pr.risk, got, pr.want)
				}
			}
		})
	}
}

func TestDisclosurePolicyEnabled(t *testing.T) {
	cases := map[string]bool{
		"":      false,
		"false": false,
		"off":   false,
		"0":     false,
		"true":  true,
		"all":   true,
		"high":  true,
		"1":     true,
		"system.command.execute": true,
	}
	for in, want := range cases {
		pol, err := ParseDisclosurePolicy(in)
		if err != nil {
			t.Fatalf("ParseDisclosurePolicy(%q): %v", in, err)
		}
		if got := pol.Enabled(); got != want {
			t.Errorf("ParseDisclosurePolicy(%q).Enabled() = %v, want %v", in, got, want)
		}
	}
}

// TestDisclosurePolicyStringRoundTrips verifies String() output re-parses to an
// equivalent policy for the keyword modes.
func TestDisclosurePolicyStringRoundTrips(t *testing.T) {
	for _, in := range []string{"off", "all", "high"} {
		pol, err := ParseDisclosurePolicy(in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		if got := pol.String(); got != in {
			t.Errorf("String() = %q, want %q", got, in)
		}
		reparsed, err := ParseDisclosurePolicy(pol.String())
		if err != nil {
			t.Fatalf("reparse %q: %v", pol.String(), err)
		}
		if reparsed.mode != pol.mode {
			t.Errorf("reparsed mode = %v, want %v", reparsed.mode, pol.mode)
		}
	}
}
