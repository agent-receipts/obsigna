package receipt

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// groundedVectorsPath is the cross-SDK grounded-tier corpus (spec v0.7.0
// §7.9, ADR-0041). The TypeScript and Python SDKs run the same file; all three
// must agree on every case.
var groundedVectorsPath = filepath.Join("..", "..", "..", "cross-sdk-tests", "grounded_tier_vectors.json")

type groundedVectorFile struct {
	Cases []groundedVectorCase `json:"cases"`
}

type groundedVectorCase struct {
	Name        string `json:"name"`
	ClockSkewMs int64  `json:"clock_skew_ms"`
	Receipt     struct {
		RiskLevel       RiskLevel      `json:"risk_level"`
		PrincipalID     string         `json:"principal_id"`
		ActionTimestamp string         `json:"action_timestamp"`
		Authorization   *Authorization `json:"authorization"`
	} `json:"receipt"`
	Resolver struct {
		Grant *groundedVectorGrant `json:"grant"`
		Error string               `json:"error"`
	} `json:"resolver"`
	Expected struct {
		ConfigError bool     `json:"config_error"`
		Checked     bool     `json:"checked"`
		Outcome     *string  `json:"outcome"`
		Warnings    []string `json:"warnings"`
	} `json:"expected"`
}

type groundedVectorGrant struct {
	Subject    string   `json:"subject"`
	Scopes     []string `json:"scopes"`
	ValidFrom  string   `json:"valid_from"`
	ExpiresAt  string   `json:"expires_at"`
	Revocation string   `json:"revocation"`
	RevokedAt  string   `json:"revoked_at"`
	Issuer     string   `json:"issuer"`
}

func (g groundedVectorGrant) toGrantInfo(t *testing.T) GrantInfo {
	t.Helper()
	parse := func(s string) *time.Time {
		if s == "" {
			return nil
		}
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatalf("corpus time %q: %v", s, err)
		}
		return &v
	}
	info := GrantInfo{
		Subject:    g.Subject,
		Scopes:     g.Scopes,
		ExpiresAt:  parse(g.ExpiresAt),
		Revocation: Revocation(g.Revocation),
		RevokedAt:  parse(g.RevokedAt),
		Issuer:     g.Issuer,
	}
	if vf := parse(g.ValidFrom); vf != nil {
		info.ValidFrom = *vf
	}
	return info
}

type vectorResolver struct {
	grant GrantInfo
	err   error
}

func (v vectorResolver) ResolveGrant(string, string) (GrantInfo, error) {
	return v.grant, v.err
}

func TestGroundedTierVectors(t *testing.T) {
	raw, err := os.ReadFile(groundedVectorsPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var file groundedVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("corpus has no cases")
	}

	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			r := AgentReceipt{
				ID: "urn:receipt:" + c.Name,
				CredentialSubject: CredentialSubject{
					Principal: Principal{ID: c.Receipt.PrincipalID},
					Action: Action{
						Type:      "filesystem.file.write",
						RiskLevel: c.Receipt.RiskLevel,
						Timestamp: c.Receipt.ActionTimestamp,
					},
					Authorization: c.Receipt.Authorization,
				},
			}

			var res vectorResolver
			if c.Resolver.Error != "" {
				res.err = errors.New(c.Resolver.Error)
			} else {
				res.grant = c.Resolver.Grant.toGrantInfo(t)
			}

			opts := GroundedOptions{ClockSkew: time.Duration(c.ClockSkewMs) * time.Millisecond}
			results, err := VerifyGroundedPrincipalTier([]AgentReceipt{r}, res, opts)

			if c.Expected.ConfigError {
				if err == nil {
					t.Fatalf("want a configuration error, got results %+v", results)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !c.Expected.Checked {
				if len(results) != 0 {
					t.Fatalf("want receipt outside the tier, got %+v", results)
				}
				return
			}
			if len(results) != 1 {
				t.Fatalf("want 1 result, got %d", len(results))
			}
			got := results[0]

			wantOutcome := ""
			if c.Expected.Outcome != nil {
				wantOutcome = *c.Expected.Outcome
			}
			if string(got.Outcome) != wantOutcome {
				t.Errorf("outcome = %q, want %q (detail: %s)", got.Outcome, wantOutcome, got.Detail)
			}
			if got.Grounded() != (wantOutcome == "") {
				t.Errorf("Grounded() = %v with outcome %q", got.Grounded(), got.Outcome)
			}

			var gotWarnings []string
			for _, w := range got.Warnings {
				gotWarnings = append(gotWarnings, string(w.Code))
			}
			if !slices.Equal(gotWarnings, c.Expected.Warnings) && !(len(gotWarnings) == 0 && len(c.Expected.Warnings) == 0) {
				t.Errorf("warnings = %v, want %v", gotWarnings, c.Expected.Warnings)
			}
		})
	}
}
