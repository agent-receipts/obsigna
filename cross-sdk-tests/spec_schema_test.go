//go:build integration

package crosssdk_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

const specSchemaPath = "../spec/schema/agent-receipt.schema.json"

// loadSchema compiles spec/schema/agent-receipt.schema.json against the
// JSON Schema 2020-12 draft. The schema declares additionalProperties: false
// at the root, so any new top-level field will fail validation until added.
func loadSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	abs, err := filepath.Abs(specSchemaPath)
	if err != nil {
		t.Fatalf("resolve schema path: %v", err)
	}
	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft2020
	// santhosh-tekuri/jsonschema treats `format` as annotation-only by
	// default per JSON Schema spec — without AssertFormat the schema's
	// "format": "date-time" constraints on issuanceDate / proof.created
	// are silent, and a regression to a non-RFC3339 timestamp would not
	// fail validation.
	c.AssertFormat = true
	if err := c.AddResource("agent-receipt.schema.json", mustOpen(t, abs)); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	s, err := c.Compile("agent-receipt.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return s
}

func mustOpen(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func decodeJSON(t *testing.T, path string) any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return v
}

// TestSpecExamplesValidateAgainstSchema runs every receipt in spec/examples/
// through the JSON schema. This is the authoritative check that the spec
// examples are consistent with the spec schema — the existing
// spec_examples_test.go does field-presence checks against an ad-hoc Go
// struct, which would silently miss schema constraints like the urn:receipt
// pattern, additionalProperties: false, or enum tightening.
func TestSpecExamplesValidateAgainstSchema(t *testing.T) {
	schema := loadSchema(t)

	examples, err := filepath.Glob(filepath.Join("..", "spec", "examples", "*.json"))
	if err != nil {
		t.Fatalf("glob examples: %v", err)
	}
	if len(examples) == 0 {
		t.Fatal("no spec examples found — wrong working directory?")
	}

	for _, path := range examples {
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			doc := decodeJSON(t, path)
			if err := schema.Validate(doc); err != nil {
				t.Errorf("%s does not validate against agent-receipt.schema.json:\n%v", name, err)
			}
		})
	}
}

// TestRotationVectorValidatesAgainstSchema pins the ADR-0015 rotation-event
// wire-format vector against the schema, so the credentialSubject.keyRotation
// $def cannot silently drift from the worked example the SDKs verify against.
func TestRotationVectorValidatesAgainstSchema(t *testing.T) {
	schema := loadSchema(t)
	path := filepath.Join("..", "spec", "test-vectors", "rotation-event", "example.json")
	doc := decodeJSON(t, path)
	if err := schema.Validate(doc); err != nil {
		t.Errorf("rotation-event vector does not validate against schema:\n%v", err)
	}
}

// TestSpecSchemaRejectsMissingRequiredField confirms the schema actually
// enforces required fields. This guards against accidentally weakening the
// schema (e.g. demoting `proof` to optional).
func TestSpecSchemaRejectsMissingRequiredField(t *testing.T) {
	schema := loadSchema(t)

	full := decodeJSON(t, filepath.Join("..", "spec", "examples", "minimal-receipt.json"))
	receipt, ok := full.(map[string]any)
	if !ok {
		t.Fatalf("minimal-receipt.json is not an object: %T", full)
	}

	for _, field := range []string{"@context", "id", "type", "version", "issuer", "issuanceDate", "credentialSubject", "proof"} {
		t.Run("missing_"+field, func(t *testing.T) {
			mutated := make(map[string]any, len(receipt))
			for k, v := range receipt {
				if k == field {
					continue
				}
				mutated[k] = v
			}
			if err := schema.Validate(mutated); err == nil {
				t.Errorf("schema accepted receipt with %q removed — required-field constraint missing", field)
			}
		})
	}
}

// TestSpecSchemaRejectsUnknownTopLevelField confirms additionalProperties:
// false at the root catches stray fields. Spec drift that lands an unknown
// top-level field should be rejected here before it reaches an SDK.
func TestSpecSchemaRejectsUnknownTopLevelField(t *testing.T) {
	schema := loadSchema(t)

	full := decodeJSON(t, filepath.Join("..", "spec", "examples", "minimal-receipt.json"))
	receipt, ok := full.(map[string]any)
	if !ok {
		t.Fatalf("minimal-receipt.json is not an object: %T", full)
	}
	receipt["unexpected_field"] = "value"

	if err := schema.Validate(receipt); err == nil {
		t.Error("schema accepted receipt with unknown top-level field — additionalProperties: false missing or weakened")
	}
}

// TestSpecSchemaRejectsBadReceiptID checks the urn:receipt:<uuid> pattern is
// enforced. A regression that loosens this regex would break URN-based
// receipt lookup contracts.
func TestSpecSchemaRejectsBadReceiptID(t *testing.T) {
	schema := loadSchema(t)
	full := decodeJSON(t, filepath.Join("..", "spec", "examples", "minimal-receipt.json"))
	receipt, ok := full.(map[string]any)
	if !ok {
		t.Fatalf("minimal-receipt.json is not an object: %T", full)
	}
	receipt["id"] = "not-a-urn"

	if err := schema.Validate(receipt); err == nil {
		t.Error("schema accepted invalid receipt id — urn:receipt:<uuid> pattern missing")
	}
}

// TestSpecSchemaRejectsNonRFC3339IssuanceDate pins that AssertFormat is
// wired in — without it, "format": "date-time" is annotation-only and this
// would silently pass.
func TestSpecSchemaRejectsNonRFC3339IssuanceDate(t *testing.T) {
	schema := loadSchema(t)
	full := decodeJSON(t, filepath.Join("..", "spec", "examples", "minimal-receipt.json"))
	receipt, ok := full.(map[string]any)
	if !ok {
		t.Fatalf("minimal-receipt.json is not an object: %T", full)
	}
	receipt["issuanceDate"] = "2026/04/22 00:00:00"

	if err := schema.Validate(receipt); err == nil {
		t.Error("schema accepted non-RFC3339 issuanceDate — AssertFormat is not enabled")
	}
}

// TestSpecSchemaCouplesVersionAndContext pins the ADR-0026 allOf binding: a
// receipt's protocol version and its Agent Receipts @context URI must agree
// (0.1.0–0.4.0 → context v1; 0.5.0 → v2). Without the coupling, a 0.5.0 receipt
// could declare context v1 (whose JSON-LD has no runtime term) and validate.
func TestSpecSchemaCouplesVersionAndContext(t *testing.T) {
	schema := loadSchema(t)

	load := func() (map[string]any, []any) {
		full := decodeJSON(t, filepath.Join("..", "spec", "examples", "minimal-receipt.json"))
		receipt, ok := full.(map[string]any)
		if !ok {
			t.Fatalf("minimal-receipt.json is not an object: %T", full)
		}
		ctx, ok := receipt["@context"].([]any)
		if !ok {
			t.Fatalf("@context is not an array: %T", receipt["@context"])
		}
		return receipt, ctx
	}

	// Baseline: the unmodified example (a pre-0.5.0 version on context v1) validates.
	base, _ := load()
	if err := schema.Validate(base); err != nil {
		t.Fatalf("baseline minimal-receipt.json does not validate: %v", err)
	}

	// 0.5.0 declaring context v1 — runtime term would be undefined; must reject.
	mismatch1, _ := load()
	mismatch1["version"] = "0.5.0"
	if err := schema.Validate(mismatch1); err == nil {
		t.Error("schema accepted version 0.5.0 with context v1 — version/context coupling missing")
	}

	// A pre-0.5.0 version declaring context v2 — must reject (released versions
	// reference v1 permanently).
	mismatch2, ctx2 := load()
	ctx2[1] = "https://agentreceipts.ai/context/v2"
	mismatch2["@context"] = ctx2
	if err := schema.Validate(mismatch2); err == nil {
		t.Error("schema accepted a 0.1.0–0.4.0 version with context v2 — version/context coupling missing")
	}
}

// TestCrossSDKVectorsValidateAgainstSchema runs the signed receipts produced
// by all three SDKs (Go, TS, Py) through the schema. If any SDK regresses to
// emitting a non-spec field shape, the cross-SDK contract fails here.
func TestCrossSDKVectorsValidateAgainstSchema(t *testing.T) {
	schema := loadSchema(t)

	cases := []struct {
		name string
		path string
	}{
		{"go_vectors.json", "go_vectors.json"},
		{"py_vectors.json", "py_vectors.json"},
		{"ts_vectors.json", filepath.Join("..", "sdk", "py", "tests", "fixtures", "ts_vectors.json")},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := decodeJSON(t, c.path).(map[string]any)
			signing, ok := v["signing"].(map[string]any)
			if !ok {
				t.Fatalf("%s: missing signing section", c.name)
			}
			signed := signing["signed"]
			if err := schema.Validate(signed); err != nil {
				t.Errorf("%s signed receipt does not validate:\n%v", c.name, err)
			}
		})
	}
}
