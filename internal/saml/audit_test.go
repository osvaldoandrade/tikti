package saml

import (
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// schemaPath resolves the absolute path to the audit-schema.json file
// relative to this test file's location.
func schemaPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "docs", "saml", "audit-schema.json")
}

// compileSchema loads and compiles the audit JSON schema.
func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	path := schemaPath(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("audit-schema.json", strings.NewReader(string(data))); err != nil {
		t.Fatalf("add resource: %v", err)
	}
	sch, err := compiler.Compile("audit-schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

// validateRecord marshals the record to JSON, unmarshals to interface{},
// and validates against the compiled schema.
func validateRecord(t *testing.T, sch *jsonschema.Schema, rec AuditRecord) {
	t.Helper()
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := sch.Validate(v); err != nil {
		t.Fatalf("schema validation failed: %v\nJSON: %s", err, data)
	}
}

func TestAudit_AcceptRecord_Schema(t *testing.T) {
	sch := compileSchema(t)

	rec := NewAcceptRecord(
		"tenant-001",
		VerifiedAssertion{
			AssertionID:    "_abc123",
			NameID:         "user@example.com",
			NameIDFormat:   "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			IssuerEntityID: "https://idp.example.com",
			Attributes: map[string][]string{
				"email": {"user@example.com"},
				"role":  {"admin", "viewer"},
			},
		},
		"_aabbccddee00112233445566778899aabbccddee",
		"https://sp.example.com",
		42*time.Millisecond,
	)

	validateRecord(t, sch, rec)
}

func TestAudit_RejectRecord_Schema(t *testing.T) {
	sch := compileSchema(t)

	rec := NewRejectRecord(
		"tenant-002",
		"_aabbccddee00112233445566778899aabbccddee",
		ReasonSignatureInvalid,
		15*time.Millisecond,
	)

	validateRecord(t, sch, rec)
}

func TestAudit_AttrHash_Deterministic(t *testing.T) {
	attrs := map[string][]string{
		"role":  {"viewer", "admin", "editor"},
		"email": {"a@example.com", "b@example.com"},
		"group": {"eng"},
	}

	// Compute baseline hash.
	baseline := AttrHash(attrs)
	if baseline == "" {
		t.Fatal("expected non-empty hash")
	}

	// Verify deterministic across 1000 random reorderings.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}

	for i := 0; i < 1000; i++ {
		// Build a new map with shuffled insertion order.
		shuffled := make(map[string][]string, len(attrs))
		perm := rng.Perm(len(keys))
		for _, idx := range perm {
			k := keys[idx]
			// Also shuffle values.
			vals := make([]string, len(attrs[k]))
			copy(vals, attrs[k])
			rng.Shuffle(len(vals), func(a, b int) { vals[a], vals[b] = vals[b], vals[a] })
			shuffled[k] = vals
		}

		got := AttrHash(shuffled)
		if got != baseline {
			t.Fatalf("iteration %d: hash mismatch\n  baseline: %s\n  got:      %s", i, baseline, got)
		}
	}
}

func TestAudit_AttrHash_Empty(t *testing.T) {
	if got := AttrHash(nil); got != "" {
		t.Errorf("nil map: expected empty, got %q", got)
	}
	if got := AttrHash(map[string][]string{}); got != "" {
		t.Errorf("empty map: expected empty, got %q", got)
	}
}

func TestAudit_NoPIIPersisted(t *testing.T) {
	attrs := map[string][]string{
		"email": {"secret@example.com"},
		"phone": {"+1-555-0100"},
		"role":  {"admin"},
	}

	rec := NewAcceptRecord(
		"tenant-pii",
		VerifiedAssertion{
			AssertionID:    "_id1",
			NameID:         "user@example.com",
			NameIDFormat:   "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			IssuerEntityID: "https://idp.example.com",
			Attributes:     attrs,
		},
		"_aabbccddee00112233445566778899aabbccddee",
		"https://sp.example.com",
		10*time.Millisecond,
	)

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	jsonStr := string(data)

	// Attribute values must NOT appear in the serialised record.
	for _, vals := range attrs {
		for _, v := range vals {
			if contains(jsonStr, v) {
				t.Errorf("PII value %q found in audit record: %s", v, jsonStr)
			}
		}
	}

	// nameID, issuer, audience are allowed.
	if !contains(jsonStr, "user@example.com") {
		t.Error("nameID should be present in audit record")
	}
	if !contains(jsonStr, "https://idp.example.com") {
		t.Error("issuer should be present in audit record")
	}
	if !contains(jsonStr, "https://sp.example.com") {
		t.Error("audience should be present in audit record")
	}

	// attrHash should be present (not empty).
	if rec.AttrHash == "" {
		t.Error("attrHash should be non-empty for non-empty attributes")
	}
}

func TestAudit_LogEmitter(t *testing.T) {
	emitter := LogEmitter{}
	rec := NewRejectRecord("t-emit", "_aabbccddee00112233445566778899aabbccddee", ReasonInternal, 5*time.Millisecond)
	if err := emitter.Emit(context.Background(), rec); err != nil {
		t.Fatalf("Emit error: %v", err)
	}
}

// contains reports whether s contains substr.
func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
