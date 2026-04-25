package audit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// schemaPath resolves the absolute path to docs/saml/audit-schema.json
// relative to this test file.
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

// validateJSON validates a raw JSON map against the compiled schema.
func validateJSON(t *testing.T, sch *jsonschema.Schema, data []byte) error {
	t.Helper()
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return sch.Validate(v)
}

// marshalRecord marshals an AuditRecord to JSON.
func marshalRecord(t *testing.T, rec saml.AuditRecord) []byte {
	t.Helper()
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// tamperRecord unmarshals a JSON record into a map, applies a mutation, and
// marshals the result back. It fails the test on any marshal/unmarshal error.
func tamperRecord(t *testing.T, data []byte, mutate func(m map[string]interface{})) []byte {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal for tamper: %v", err)
	}
	mutate(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal tampered record: %v", err)
	}
	return out
}

// TestAcceptRecord_Schema validates that a well-formed accept audit record
// conforms to the audit JSON schema.
func TestAcceptRecord_Schema(t *testing.T) {
	sch := compileSchema(t)

	rec := saml.NewAcceptRecord(
		"tenant-001",
		saml.VerifiedAssertion{
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

	data := marshalRecord(t, rec)
	if err := validateJSON(t, sch, data); err != nil {
		t.Fatalf("accept record failed schema validation: %v\nJSON: %s", err, data)
	}
}

// TestRejectRecord_Schema validates that a well-formed reject audit record
// conforms to the audit JSON schema.
func TestRejectRecord_Schema(t *testing.T) {
	sch := compileSchema(t)

	rec := saml.NewRejectRecord(
		"tenant-002",
		"_aabbccddee00112233445566778899aabbccddee",
		saml.ReasonSignatureInvalid,
		15*time.Millisecond,
	)

	data := marshalRecord(t, rec)
	if err := validateJSON(t, sch, data); err != nil {
		t.Fatalf("reject record failed schema validation: %v\nJSON: %s", err, data)
	}
}

// TestAllRejectReasons_Schema verifies that a reject record with every
// known rejection reason passes schema validation.
func TestAllRejectReasons_Schema(t *testing.T) {
	sch := compileSchema(t)

	for _, reason := range saml.AllRejectReasons {
		t.Run(string(reason), func(t *testing.T) {
			rec := saml.NewRejectRecord(
				"tenant-reasons",
				"_aabbccddee00112233445566778899aabbccddee",
				reason,
				5*time.Millisecond,
			)
			data := marshalRecord(t, rec)
			if err := validateJSON(t, sch, data); err != nil {
				t.Fatalf("reject record (reason=%s) failed schema validation: %v\nJSON: %s", reason, err, data)
			}
		})
	}
}

// TestDeviation_BadEvent ensures the schema rejects a record whose "event"
// field does not equal the required constant.
func TestDeviation_BadEvent(t *testing.T) {
	sch := compileSchema(t)

	rec := saml.NewAcceptRecord(
		"tenant-001",
		saml.VerifiedAssertion{
			AssertionID:    "_abc123",
			NameID:         "user@example.com",
			NameIDFormat:   "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			IssuerEntityID: "https://idp.example.com",
		},
		"_aabbccddee00112233445566778899aabbccddee",
		"https://sp.example.com",
		10*time.Millisecond,
	)
	data := marshalRecord(t, rec)

	tampered := tamperRecord(t, data, func(m map[string]interface{}) {
		m["event"] = "wrong.event"
	})

	if err := validateJSON(t, sch, tampered); err == nil {
		t.Fatal("expected schema validation to fail for bad event, but it passed")
	}
}

// TestDeviation_BadDecision ensures the schema rejects a record with an
// invalid decision value.
func TestDeviation_BadDecision(t *testing.T) {
	sch := compileSchema(t)

	rec := saml.NewRejectRecord(
		"tenant-001",
		"_aabbccddee00112233445566778899aabbccddee",
		saml.ReasonInternal,
		10*time.Millisecond,
	)
	data := marshalRecord(t, rec)

	tampered := tamperRecord(t, data, func(m map[string]interface{}) {
		m["decision"] = "maybe"
	})

	if err := validateJSON(t, sch, tampered); err == nil {
		t.Fatal("expected schema validation to fail for bad decision, but it passed")
	}
}

// TestDeviation_BadSchemaVersion ensures the schema rejects a record with
// a schemaVersion other than 1.
func TestDeviation_BadSchemaVersion(t *testing.T) {
	sch := compileSchema(t)

	rec := saml.NewRejectRecord(
		"tenant-001",
		"_aabbccddee00112233445566778899aabbccddee",
		saml.ReasonInternal,
		10*time.Millisecond,
	)
	data := marshalRecord(t, rec)

	tampered := tamperRecord(t, data, func(m map[string]interface{}) {
		m["schemaVersion"] = 99
	})

	if err := validateJSON(t, sch, tampered); err == nil {
		t.Fatal("expected schema validation to fail for bad schemaVersion, but it passed")
	}
}

// TestDeviation_MissingRequired ensures the schema rejects a record that
// is missing required fields (tid, decision).
func TestDeviation_MissingRequired(t *testing.T) {
	sch := compileSchema(t)

	rec := saml.NewAcceptRecord(
		"tenant-001",
		saml.VerifiedAssertion{
			AssertionID:    "_abc123",
			NameID:         "user@example.com",
			NameIDFormat:   "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			IssuerEntityID: "https://idp.example.com",
		},
		"_aabbccddee00112233445566778899aabbccddee",
		"https://sp.example.com",
		10*time.Millisecond,
	)
	data := marshalRecord(t, rec)

	for _, field := range []string{"event", "schemaVersion", "ts", "tid", "decision"} {
		t.Run("missing_"+field, func(t *testing.T) {
			tampered := tamperRecord(t, data, func(m map[string]interface{}) {
				delete(m, field)
			})

			if err := validateJSON(t, sch, tampered); err == nil {
				t.Fatalf("expected schema validation to fail for missing %q, but it passed", field)
			}
		})
	}
}

// TestDeviation_AdditionalProperty ensures the schema rejects a record
// with an unknown property (additionalProperties: false).
func TestDeviation_AdditionalProperty(t *testing.T) {
	sch := compileSchema(t)

	rec := saml.NewRejectRecord(
		"tenant-001",
		"_aabbccddee00112233445566778899aabbccddee",
		saml.ReasonInternal,
		10*time.Millisecond,
	)
	data := marshalRecord(t, rec)

	tampered := tamperRecord(t, data, func(m map[string]interface{}) {
		m["extraField"] = "should-not-exist"
	})

	if err := validateJSON(t, sch, tampered); err == nil {
		t.Fatal("expected schema validation to fail for additional property, but it passed")
	}
}

// TestDeviation_BadRequestIDPattern ensures the schema rejects a requestID
// that does not match the required pattern ^_[0-9a-f]{40}$.
func TestDeviation_BadRequestIDPattern(t *testing.T) {
	sch := compileSchema(t)

	rec := saml.NewRejectRecord(
		"tenant-001",
		"_aabbccddee00112233445566778899aabbccddee",
		saml.ReasonInternal,
		10*time.Millisecond,
	)
	data := marshalRecord(t, rec)

	tampered := tamperRecord(t, data, func(m map[string]interface{}) {
		m["requestID"] = "not-a-valid-request-id"
	})

	if err := validateJSON(t, sch, tampered); err == nil {
		t.Fatal("expected schema validation to fail for bad requestID pattern, but it passed")
	}
}

// TestDeviation_BadReason ensures the schema rejects a reason value
// that is not in the allowed enum.
func TestDeviation_BadReason(t *testing.T) {
	sch := compileSchema(t)

	rec := saml.NewRejectRecord(
		"tenant-001",
		"_aabbccddee00112233445566778899aabbccddee",
		saml.ReasonInternal,
		10*time.Millisecond,
	)
	data := marshalRecord(t, rec)

	tampered := tamperRecord(t, data, func(m map[string]interface{}) {
		m["reason"] = "totally_made_up_reason"
	})

	if err := validateJSON(t, sch, tampered); err == nil {
		t.Fatal("expected schema validation to fail for bad reason, but it passed")
	}
}

// TestDeviation_NegativeDuration ensures the schema rejects a negative durationMs.
func TestDeviation_NegativeDuration(t *testing.T) {
	sch := compileSchema(t)

	rec := saml.NewRejectRecord(
		"tenant-001",
		"_aabbccddee00112233445566778899aabbccddee",
		saml.ReasonInternal,
		10*time.Millisecond,
	)
	data := marshalRecord(t, rec)

	tampered := tamperRecord(t, data, func(m map[string]interface{}) {
		m["durationMs"] = -1
	})

	if err := validateJSON(t, sch, tampered); err == nil {
		t.Fatal("expected schema validation to fail for negative durationMs, but it passed")
	}
}
