package aigateway

import (
	"strings"
	"testing"
)

func TestAIIdentityJSONRefusesAmbiguousWireShapes(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		``, `{`, `[]`, `null`, `{"schemaVersion":{}}`, `{"schemaVersion":[]}`,
		`{"schemaVersion":"ai-identity/v1"`, `{"schemaVersion":"ai-identity/v1",}`,
		`{"scopes":null}`, `{"scopes":{}}`, `{"scopes":[`, `{"scopes":["a"}`, `{"scopes":["a",]}`,
		`{"scopes":[{}]}`, `{"scopes":[42]}`, `{"workload":{"issuer":"a","issuer":"b"}}`,
		`{"workload":{"Issuer":"a"}}`, `{"workload":null}`, `{"scopes":[` + strings.Repeat(`"x",`, 256) + `"x"]}`,
		`{} []`, `{} garbage`, strings.Repeat(" ", 16385),
	} {
		var value Identity
		if err := Decode([]byte(raw), &value); err == nil {
			t.Fatalf("ambiguous identity JSON accepted, length %d", len(raw))
		}
	}
	for _, destination := range []any{nil, Identity{}, (*Identity)(nil)} {
		if err := Decode([]byte(`{}`), destination); err == nil {
			t.Fatal("invalid destination accepted")
		}
	}
	var claims Claims
	if err := Decode([]byte(`{"ver":9223372036854775808}`), &claims); err == nil {
		t.Fatal("overflowing token version accepted")
	}
	// The shape parser permits a bounded array; authorization owns the smaller
	// closed scope set and cannot rely on this parser to grant any scope.
	var identity Identity
	if err := Decode([]byte(`{}`+strings.Repeat(" ", 16382)), &identity); err != nil {
		t.Fatal("parser size boundary changed")
	}
	if err := Decode([]byte(`{"scopes":[`+strings.Repeat(`"x",`, 255)+`"x"]}`), &identity); err != nil || len(identity.Scopes) != 256 {
		t.Fatal("parser array boundary changed")
	}
}

func TestAIIdentityJSONDepthBound(t *testing.T) {
	t.Parallel()
	type nested struct {
		Next *nested `json:"next,omitempty"`
	}
	for depth := 0; depth <= 10; depth++ {
		raw := strings.Repeat(`{"next":`, depth) + `{}` + strings.Repeat(`}`, depth)
		var value nested
		err := Decode([]byte(raw), &value)
		if (err == nil) != (depth <= 8) {
			t.Fatalf("nesting depth %d: %v", depth, err)
		}
	}
}
