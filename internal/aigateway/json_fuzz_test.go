package aigateway

import (
	"encoding/json"
	"reflect"
	"testing"
)

func FuzzAIIdentityJSON(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":"ai-identity/v1","kind":"User","subject":"user-1","tenantId":"tenant-1","scopes":["code-llm:invoke"]}`))
	f.Add([]byte(`{"subject":"first","subject":"second"}`))
	f.Add([]byte(`{"workload":null}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var value Identity
		if Decode(raw, &value) != nil {
			return
		}
		// Missing scopes are rejected by authorization, not the shape parser.
		// Normalize that incomplete shape before checking the wire round-trip.
		if value.Scopes == nil {
			value.Scopes = []string{}
		}
		canonical, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var again Identity
		if Decode(canonical, &again) != nil || !reflect.DeepEqual(value, again) {
			t.Fatal("accepted identity does not round-trip unambiguously")
		}
	})
}
