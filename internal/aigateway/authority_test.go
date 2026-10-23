package aigateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIdentityAuthorityUsesSignedAssertionAndEmptyBody(t *testing.T) {
	want := Principal{SchemaVersion: IdentityVersion, TenantID: "tenant1", TenantUID: "tenant1", TenantEpoch: strings.Repeat("e", 64), Subject: "user-1", PrincipalKind: "User"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != AuthorityPath || r.Header.Get("Authorization") != "Bearer assertion" || r.ContentLength != 0 || r.Body != http.NoBody {
			t.Error("authority request is not the closed, bodyless signed contract")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer server.Close()
	c := &Client{url: server.URL + AuthorityPath, http: server.Client()}
	got, err := c.Authorize(context.Background(), "assertion")
	if err != nil || got != want {
		t.Fatalf("authority response mismatch: %v", err)
	}
}

func TestIdentityAuthorityRejectsAmbiguousOrUnboundedJSON(t *testing.T) {
	for _, raw := range []string{
		`{"subject":"a","subject":"b"}`, `{"Subject":"a"}`, `{"subject":"a","unknown":1}`,
		`{} {}`, `{"workload":null}`, `{"tenantEpoch":42}`, strings.Repeat(" ", 16385),
	} {
		var p Principal
		if Decode([]byte(raw), &p) == nil {
			t.Fatal("accepted ambiguous authority schema")
		}
	}
	for _, raw := range []string{"http://example.test" + AuthorityPath, "https://example.test/other", "https://u@example.test" + AuthorityPath, "https://example.test" + AuthorityPath + "?x=1"} {
		if _, err := NewClient(raw, time.Second); err == nil {
			t.Fatal("accepted unbounded authority target")
		}
	}
}
