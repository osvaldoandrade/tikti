package managedlogs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLogsAuthorityHTTPIsStrictBoundedAndNonCacheable(t *testing.T) {
	r := Request{SchemaVersion: Version, RequestID: "correlation-1", Operation: "Ingest"}
	for _, kind := range []string{"valid", "unknown", "duplicate", "case", "wrong tenant", "missing no store", "redirect", "oversized", "body error"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				calls++
				if q.URL.Path != AuthorityPath || q.Method != http.MethodPost || q.Header.Get("Authorization") != "Bearer test-assertion" {
					t.Error("wrong request contract")
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Pragma", "no-cache")
				d := Decision{SchemaVersion: Version, RequestID: r.RequestID, Allowed: true, Reason: "Resolved", InstallationID: "installation", ClusterUID: "cluster-uid", GrantUID: "collector-policy", GrantGeneration: 1}
				raw, _ := json.Marshal(d)
				switch kind {
				case "unknown":
					raw = []byte(`{"unknown":"secret-sentinel"}`)
				case "duplicate":
					raw = append(raw[:len(raw)-1], []byte(`,"allowed":true}`)...)
				case "case":
					raw = []byte(strings.Replace(string(raw), `"allowed"`, `"Allowed"`, 1))
				case "wrong tenant":
					d.TenantID = "foreign"
					raw, _ = json.Marshal(d)
				case "missing no store":
					w.Header().Del("Cache-Control")
				case "redirect":
					w.Header().Set("Location", safelyUnreachableURL())
					w.WriteHeader(307)
				case "oversized":
					raw = []byte(strings.Repeat("x", 17000))
				case "body error":
					w.WriteHeader(503)
					raw = []byte("secret-sentinel")
				}
				_, _ = w.Write(raw)
			}))
			t.Cleanup(s.Close)
			c, err := NewClient(s.URL+AuthorityPath, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			c.http.Transport = s.Client().Transport
			d, err := c.Authorize(context.Background(), r, "test-assertion")
			if kind == "valid" {
				if err != nil || !d.Allowed {
					t.Fatalf("valid response failed: %v", err)
				}
			} else if err == nil {
				t.Fatal("unsafe authority response accepted")
			}
			if err != nil && strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatal("provider body exposed")
			}
			if calls != 1 {
				t.Fatal("authority retried or followed redirect")
			}
		})
	}
}

func safelyUnreachableURL() string { return "https://127.0.0.1:1/not-allowed" }

func TestLogsAuthorityRejectsAmbiguousRequestJSON(t *testing.T) {
	for _, raw := range []string{`{"logsGrant":"Ingest","logsGrant":"Resolve"}`, `{"Identity":{}}`, `{"identity":{"namespace":"a","Namespace":"b"}}`, `{"grantKind":"LogRetentionPolicy","grantKind":"ObservabilityConfig"}`, `{"GrantKind":"LogRetentionPolicy"}`, `{"unknown":"secret-sentinel"}`, `{} {}`} {
		var r Request
		if Decode([]byte(raw), &r) == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
}

func TestLogsAuthorityDecisionRejectsPolicyKindOutsideSubscribe(t *testing.T) {
	for _, operation := range []string{"Ingest", "Resolve", "Publish", "Subscribe"} {
		r := Request{SchemaVersion: Version, RequestID: "request-1", Operation: operation, GrantKind: "LogRetentionPolicy", TenantID: "conveste", ConfigUID: "native-policy", ConfigGeneration: 4}
		d := Decision{SchemaVersion: Version, RequestID: r.RequestID, Allowed: true, Reason: "Resolved", InstallationID: "installation", ClusterUID: "cluster", GrantUID: r.ConfigUID, GrantGeneration: r.ConfigGeneration, TenantID: r.TenantID, TopicID: "conveste.cf-logs", RetentionSeconds: 3600}
		if operation == "Ingest" || operation == "Resolve" {
			d.TenantID, d.TopicID, d.RetentionSeconds = "", "", 0
		}
		if ValidDecision(r, d) != (operation == "Subscribe") {
			t.Fatal("retained policy decision accepted incompatible operation")
		}
	}
}

func FuzzLogsStrictDecoder(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":"managed-logs-authority/v1","requestId":"a","allowed":false,"reason":"NotAuthorized"}`))
	f.Add([]byte(`{"identity":{"namespace":"x"},"identity":{}}`))
	f.Fuzz(func(t *testing.T, raw []byte) { var d Decision; _ = Decode(raw, &d) })
}

func TestLogsStoreDecisionsHaveNoTenantOrQueueAuthority(t *testing.T) {
	for _, operation := range []string{"CefasBootstrap", "CefasRuntime"} {
		for _, kind := range []string{"valid", "kind", "tenant", "topic", "retention", "grant-uid", "grant-generation", "request-id", "version"} {
			t.Run(operation+"/"+kind, func(t *testing.T) {
				r := Request{SchemaVersion: Version, RequestID: "store-1", Operation: operation}
				d := Decision{SchemaVersion: Version, RequestID: r.RequestID, Allowed: true, Reason: "Resolved", InstallationID: "code", ClusterUID: "native-cluster", GrantUID: "native-store-policy", GrantGeneration: 3}
				switch kind {
				case "kind":
					r.GrantKind = "LogRetentionPolicy"
				case "tenant":
					d.TenantID = "tenant-a"
				case "topic":
					d.TopicID = "tenant-a.cf-logs"
				case "retention":
					d.RetentionSeconds = 300
				case "grant-uid":
					d.GrantUID = ""
				case "grant-generation":
					d.GrantGeneration = 0
				case "request-id":
					d.RequestID = "other"
				case "version":
					d.SchemaVersion = "future/v2"
				}
				if ValidDecision(r, d) != (kind == "valid") {
					t.Fatal("native store decision broadened or lost strict compatibility")
				}
			})
		}
	}
}
