package storagests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdminAuthorizerClientUsesExactEndpointAndStrictSecretFreeContract(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/object-storage/authorize-admin" ||
			r.Header.Get("Authorization") != "Bearer service-assertion" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request=%s %s headers=%v", r.Method, r.URL.String(), r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		_, _ = w.Write([]byte(`{"schemaVersion":"object-storage-admin.v1","allowed":true,"reason":"Allowed","policy":"ReadOnly","bucket":{"uid":"bucket-uid","generation":3,"observedGeneration":3,"providerBucketName":"cf-payments-invoices-47e89ff7e282","endpoint":"https://s3.example.com","region":"us-central1"},"maximumCredentialTtlSeconds":900,"maximumPresignTtlSeconds":60,"maximumUploadBytes":1073741824}`))
	}))
	defer server.Close()
	client, err := NewAdminAuthorizerClient(server.URL+"/internal/v1/object-storage/authorize-admin", server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := client.AuthorizeAdmin(context.Background(), AdminAuthorizationRequest{
		SchemaVersion: AdminObjectStorageVersion, TenantID: "payments", BucketID: "invoices", Operation: AdminOperationList,
		ActorSubject: "user-1", AccessTokenSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RequestedCredentialTTLSeconds: 900, RequestedPresignTTLSeconds: 60, RequestID: "request-1",
	}, "service-assertion")
	if err != nil || !decision.Allowed || decision.Policy != ReadOnlyAccess || decision.Bucket == nil || decision.Bucket.ProviderBucketName != "cf-payments-invoices-47e89ff7e282" {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
}

func TestAdminAuthorizerClientRejectsAliasesAndUnknownResponseFields(t *testing.T) {
	t.Parallel()
	client := &http.Client{Timeout: time.Second}
	for _, endpoint := range []string{
		"https://api.example.com/internal/v1/object-storage:authorize-admin",
		"https://api.example.com/internal/v1/object-storage/authorize-admin/",
		"https://api.example.com/internal/v1/object-storage/authorize-admin?tenant=payments",
	} {
		if _, err := NewAdminAuthorizerClient(endpoint, client, time.Second); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		_, _ = w.Write([]byte(`{"schemaVersion":"object-storage-admin.v1","allowed":false,"reason":"InvalidRequest","credential":"forbidden"}`))
	}))
	defer server.Close()
	authorizer, err := NewAdminAuthorizerClient(server.URL+"/internal/v1/object-storage/authorize-admin", server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = authorizer.AuthorizeAdmin(context.Background(), AdminAuthorizationRequest{}, "service-assertion")
	if err == nil {
		t.Fatal("unknown credential field was accepted")
	}
}
