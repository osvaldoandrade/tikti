package storagests

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthorizerClientSendsOnlyVerifiedDigestAndParsesCurrentAllow(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/internal/v1/object-storage:authorize" ||
			request.Header.Get("Authorization") != "Bearer service-assertion" {
			t.Fatalf("request = %s %s headers=%v", request.Method, request.URL, request.Header)
		}
		var input AuthorizationRequest
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil || input.TokenSHA256 != strings.Repeat("a", 64) ||
			input.Subject != "system:serviceaccount:workload-payments:payments-api" || input.Issuer != "https://cluster.example.com" {
			t.Fatalf("authorizer input=%#v error=%v", input, err)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Pragma", "no-cache")
		_ = json.NewEncoder(writer).Encode(allowDecision(ReadOnlyAccess))
	}))
	defer server.Close()
	client, err := NewAuthorizerClient(server.URL+"/internal/v1/object-storage:authorize", server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := client.Authorize(context.Background(), authorizationTestRequest(), "service-assertion")
	if err != nil || !decision.Allowed || decision.Binding == nil || decision.Binding.Policy != ReadOnlyAccess {
		t.Fatalf("decision=%#v error=%v", decision, err)
	}
}

func TestAuthorizerClientRejectsRedirectsOversizeAndStaleResponses(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "redirect", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://elsewhere.example")
			w.WriteHeader(http.StatusFound)
		}},
		{name: "oversized", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			_, _ = w.Write([]byte(strings.Repeat("x", maxAuthorizerResponseBytes+1)))
		}},
		{name: "unknown JSON", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			_, _ = w.Write([]byte(`{"schemaVersion":"object-storage.v1","allowed":false,"reason":"AccessDenied","credential":"secret"}`))
		}},
		{name: "stale bucket", handler: func(w http.ResponseWriter, _ *http.Request) {
			decision := allowDecision(ReadOnlyAccess)
			decision.Bucket.ObservedGeneration = 2
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			_ = json.NewEncoder(w).Encode(decision)
		}},
		{name: "oversized physical bucket", handler: func(w http.ResponseWriter, _ *http.Request) {
			decision := allowDecision(ReadOnlyAccess)
			decision.Bucket.ProviderBucketName = "cf-" + strings.Repeat("a", 49) + "-0123456789ab"
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			_ = json.NewEncoder(w).Encode(decision)
		}},
		{name: "same normalized endpoint", handler: func(w http.ResponseWriter, _ *http.Request) {
			decision := allowDecision(ReadOnlyAccess)
			decision.Bucket.STSEndpoint = decision.Bucket.Endpoint + "/"
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			_ = json.NewEncoder(w).Encode(decision)
		}},
		{name: "wrong content type", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			_ = json.NewEncoder(w).Encode(allowDecision(ReadOnlyAccess))
		}},
		{name: "lookalike cache directive", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-storehouse")
			w.Header().Set("Pragma", "no-cache")
			_ = json.NewEncoder(w).Encode(allowDecision(ReadOnlyAccess))
		}},
		{name: "cacheable", handler: func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(allowDecision(ReadOnlyAccess))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			client, err := NewAuthorizerClient(server.URL+"/internal/v1/object-storage:authorize", server.Client(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, callErr := client.Authorize(context.Background(), authorizationTestRequest(), "service-assertion"); !errors.Is(callErr, ErrInvalidDependencyResponse) && !errors.Is(callErr, ErrDependencyUnavailable) {
				t.Fatalf("error = %v", callErr)
			}
		})
	}
}

func TestMinIOClientForwardsOnlyOIDCAssertionAndParsesBoundedCredentials(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		raw, _ := url.ParseQuery(readStorageTestBody(t, request))
		if request.Method != http.MethodPost || raw.Get("Action") != AWSQueryAction || raw.Get("Version") != AWSQueryVersion ||
			raw.Get("WebIdentityToken") != "minio-assertion" || raw.Get("DurationSeconds") != "900" ||
			raw.Get("RoleArn") != "" || raw.Get("Policy") != "" || len(raw) != 4 {
			t.Fatalf("MinIO form = %#v", raw)
		}
		writer.Header().Set("Content-Type", "application/xml")
		_, _ = writer.Write([]byte(minioSuccessXML(now.Add(15 * time.Minute))))
	}))
	defer server.Close()
	client, err := NewMinIOClient(server.URL, server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	credentials, err := client.Exchange(context.Background(), "minio-assertion", 900)
	if err != nil || credentials.AccessKeyID != "MINIOACCESSKEY123456" || credentials.SecretAccessKey != "minio-secret-access-key" ||
		credentials.SessionToken != "minio-session-token" || !credentials.Expiration.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("credentials=%#v error=%v", credentials, err)
	}
}

func TestMinIOClientRejectsSecretBearingErrorsAndInvalidXML(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, test := range []struct {
		name, response string
		status         int
	}{
		{name: "provider error", status: http.StatusForbidden, response: `<Error><Message>secret-access-sentinel</Message></Error>`},
		{name: "wrong namespace", response: strings.Replace(minioSuccessXML(now.Add(15*time.Minute)), AWSQueryXMLNamespace, "https://foreign.example/", 1)},
		{name: "trailing XML", response: minioSuccessXML(now.Add(15*time.Minute)) + `<secret>credential-sentinel</secret>`},
		{name: "duplicate credential", response: strings.Replace(minioSuccessXML(now.Add(15*time.Minute)), `<AccessKeyId>`, `<AccessKeyId>duplicate</AccessKeyId><AccessKeyId>`, 1)},
		{name: "expired", response: minioSuccessXML(now.Add(-time.Minute))},
		{name: "too long", response: minioSuccessXML(now.Add(16 * time.Minute))},
		{name: "oversized", response: strings.Repeat("x", maxMinIOResponseBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				status := test.status
				if status == 0 {
					status = http.StatusOK
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte(test.response))
			}))
			defer server.Close()
			client, err := NewMinIOClient(server.URL, server.Client(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			client.now = func() time.Time { return now }
			_, callErr := client.Exchange(context.Background(), "minio-assertion", 900)
			if callErr == nil || strings.Contains(callErr.Error(), "secret-access-sentinel") || strings.Contains(callErr.Error(), "credential-sentinel") {
				t.Fatalf("error = %v", callErr)
			}
		})
	}
}

func FuzzMinIOXMLShapeNeverPanics(f *testing.F) {
	f.Add([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="` + AWSQueryXMLNamespace + `"></AssumeRoleWithWebIdentityResponse>`))
	f.Add([]byte(`<Error><Message>credential-sentinel</Message></Error>`))
	f.Add([]byte("<"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = validMinIOXMLShape(raw)
	})
}

func authorizationTestRequest() AuthorizationRequest {
	return AuthorizationRequest{
		SchemaVersion: ObjectStorageVersion, RoleARN: testRoleARN, Issuer: "https://cluster.example.com", ClusterRef: "code-cloud",
		Namespace: "workload-payments", ServiceAccount: "payments-api", Subject: "system:serviceaccount:workload-payments:payments-api",
		TokenSHA256: strings.Repeat("a", 64), RequestedDurationSeconds: 900, RequestID: "request-storage-1",
	}
}

func readStorageTestBody(t *testing.T, request *http.Request) string {
	t.Helper()
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func minioSuccessXML(expiration time.Time) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<AssumeRoleWithWebIdentityResponse xmlns="` + AWSQueryXMLNamespace + `">` +
		`<AssumeRoleWithWebIdentityResult><Credentials>` +
		`<AccessKeyId>MINIOACCESSKEY123456</AccessKeyId><SecretAccessKey>minio-secret-access-key</SecretAccessKey>` +
		`<SessionToken>minio-session-token</SessionToken><Expiration>` + expiration.Format(time.RFC3339) + `</Expiration>` +
		`</Credentials></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>minio-request</RequestId></ResponseMetadata>` +
		`</AssumeRoleWithWebIdentityResponse>`
}
