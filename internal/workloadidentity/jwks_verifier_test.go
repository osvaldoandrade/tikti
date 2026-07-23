package workloadidentity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	testWorkloadIssuer   = "https://kubernetes.example.com"
	testWorkloadAudience = "tikti-workload-exchange"
	testWorkloadKid      = "kubernetes-key-1"
	testWorkloadSubject  = "system:serviceaccount:code-admin:code-admin-controller-queue"
)

func TestJWKSVerifierValidatesProjectedServiceAccountToken(t *testing.T) {
	key := verifierTestKey(t)
	server, calls := jwksTestServer(t, key, testWorkloadKid, 0)
	verifier := newTestVerifier(t, server, time.Minute)
	token := signProjectedToken(t, key, testWorkloadKid, projectedClaims(time.Now()))

	subject, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if subject.Subject != testWorkloadSubject || subject.Namespace != "code-admin" || subject.ServiceAccount != "code-admin-controller-queue" {
		t.Fatalf("Verify() subject = %#v", subject)
	}
	if calls.Load() != 1 {
		t.Fatalf("JWKS calls = %d", calls.Load())
	}
}

func TestJWKSVerifierRejectsWrongSignature(t *testing.T) {
	trustedKey := verifierTestKey(t)
	untrustedKey := verifierTestKey(t)
	server, _ := jwksTestServer(t, trustedKey, testWorkloadKid, 0)
	verifier := newTestVerifier(t, server, time.Minute)
	token := signProjectedToken(t, untrustedKey, testWorkloadKid, projectedClaims(time.Now()))
	if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, domain.ErrWorkloadTokenInvalid) {
		t.Fatalf("Verify() wrong signature error = %v", err)
	}
}

func TestJWKSVerifierRejectsInvalidProjectedClaims(t *testing.T) {
	key := verifierTestKey(t)
	server, _ := jwksTestServer(t, key, testWorkloadKid, 0)
	tests := []struct {
		name   string
		mutate func(jwt.MapClaims)
	}{
		{name: "issuer", mutate: func(claims jwt.MapClaims) { claims["iss"] = "https://other.example.com" }},
		{name: "audience", mutate: func(claims jwt.MapClaims) { claims["aud"] = "other" }},
		{name: "additional audience", mutate: func(claims jwt.MapClaims) { claims["aud"] = []string{testWorkloadAudience, "other"} }},
		{name: "expired", mutate: func(claims jwt.MapClaims) { claims["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{name: "missing expiry", mutate: func(claims jwt.MapClaims) { delete(claims, "exp") }},
		{name: "subject", mutate: func(claims jwt.MapClaims) { claims["sub"] = "user@example.com" }},
		{name: "namespace", mutate: func(claims jwt.MapClaims) { claims["kubernetes.io"].(map[string]interface{})["namespace"] = "other" }},
		{name: "service account", mutate: func(claims jwt.MapClaims) {
			claims["kubernetes.io"].(map[string]interface{})["serviceaccount"].(map[string]interface{})["name"] = "other"
		}},
		{name: "missing kubernetes claims", mutate: func(claims jwt.MapClaims) { delete(claims, "kubernetes.io") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := projectedClaims(time.Now())
			test.mutate(claims)
			verifier := newTestVerifier(t, server, time.Minute)
			if subject, err := verifier.Verify(context.Background(), signProjectedToken(t, key, testWorkloadKid, claims)); !errors.Is(err, domain.ErrWorkloadTokenInvalid) || subject.Subject != "" {
				t.Fatalf("Verify() = %#v, %v", subject, err)
			}
		})
	}
}

func TestJWKSVerifierRateLimitsUnknownKIDRefresh(t *testing.T) {
	key := verifierTestKey(t)
	server, calls := jwksTestServer(t, key, testWorkloadKid, 0)
	verifier := newTestVerifier(t, server, time.Minute)
	validToken := signProjectedToken(t, key, testWorkloadKid, projectedClaims(time.Now()))
	if _, err := verifier.Verify(context.Background(), validToken); err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	for index := 0; index < 20; index++ {
		unknownToken := signProjectedToken(t, key, fmt.Sprintf("unknown-%d", index), projectedClaims(time.Now()))
		if _, err := verifier.Verify(context.Background(), unknownToken); !errors.Is(err, domain.ErrWorkloadTokenInvalid) {
			t.Fatalf("unknown kid %d error = %v", index, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("JWKS calls = %d, want 1", calls.Load())
	}
}

func TestJWKSVerifierRejectsUnsafeJWKSResponses(t *testing.T) {
	key := verifierTestKey(t)
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak RSA key: %v", err)
	}
	tests := []struct {
		name string
		body func(http.ResponseWriter)
	}{
		{name: "oversized", body: func(response http.ResponseWriter) {
			_, _ = response.Write([]byte(`{"keys":[]}`))
			_, _ = response.Write(make([]byte, maxJWKSResponseBytes))
		}},
		{name: "weak key", body: func(response http.ResponseWriter) {
			_ = json.NewEncoder(response).Encode(jwksDocument{Keys: []jwk{rsaJWK(weakKey, testWorkloadKid)}})
		}},
		{name: "duplicate kid", body: func(response http.ResponseWriter) {
			_ = json.NewEncoder(response).Encode(jwksDocument{Keys: []jwk{rsaJWK(key, testWorkloadKid), rsaJWK(key, testWorkloadKid)}})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				test.body(response)
			}))
			t.Cleanup(server.Close)
			verifier := newTestVerifier(t, server, time.Minute)
			token := signProjectedToken(t, key, testWorkloadKid, projectedClaims(time.Now()))
			if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, domain.ErrWorkloadIdentityUnavailable) {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}

func TestJWKSVerifierDoesNotFollowRedirects(t *testing.T) {
	key := verifierTestKey(t)
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	t.Cleanup(target.Close)
	redirect := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	t.Cleanup(redirect.Close)
	verifier := newTestVerifier(t, redirect, time.Minute)
	token := signProjectedToken(t, key, testWorkloadKid, projectedClaims(time.Now()))
	if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, domain.ErrWorkloadIdentityUnavailable) {
		t.Fatalf("Verify() redirect error = %v", err)
	}
	if targetCalls.Load() != 0 {
		t.Fatalf("redirect target calls = %d", targetCalls.Load())
	}
}

func TestJWKSVerifierCachesConcurrentKeyFetches(t *testing.T) {
	key := verifierTestKey(t)
	server, calls := jwksTestServer(t, key, testWorkloadKid, 25*time.Millisecond)
	verifier := newTestVerifier(t, server, time.Minute)
	token := signProjectedToken(t, key, testWorkloadKid, projectedClaims(time.Now()))

	const workers = 32
	var wait sync.WaitGroup
	errorsCh := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := verifier.Verify(context.Background(), token); err != nil {
				errorsCh <- err
			}
		}()
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Errorf("concurrent Verify() error = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("JWKS calls = %d, want 1", calls.Load())
	}
}

func TestJWKSVerifierSurfacesJWKSOutageAsUnavailable(t *testing.T) {
	key := verifierTestKey(t)
	server, _ := jwksTestServer(t, key, testWorkloadKid, 100*time.Millisecond)
	client := server.Client()
	client.Timeout = 10 * time.Millisecond
	verifier, err := NewJWKSVerifier(testWorkloadIssuer, testWorkloadAudience, server.URL, client, time.Minute)
	if err != nil {
		t.Fatalf("NewJWKSVerifier() error = %v", err)
	}
	token := signProjectedToken(t, key, testWorkloadKid, projectedClaims(time.Now()))
	if _, err := verifier.Verify(context.Background(), token); !errors.Is(err, domain.ErrWorkloadIdentityUnavailable) {
		t.Fatalf("Verify() outage error = %v", err)
	}
}

func TestNewJWKSVerifierRejectsUnsafeConfiguration(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	for _, rawURL := range []string{"", "jwks", "ftp://issuer/keys", "http://issuer.example.com/keys", "https://user:secret@issuer/keys", "https://issuer/keys?token=secret"} {
		if _, err := NewJWKSVerifier(testWorkloadIssuer, testWorkloadAudience, rawURL, client, time.Minute); err == nil {
			t.Fatalf("NewJWKSVerifier(%q) succeeded", rawURL)
		}
	}
	if _, err := NewJWKSVerifier("", testWorkloadAudience, "https://issuer/keys", client, time.Minute); err == nil {
		t.Fatal("empty issuer was accepted")
	}
	if _, err := NewJWKSVerifier(testWorkloadIssuer, "", "https://issuer/keys", client, time.Minute); err == nil {
		t.Fatal("empty audience was accepted")
	}
	if _, err := NewJWKSVerifier(testWorkloadIssuer, testWorkloadAudience, "https://issuer/keys", nil, time.Minute); err == nil {
		t.Fatal("nil HTTP client was accepted")
	}
}

func newTestVerifier(t *testing.T, server *httptest.Server, cacheTTL time.Duration) *JWKSVerifier {
	t.Helper()
	verifier, err := NewJWKSVerifier(testWorkloadIssuer, testWorkloadAudience, server.URL, server.Client(), cacheTTL)
	if err != nil {
		t.Fatalf("NewJWKSVerifier() error = %v", err)
	}
	return verifier
}

func jwksTestServer(t *testing.T, key *rsa.PrivateKey, kid string, delay time.Duration) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if !strings.Contains(request.Header.Get("Accept"), "application/jwk-set+json") {
			t.Errorf("Accept header = %q", request.Header.Get("Accept"))
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(jwksDocument{Keys: []jwk{rsaJWK(key, kid)}})
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func rsaJWK(key *rsa.PrivateKey, kid string) jwk {
	return jwk{
		Kty: "RSA", Kid: kid, Alg: jwt.SigningMethodRS256.Alg(), Use: "sig",
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()), E: encodeExponent(key.E),
	}
}

func encodeExponent(exponent int) string {
	bytes := []byte{byte(exponent >> 16), byte(exponent >> 8), byte(exponent)}
	for len(bytes) > 1 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func projectedClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": testWorkloadIssuer, "aud": testWorkloadAudience, "sub": testWorkloadSubject,
		"iat": now.Add(-time.Second).Unix(), "exp": now.Add(time.Hour).Unix(),
		"kubernetes.io": map[string]interface{}{
			"namespace":      "code-admin",
			"serviceaccount": map[string]interface{}{"name": "code-admin-controller-queue", "uid": "uid-1"},
		},
	}
}

func signProjectedToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign projected token: %v", err)
	}
	return signed
}

func verifierTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func ExampleJWKSVerifier() {
	fmt.Println("validates projected Kubernetes ServiceAccount tokens against configured JWKS")
	// Output: validates projected Kubernetes ServiceAccount tokens against configured JWKS
}
