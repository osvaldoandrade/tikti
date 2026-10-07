package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/osvaldoandrade/tikti/internal/codeqbinding"
	"github.com/osvaldoandrade/tikti/internal/workloadidentity"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// TestCodeQBindingExchangeEndToEndOverHTTP drives the real projected-token
// verifier (issuer -> clusterRef map) and the real authority client against a
// stub that implements the C2 schema and authenticates the Tikti assertion the
// way the API's exact-audience middleware does.
func TestCodeQBindingExchangeEndToEndOverHTTP(t *testing.T) {
	k3sKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k3s", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(k3sKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k3sKey.E)).Bytes()),
		}}})
	}))
	t.Cleanup(jwks.Close)
	k3sIssuer := "https://kubernetes.default.svc.cluster.local"
	k3sVerifier, err := workloadidentity.NewJWKSVerifier(k3sIssuer, "tikti-workload-exchange", jwks.URL+"/jwks", jwks.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	masterVerifier, err := workloadidentity.NewJWKSVerifier("https://master.example", "tikti-workload-exchange", jwks.URL+"/jwks", jwks.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := workloadidentity.NewMultiIssuerVerifier(map[string]workloadidentity.TokenVerifier{
		k3sIssuer: k3sVerifier.WithClusterRef("conveste-hostgator"), "https://master.example": masterVerifier.WithClusterRef("code-cloud"),
	})
	if err != nil {
		t.Fatal(err)
	}

	tiktiKey, tiktiPEM := workloadTestKey(t)
	var seen []codeqbinding.AuthorityRequest
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return &tiktiKey.PublicKey, nil },
			jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(codeqbinding.AuthorityAudience),
			jwt.WithIssuer("https://conveste.codefoundry.cc"), jwt.WithExpirationRequired())
		if err != nil || !token.Valid || claims["sub"] != codeqbinding.ServiceSubject || claims["tid"] != nil || claims["scope"] != nil ||
			claims["eventTypes"] != nil || claims["jti"] == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		var request codeqbinding.AuthorityRequest
		if err := decoder.Decode(&request); err != nil || !codeqbinding.ValidRequest(request) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		seen = append(seen, request)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		if request.ClusterRef != "conveste-hostgator" || request.Namespace != "workload-"+request.TenantID {
			_, _ = io.WriteString(w, `{"schemaVersion":"codeq-binding-authority/v1","requestId":"`+request.RequestID+`","allowed":false,"reason":"PlacementMismatch","bindings":[],"excluded":[]}`)
			return
		}
		_, _ = io.WriteString(w, `{"schemaVersion":"codeq-binding-authority/v1","requestId":"`+request.RequestID+`","allowed":true,"reason":"Resolved",`+
			`"bindings":[{"bindingUid":"rb-7","generation":2,"topicId":"conveste.cflow-executar","topicName":"cflow-executar","policy":"Publish"}],`+
			`"excluded":[{"bindingUid":"rb-8","reason":"TopicNotReady","topicId":"conveste.cloudbi","policy":"Subscribe"}]}`)
	}))
	t.Cleanup(authority.Close)
	client, err := codeqbinding.NewClient(authority.URL+codeqbinding.AuthorityPath, authority.Client(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	service := NewWorkloadIdentityService(nil, verifier, "https://conveste.codefoundry.cc", tiktiPEM, "tikti-kid", 5*time.Minute,
		WithCodeQBindingExchange(CodeQBindingExchangeConfig{Enabled: true, AccessTokenTTL: 300 * time.Second, MaximumConcurrent: 8, PerIdentityPerMinute: 6},
			client, stubTenantReader{tenant: &domain.Tenant{Id: "conveste", Status: domain.TenantStatusActive, CreatedAt: time.Now().Add(-time.Hour)}}),
		WithWorkloadIdentityMetrics(NewWorkloadIdentityMetrics(prometheus.NewRegistry())),
	)

	projected := func(issuer string) string {
		now := time.Now()
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": issuer, "aud": []string{"tikti-workload-exchange"},
			"sub": "system:serviceaccount:workload-conveste:cflow-publisher",
			"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
			"kubernetes.io": map[string]any{
				"namespace":      "workload-conveste",
				"serviceaccount": map[string]any{"name": "cflow-publisher", "uid": "6b0f8a52-4c55-4f3c-9d1e-1a2b3c4d5e6f"},
				"pod":            map[string]any{"name": "p", "uid": "0f9e8d7c-6b5a-4f3e-9d2c-1b0a9f8e7d6c"},
			},
		})
		token.Header["kid"] = "k3s"
		signed, err := token.SignedString(k3sKey)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	request := domain.WorkloadTokenExchangeReq{
		SubjectToken: projected(k3sIssuer), SubjectTokenType: domain.WorkloadSubjectTokenType,
		Audience: domain.WorkloadProducerAudience, Scopes: []string{"codeq:publish"}, TenantID: "conveste", CodeQTopicID: "conveste.cflow-executar",
	}
	response, err := service.Exchange(context.Background(), request)
	if err != nil {
		t.Fatalf("end-to-end exchange: %v", err)
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(response.AccessToken, claims, func(*jwt.Token) (any, error) { return &tiktiKey.PublicKey, nil },
		jwt.WithAudience(domain.WorkloadProducerAudience)); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "codefoundry:workload:conveste-hostgator:workload-conveste:cflow-publisher:0f9e8d7c-6b5a-4f3e-9d2c-1b0a9f8e7d6c" ||
		claims["cluster_ref"] != "conveste-hostgator" || claims["scope"] != "codeq:publish" {
		t.Fatalf("issued claims = %#v", claims)
	}
	if len(seen) != 1 || seen[0].ClusterRef != "conveste-hostgator" {
		t.Fatalf("authority saw %#v", seen)
	}

	// The same namespace/ServiceAccount name on MASTER maps to code-cloud only
	// through the trusted issuer, and the authority refuses its placement.
	request.SubjectToken = projected("https://master.example")
	_, err = service.Exchange(context.Background(), request)
	if refusal := refusalOf(t, err); refusal.Code != "AuthorityPlacementMismatch" || seen[1].ClusterRef != "code-cloud" {
		t.Fatalf("MASTER identity: %+v seen=%#v", refusal, seen)
	}
	// An unknown issuer never reaches the authority.
	request.SubjectToken = projected("https://untrusted.example")
	_, err = service.Exchange(context.Background(), request)
	if refusal := refusalOf(t, err); refusal.Code != CodeQBindingCodeSubjectTokenInvalid || len(seen) != 2 {
		t.Fatalf("untrusted issuer: %+v calls=%d", refusal, len(seen))
	}
}
