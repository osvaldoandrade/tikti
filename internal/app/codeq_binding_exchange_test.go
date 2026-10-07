package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type projectedIssuer struct {
	key    *rsa.PrivateKey
	server *httptest.Server
	issuer string
}

func newProjectedIssuer(t *testing.T, issuer string) *projectedIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k3s-1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(server.Close)
	return &projectedIssuer{key: key, server: server, issuer: issuer}
}

func (p *projectedIssuer) token(t *testing.T, namespace, serviceAccount string) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": p.issuer, "aud": []string{"tikti-workload-exchange"},
		"sub": "system:serviceaccount:" + namespace + ":" + serviceAccount,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      namespace,
			"serviceaccount": map[string]any{"name": serviceAccount, "uid": "6b0f8a52-4c55-4f3c-9d1e-1a2b3c4d5e6f"},
			"pod":            map[string]any{"name": "worker-0", "uid": "0f9e8d7c-6b5a-4f3e-9d2c-1b0a9f8e7d6c"},
		},
	})
	token.Header["kid"] = "k3s-1"
	signed, err := token.SignedString(p.key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func codeqBindingAppConfig(t *testing.T, redisAddr, jwksURL, authorityURL string, enabled bool) *config.Config {
	cfg := workloadRuntimeConfig("admin-key", applicationTestPrivateKey(t, 2048))
	cfg.RedisAddr = redisAddr
	cfg.IssuerBaseURL = "https://conveste.codefoundry.cc"
	cfg.WorkloadIdentity = config.WorkloadIdentityConfig{
		Audience: "tikti-workload-exchange", HTTPTimeoutSeconds: 2, JWKSCacheTTLSeconds: 60, AccessTokenTTLSeconds: 300,
		Providers: []config.WorkloadIdentityProviderConfig{
			{ClusterRef: "conveste-hostgator", Issuer: "https://kubernetes.default.svc.cluster.local", JWKSURL: jwksURL},
			{ClusterRef: "code-cloud", Issuer: "https://container.googleapis.com/v1/projects/p/locations/us-central1/clusters/code-cloud", JWKSURL: jwksURL},
		},
		CodeQBindings: config.CodeQBindingsConfig{
			Enabled: enabled, AuthorityURL: authorityURL, ServiceSubject: config.CodeQBindingServiceSubject,
			AccessTokenTTLSeconds: 300, DependencyTimeoutSeconds: 1, MaximumConcurrent: 8, PerIdentityPerMinute: 6,
		},
	}
	return cfg
}

func postExchange(t *testing.T, engine http.Handler, body map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, "/v1/workloads/token/exchange", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	decoded := map[string]any{}
	_ = json.Unmarshal(recorder.Body.Bytes(), &decoded)
	return recorder, decoded
}

func TestCodeQBindingExchangeApplicationWiring(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := miniredis.RunT(t)
	seed := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = seed.Close() })
	if err := repository.NewTenantRepo(seed).Create(context.Background(), &domain.Tenant{
		Id: "conveste", Slug: "conveste", Name: "Conveste", Status: domain.TenantStatusActive, CreatedAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	k3s := newProjectedIssuer(t, "https://kubernetes.default.svc.cluster.local")
	var authorityCalls atomic.Int32
	authority := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { authorityCalls.Add(1) }))
	t.Cleanup(authority.Close)
	authorityURL := authority.URL + config.CodeQBindingAuthorityPath

	exchange := map[string]any{
		"subjectToken": k3s.token(t, "workload-conveste", "cflow-codeq-worker-cf"), "subjectTokenType": domain.WorkloadSubjectTokenType,
		"audience": "codeq-worker", "scopes": []string{"codeq:abandon", "codeq:claim", "codeq:heartbeat", "codeq:nack", "codeq:result"},
		"tenantId": "conveste", "codeqTopicId": "conveste.cflow-executar",
	}

	for _, enabled := range []bool{false, true} {
		application, err := NewApplication(codeqBindingAppConfig(t, server.Addr(), k3s.server.URL+"/jwks", authorityURL, enabled))
		if err != nil {
			t.Fatalf("enabled=%v startup: %v", enabled, err)
		}
		t.Cleanup(func() { _ = application.Redis.Close() })
		if authorityCalls.Load() != 0 {
			t.Fatal("startup called the authority URL")
		}
		SetupMappings(application.Engine, application.Config, application.UserService, application.TenantSvc, application.RoleSvc,
			application.ClientSvc, application.WorkloadSvc, application.WorkloadAccountSvc, saml.NewRedisStore(nil), nil)
		recorder, body := postExchange(t, application.Engine, exchange)
		if !enabled {
			if recorder.Code != http.StatusForbidden || body["code"] != "FeatureDisabled" || body["correlationId"] == "" {
				t.Fatalf("flag off: %d %v", recorder.Code, body)
			}
			continue
		}
		// The test TLS certificate is not trusted by the production client, so the
		// authority is unreachable: the exchange fails closed and issues nothing.
		if recorder.Code != http.StatusServiceUnavailable || body["code"] != "AuthorityUnavailable" || body["accessToken"] != nil {
			t.Fatalf("authority unreachable: %d %v", recorder.Code, body)
		}
	}
}

func TestNewApplicationRefusesInvalidCodeQBindingConfiguration(t *testing.T) {
	server := miniredis.RunT(t)
	cfg := codeqBindingAppConfig(t, server.Addr(), "https://k3s.example/jwks", "http://10.0.0.5:8080"+config.CodeQBindingAuthorityPath, true)
	if application, err := NewApplication(cfg); err == nil || application != nil {
		t.Fatal("non cluster-local HTTP authority accepted")
	}
	cfg = codeqBindingAppConfig(t, server.Addr(), "https://k3s.example/jwks", "http://code-admin-api.code-admin.svc.cluster.local:8080"+config.CodeQBindingAuthorityPath, true)
	cfg.WorkloadIdentity.Providers[1].ClusterRef = ""
	if application, err := NewApplication(cfg); err == nil || application != nil {
		t.Fatal("provider without clusterRef accepted with codeqBindings enabled")
	}
}
