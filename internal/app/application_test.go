package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

func TestValidateWorkloadIdentityRuntimeConfig(t *testing.T) {
	validKey := applicationTestPrivateKey(t, 2048)
	weakKey := applicationTestPrivateKey(t, 1024)
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{name: "nil", cfg: nil, wantErr: true},
		{name: "disabled", cfg: &config.Config{}},
		{name: "missing API key", cfg: workloadRuntimeConfig("", validKey), wantErr: true},
		{name: "unresolved API key", cfg: workloadRuntimeConfig("${API_KEY}", validKey), wantErr: true},
		{name: "missing issuer metadata", cfg: &config.Config{
			ApiKey: "admin-key", JwksPrivateKey: validKey,
			WorkloadIdentity: config.WorkloadIdentityConfig{Issuer: "https://kubernetes.example.com"},
		}, wantErr: true},
		{name: "invalid signing key", cfg: workloadRuntimeConfig("admin-key", "invalid"), wantErr: true},
		{name: "weak signing key", cfg: workloadRuntimeConfig("admin-key", weakKey), wantErr: true},
		{name: "valid", cfg: workloadRuntimeConfig("admin-key", validKey)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateWorkloadIdentityRuntimeConfig(test.cfg)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateWorkloadIdentityRuntimeConfig() error = %v", err)
			}
		})
	}
}

func TestSetupMappingsRegistersTenantCreateRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	SetupMappings(engine, &config.Config{}, nil, nil, nil, nil, nil, nil, saml.NewRedisStore(nil), nil)
	routes := make(map[string]bool)
	for _, route := range engine.Routes() {
		routes[route.Method+" "+route.Path] = true
	}
	for _, route := range []string{"POST /v1/tenants", "PUT /v1/tenants/:tenantId"} {
		if !routes[route] {
			t.Fatalf("missing route %s", route)
		}
	}
	for _, test := range []struct{ name, method, key, header, target, want string }{
		{name: "query rejected", method: http.MethodPut, key: "secret", target: "/v1/tenants/bereia?key=secret", want: "Invalid or missing API key"},
		{name: "empty key rejected", method: http.MethodPut, header: "secret", target: "/v1/tenants/bereia", want: "Invalid or missing API key"},
		{name: "header passes middleware", method: http.MethodPut, key: "secret", header: "secret", target: "/v1/tenants/bereia", want: "missing authentication"},
		{name: "legacy POST query", method: http.MethodPost, key: "secret", target: "/v1/tenants?key=secret", want: "missing authentication"},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			SetupMappings(router, &config.Config{ApiKey: test.key}, nil, nil, nil, nil, nil, nil, nil, nil)
			req := httptest.NewRequest(test.method, test.target, strings.NewReader(`{}`))
			req.Header.Set("X-API-Key", test.header)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), test.want) {
				t.Fatalf("response = %d %s", rec.Code, rec.Body.String())
			}
		})
	}
	SetupMappings(gin.New(), &config.Config{}, nil, nil, nil, nil, nil, nil, nil, nil)
}

func TestNewApplication(t *testing.T) {
	server := miniredis.RunT(t)
	if _, err := NewApplication(nil); err == nil {
		t.Fatal("expected nil configuration error")
	}
	if _, err := NewApplication(&config.Config{RedisURL: "://invalid"}); err == nil {
		t.Fatal("expected Redis configuration error")
	}
	invalidVerifier := workloadRuntimeConfig("admin-key", applicationTestPrivateKey(t, 2048))
	invalidVerifier.RedisAddr = server.Addr()
	if _, err := NewApplication(invalidVerifier); err == nil {
		t.Fatal("expected workload verifier error")
	}
	application, err := NewApplication(&config.Config{RedisAddr: server.Addr()})
	if err != nil {
		t.Fatalf("new application: %v", err)
	}
	t.Cleanup(func() { _ = application.Redis.Close() })
	if application.Engine == nil || application.TenantSvc == nil || application.WorkloadSvc == nil {
		t.Fatal("expected wired application")
	}
}

func TestNewWorkloadTokenVerifier(t *testing.T) {
	provider := func(index int) config.WorkloadIdentityProviderConfig {
		return config.WorkloadIdentityProviderConfig{
			Issuer:  fmt.Sprintf("https://cluster-%d.example.com", index),
			JWKSURL: fmt.Sprintf("https://cluster-%d.example.com/jwks", index),
		}
	}
	tooMany := make([]config.WorkloadIdentityProviderConfig, 18)
	for index := range tooMany {
		tooMany[index] = provider(index)
	}
	tests := []struct {
		name    string
		cfg     config.WorkloadIdentityConfig
		wantNil bool
		wantErr bool
	}{
		{name: "disabled", wantNil: true},
		{name: "single", cfg: config.WorkloadIdentityConfig{
			Issuer: "https://cluster.example.com", Audience: "audience",
			JWKSURL: "https://cluster.example.com/jwks", JWKSCacheTTLSeconds: 1,
		}},
		{name: "multiple", cfg: config.WorkloadIdentityConfig{
			Audience: "audience", JWKSCacheTTLSeconds: 1,
			Providers: []config.WorkloadIdentityProviderConfig{provider(1), provider(2)},
		}},
		{name: "bearer file", cfg: config.WorkloadIdentityConfig{
			Audience: "audience", JWKSCacheTTLSeconds: 1,
			Providers: []config.WorkloadIdentityProviderConfig{{
				Issuer: "https://cluster.example.com", JWKSURL: "https://cluster.example.com/jwks",
				JWKSBearerTokenFile: filepath.Join(t.TempDir(), "token"),
			}},
		}},
		{name: "relative bearer file", cfg: config.WorkloadIdentityConfig{
			Audience: "audience", JWKSCacheTTLSeconds: 1,
			Providers: []config.WorkloadIdentityProviderConfig{{
				Issuer: "https://cluster.example.com", JWKSURL: "https://cluster.example.com/jwks",
				JWKSBearerTokenFile: "relative-token",
			}},
		}, wantErr: true},
		{name: "invalid verifier", cfg: config.WorkloadIdentityConfig{
			Issuer: "https://cluster.example.com", JWKSCacheTTLSeconds: 1,
		}, wantErr: true},
		{name: "too many issuers", cfg: config.WorkloadIdentityConfig{
			Audience: "audience", JWKSCacheTTLSeconds: 1, Providers: tooMany,
		}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := newWorkloadTokenVerifier(test.cfg)
			if (err != nil) != test.wantErr || (!test.wantErr && (verifier == nil) != test.wantNil) {
				t.Fatalf("verifier=%T err=%v", verifier, err)
			}
		})
	}
}

func workloadRuntimeConfig(apiKey, privateKey string) *config.Config {
	return &config.Config{
		ApiKey: apiKey, IssuerBaseURL: "https://tikti.example.com", JwksPrivateKey: privateKey, JwksKeyID: "kid-1",
		WorkloadIdentity: config.WorkloadIdentityConfig{Issuer: "https://kubernetes.example.com"},
	}
}

func applicationTestPrivateKey(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}
