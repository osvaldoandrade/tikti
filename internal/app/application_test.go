package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
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
	SetupMappings(engine, &config.Config{}, nil, nil, nil, nil, nil, nil, nil, saml.NewRedisStore(nil), nil)
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
		{name: "header passes middleware", method: http.MethodPut, key: "secret", header: "secret", target: "/v1/tenants/bereia", want: "missing or invalid bearer token"},
		{name: "legacy POST query", method: http.MethodPost, key: "secret", target: "/v1/tenants?key=secret", want: "Invalid or missing API key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			SetupMappings(router, &config.Config{ApiKey: test.key}, nil, nil, nil, nil, nil, nil, nil, nil, nil)
			req := httptest.NewRequest(test.method, test.target, strings.NewReader(`{}`))
			req.Header.Set("X-API-Key", test.header)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), test.want) {
				t.Fatalf("response = %d %s", rec.Code, rec.Body.String())
			}
		})
	}
	SetupMappings(gin.New(), &config.Config{}, nil, nil, nil, nil, nil, nil, nil, nil, nil)
}

func TestProtectedRoutesRejectQueryAPIKeyBeforeControllers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	SetupMappings(router, &config.Config{ApiKey: "secret"}, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	for _, path := range []string{
		"/v1/accounts/signUp",
		"/v1/accounts/signInWithPassword",
		"/v1/accounts/lookup",
		"/v1/accounts/token/exchange",
		"/v1/accounts/status",
		"/v1/accounts/revoke",
		"/v1/accounts/validate",
		"/v1/accounts/update",
		"/v1/accounts/delete",
		"/v1/accounts/sendOobCode",
		"/v1/accounts/resetPassword",
		"/v1/tenants",
		"/v1/tenants/bereia/roles",
		"/v1/tenants/bereia/clients",
	} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, path+"?key=secret", strings.NewReader(`[`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "Invalid or missing API key") {
				t.Fatalf("query credential reached %s controller: %d %s", path, response.Code, response.Body.String())
			}
		})
	}
}

type applicationWorkloadAccountService struct{}

func (applicationWorkloadAccountService) Register(context.Context, string, domain.WorkloadAccountCredentials) (*domain.WorkloadAccountRegistrationResp, bool, error) {
	return nil, false, domain.ErrWorkloadTokenInvalid
}

func (applicationWorkloadAccountService) Session(context.Context, string, domain.WorkloadAccountCredentials) (*domain.WorkloadAccountSessionResp, error) {
	return nil, domain.ErrWorkloadTokenInvalid
}

func TestSetupMappingsRegistersExactWorkloadAccountEdgeAliases(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	cfg := &config.Config{WorkloadAccountBFF: config.WorkloadAccountBFFConfig{Enabled: true}}
	SetupMappings(router, cfg, nil, nil, nil, nil, nil, nil, applicationWorkloadAccountService{}, nil, nil)

	routes := make(map[string]bool)
	for _, route := range router.Routes() {
		routes[route.Method+" "+route.Path] = true
	}
	for _, route := range []string{
		"POST /v1/workloads/accounts/register",
		"POST /v1/workloads/accounts/session",
		"POST /identity/v1/workloads/accounts/register",
		"POST /identity/v1/workloads/accounts/session",
	} {
		if !routes[route] {
			t.Fatalf("missing exact workload-account route %s", route)
		}
	}
	for route := range routes {
		if strings.HasPrefix(route, "GET /identity/v1/workloads/accounts/") {
			t.Fatalf("workload-account edge alias must remain POST-only: %s", route)
		}
	}
	for _, path := range []string{
		"/identity/v1/workloads/accounts/register",
		"/identity/v1/workloads/accounts/session",
	} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("X-Tikti-Contract") != "workload-account-bff-v1" {
			t.Fatalf("edge alias %s did not preserve the authenticated broker contract: %d %v %s", path, rec.Code, rec.Header(), rec.Body.String())
		}
	}
}

func TestSetupMappingsRoleContractAuthorizationAndIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	repo := repository.NewRoleRepo(client)
	privateKey := applicationTestPrivateKey(t, 2048)
	cfg := &config.Config{ApiKey: "secret", JwksPrivateKey: privateKey, IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin"}
	router := gin.New()
	SetupMappings(router, cfg, nil, nil, nil, services.NewRoleService(repo), nil, nil, nil, nil, nil)
	routes := map[string]bool{}
	for _, route := range router.Routes() {
		routes[route.Method+" "+route.Path] = true
	}
	if !routes["PUT /v1/admin/tenants/:tenantId/roles/:roleName"] ||
		!routes["GET /v1/admin/tenants/:tenantId/roles/:roleName"] ||
		!routes["GET /v1/admin/tenants/:tenantId/roles"] ||
		!routes["POST /v1/tenants/:tenantId/roles"] {
		t.Fatalf("role routes missing: %+v", routes)
	}
	token := func(scope, tenant, subject string) string {
		return applicationRoleToken(t, privateKey, jwt.MapClaims{"scope": scope, "tid": tenant, "sub": subject})
	}
	request := func(method, target, auth, apiKey string) *httptest.ResponseRecorder {
		body := `{"permissions":["` + strings.Split(target, "/")[4] + `:read"]}`
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("Authorization", auth)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	platform := "Bearer " + applicationRoleToken(t, privateKey, jwt.MapClaims{
		"scope": "code-admin:tenants:admin", "tid": "home", "sub": "same-user", "role": string(domain.RoleAdmin),
		domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	bereia := "Bearer " + token("code-admin:identity:write", "bereia", "same-user")
	bereiaRead := "Bearer " + token("code-admin:identity:read", "bereia", "same-user")
	storifly := "Bearer " + token("code-admin:identity:write", "storifly", "same-user")
	hs, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "same-user", "scope": "code-admin:tenants:admin", "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte("legacy"))
	tests := []struct {
		name, method, target, auth, key string
		want                            int
	}{
		{name: "query API key rejected", method: http.MethodPut, target: "/v1/admin/tenants/bereia/roles/query?key=secret", auth: platform, want: http.StatusUnauthorized},
		{name: "bearer required", method: http.MethodPut, target: "/v1/admin/tenants/bereia/roles/missing", key: "secret", want: http.StatusUnauthorized},
		{name: "HS identity token rejected", method: http.MethodPut, target: "/v1/admin/tenants/bereia/roles/hs", auth: "Bearer " + hs, key: "secret", want: http.StatusUnauthorized},
		{name: "ADMIN without scope", method: http.MethodPut, target: "/v1/admin/tenants/bereia/roles/admin", auth: "Bearer " + applicationRoleToken(t, privateKey, jwt.MapClaims{"sub": "same-user", "role": "ADMIN", "tid": "bereia"}), key: "secret", want: http.StatusForbidden},
		{name: "wrong scope", method: http.MethodPut, target: "/v1/admin/tenants/bereia/roles/wrong", auth: "Bearer " + token("code-admin:identity:write-extra code-admin:tenants:admin-extra", "bereia", "same-user"), key: "secret", want: http.StatusForbidden},
		{name: "wrong tid", method: http.MethodPut, target: "/v1/admin/tenants/storifly/roles/cross", auth: bereia, key: "secret", want: http.StatusForbidden},
		{name: "Bereia local", method: http.MethodPut, target: "/v1/admin/tenants/bereia/roles/bereia-read", auth: bereia, key: "secret", want: http.StatusCreated},
		{name: "Storifly local", method: http.MethodPut, target: "/v1/admin/tenants/storifly/roles/storifly-admin", auth: storifly, key: "secret", want: http.StatusCreated},
		{name: "platform cross tenant", method: http.MethodPut, target: "/v1/admin/tenants/storifly/roles/platform", auth: platform, key: "secret", want: http.StatusCreated},
		{name: "legacy POST query", method: http.MethodPost, target: "/v1/tenants/bereia/roles?key=secret", want: http.StatusUnauthorized},
	}
	for _, test := range tests {
		if rec := request(test.method, test.target, test.auth, test.key); rec.Code != test.want || test.name == "legacy POST query" && !strings.Contains(rec.Body.String(), "Invalid or missing API key") {
			t.Fatalf("%s: response=%d %s", test.name, rec.Code, rec.Body.String())
		}
	}
	reads := []struct {
		name, target, auth, key, body string
		want                          int
	}{
		{name: "list query API key rejected", target: "/v1/admin/tenants/bereia/roles?key=secret", auth: platform, want: http.StatusUnauthorized},
		{name: "exact query API key rejected", target: "/v1/admin/tenants/bereia/roles/bereia-read?key=secret", auth: platform, want: http.StatusUnauthorized},
		{name: "HS read rejected", target: "/v1/admin/tenants/bereia/roles", auth: "Bearer " + hs, key: "secret", want: http.StatusUnauthorized},
		{name: "ADMIN alone denied", target: "/v1/admin/tenants/bereia/roles", auth: "Bearer " + applicationRoleToken(t, privateKey, jwt.MapClaims{"sub": "same-user", "role": "ADMIN", "tid": "bereia"}), key: "secret", want: http.StatusForbidden},
		{name: "local read exact after put", target: "/v1/admin/tenants/bereia/roles/bereia-read", auth: bereiaRead, key: "secret", want: http.StatusOK, body: `"permissions":["bereia:read"]`},
		{name: "local write list", target: "/v1/admin/tenants/bereia/roles", auth: bereia, key: "secret", want: http.StatusOK, body: `"name":"bereia-read"`},
		{name: "local read foreign denied", target: "/v1/admin/tenants/storifly/roles", auth: bereiaRead, key: "secret", want: http.StatusForbidden},
		{name: "platform exact cross tenant", target: "/v1/admin/tenants/storifly/roles/storifly-admin", auth: platform, key: "secret", want: http.StatusOK, body: `"name":"storifly-admin"`},
		{name: "exact not found", target: "/v1/admin/tenants/bereia/roles/missing", auth: platform, key: "secret", want: http.StatusNotFound, body: `{"error":"role not found"}`},
		{name: "invalid tenant", target: "/v1/admin/tenants/Bereia/roles", auth: platform, key: "secret", want: http.StatusBadRequest, body: `{"error":"invalid tenant"}`},
		{name: "invalid role", target: "/v1/admin/tenants/bereia/roles/role.name-", auth: platform, key: "secret", want: http.StatusBadRequest, body: `{"error":"invalid argument"}`},
	}
	for _, test := range reads {
		rec := request(http.MethodGet, test.target, test.auth, test.key)
		if rec.Code != test.want || test.body != "" && !strings.Contains(rec.Body.String(), test.body) || strings.Contains(rec.Body.String(), `"secret"`) {
			t.Fatalf("%s: response=%d %s", test.name, rec.Code, rec.Body.String())
		}
	}
	for range 5 {
		rec := request(http.MethodGet, "/v1/admin/tenants/storifly/roles", platform, "secret")
		platformIndex := strings.Index(rec.Body.String(), `"name":"platform"`)
		storiflyIndex := strings.Index(rec.Body.String(), `"name":"storifly-admin"`)
		if rec.Code != http.StatusOK || platformIndex < 0 || storiflyIndex < 0 || platformIndex > storiflyIndex {
			t.Fatalf("role list is not deterministic: %d %s", rec.Code, rec.Body.String())
		}
	}
	bereiaRole, _ := repo.Get(context.Background(), "bereia", "bereia-read")
	storiflyRole, _ := repo.Get(context.Background(), "storifly", "storifly-admin")
	bereiaRoles, _ := repo.List(context.Background(), "bereia")
	storiflyRoles, _ := repo.List(context.Background(), "storifly")
	if len(bereiaRoles) != 1 || len(storiflyRoles) != 2 || bereiaRole == nil || storiflyRole == nil || bereiaRole.Permissions[0] != "bereia:read" || storiflyRole.Permissions[0] != "storifly:read" {
		t.Fatalf("tenant isolation failed: bereia=%+v storifly=%+v", bereiaRole, storiflyRole)
	}
	if err := repo.Create(context.Background(), "bereia", &domain.Role{Name: "corrupt", TenantId: "bereia"}); err != nil {
		t.Fatalf("seed corrupt role: %v", err)
	}
	corrupt := request(http.MethodGet, "/v1/admin/tenants/bereia/roles/corrupt", platform, "secret")
	if corrupt.Code != http.StatusInternalServerError || corrupt.Body.String() != `{"error":"could not read role"}` {
		t.Fatalf("corrupt stored role did not fail closed: %d %s", corrupt.Code, corrupt.Body.String())
	}
	if err := client.HSet(context.Background(), "roles:mismatch", "alias", `{"name":"admin","tenantId":"mismatch","permissions":["credential-canary"]}`).Err(); err != nil {
		t.Fatalf("seed mismatched role field: %v", err)
	}
	if err := client.HSet(context.Background(), "roles:empty-state", "read", "").Err(); err != nil {
		t.Fatalf("seed empty role field: %v", err)
	}
	for _, corruptRead := range []struct{ target, body string }{
		{target: "/v1/admin/tenants/mismatch/roles", body: `{"error":"could not list roles"}`},
		{target: "/v1/admin/tenants/empty-state/roles/read", body: `{"error":"could not read role"}`},
	} {
		rec := request(http.MethodGet, corruptRead.target, platform, "secret")
		if rec.Code != http.StatusInternalServerError || rec.Body.String() != corruptRead.body || strings.Contains(rec.Body.String(), "credential-canary") {
			t.Fatalf("stored identity corruption was not redacted: %d %s", rec.Code, rec.Body.String())
		}
	}
	empty := gin.New()
	SetupMappings(empty, &config.Config{JwksPrivateKey: privateKey, IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin"}, nil, nil, nil, services.NewRoleService(repo), nil, nil, nil, nil, nil)
	SetupMappings(gin.New(), cfg, nil, nil, nil, nil, nil, nil, nil, saml.NewRedisStore(nil), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/tenants/bereia/roles", nil)
	req.Header.Set("X-API-Key", "secret")
	req.Header.Set("Authorization", platform)
	empty.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty configured API key did not fail closed: %d", rec.Code)
	}
	server.Close()
	rec = request(http.MethodGet, "/v1/admin/tenants/bereia/roles/bereia-read", platform, "secret")
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != `{"error":"could not read role"}` {
		t.Fatalf("storage failure was not redacted: %d %s", rec.Code, rec.Body.String())
	}
}

func TestNewApplicationAndWorkloadVerifier(t *testing.T) {
	server := miniredis.RunT(t)
	if _, err := NewApplication(nil); err == nil {
		t.Fatal("expected nil configuration error")
	}
	if _, err := NewApplication(&config.Config{RedisURL: "://invalid"}); err == nil {
		t.Fatal("expected Redis configuration error")
	}
	invalid := workloadRuntimeConfig("admin-key", applicationTestPrivateKey(t, 2048))
	invalid.RedisAddr = server.Addr()
	if _, err := NewApplication(invalid); err == nil {
		t.Fatal("expected verifier error")
	}
	application, err := NewApplication(&config.Config{RedisAddr: server.Addr()})
	if err != nil || application.Engine == nil || application.RoleSvc == nil || application.TenantSvc == nil || application.WorkloadSvc == nil {
		t.Fatalf("application=%+v err=%v", application, err)
	}
	t.Cleanup(func() { _ = application.Redis.Close() })
	strict, err := NewApplication(&config.Config{RedisAddr: server.Addr(), TenantScopedTokenClaimsV1: true, TenantScopedTokenClaimsV1Tenants: []string{"bereia"}})
	if err != nil || strict == nil {
		t.Fatalf("strict policy startup=%+v err=%v", strict, err)
	}
	t.Cleanup(func() { _ = strict.Redis.Close() })
	tests := []struct {
		name                 string
		cfg                  config.WorkloadIdentityConfig
		nilVerifier, wantErr bool
	}{
		{name: "disabled", nilVerifier: true},
		{name: "single", cfg: config.WorkloadIdentityConfig{Issuer: "https://cluster", Audience: "aud", JWKSURL: "https://cluster/jwks", JWKSCacheTTLSeconds: 1}},
		{name: "multiple", cfg: config.WorkloadIdentityConfig{Audience: "aud", JWKSCacheTTLSeconds: 1, Providers: []config.WorkloadIdentityProviderConfig{{Issuer: "https://cluster-1", JWKSURL: "https://cluster-1/jwks"}, {Issuer: "https://cluster-2", JWKSURL: "https://cluster-2/jwks"}}}},
		{name: "bearer", cfg: config.WorkloadIdentityConfig{Audience: "aud", JWKSCacheTTLSeconds: 1, Providers: []config.WorkloadIdentityProviderConfig{{Issuer: "https://cluster", JWKSURL: "https://cluster/jwks", JWKSBearerTokenFile: t.TempDir() + "/token"}}}},
		{name: "relative bearer", cfg: config.WorkloadIdentityConfig{Providers: []config.WorkloadIdentityProviderConfig{{Issuer: "https://cluster", JWKSBearerTokenFile: "relative"}}}, wantErr: true},
		{name: "invalid", cfg: config.WorkloadIdentityConfig{Issuer: "https://cluster"}, wantErr: true},
	}
	for _, test := range tests {
		verifier, err := newWorkloadTokenVerifier(test.cfg)
		if (err != nil) != test.wantErr || !test.wantErr && (verifier == nil) != test.nilVerifier {
			t.Fatalf("%s: verifier=%T err=%v", test.name, verifier, err)
		}
	}
}

func TestNewApplicationWiresDynamicManagedAudienceTarget(t *testing.T) {
	server := miniredis.RunT(t)
	application, err := NewApplication(&config.Config{
		RedisAddr:                               server.Addr(),
		TenantTargetDiscoveryV2:                 true,
		TenantTargetDiscoveryV2PrincipalTenants: []string{"local-tenant"},
	})
	if err != nil {
		t.Fatalf("dynamic application startup: %v", err)
	}
	t.Cleanup(func() { _ = application.Redis.Close() })
	if _, _, err = application.TenantSvc.CreateWithID(context.Background(), "new-tenant", domain.TenantCreateReq{
		Name: "New Tenant", Slug: "new-tenant",
	}); err != nil {
		t.Fatalf("create dynamic tenant: %v", err)
	}
	response, created, err := application.ClientSvc.EnsureCodeAdminAudience(context.Background(), "new-tenant", domain.ManagedAudienceClientEnsureReq{
		DefaultScopes: []string{"code-admin:workloads:read"},
	})
	if err != nil || !created || response.TenantId != "new-tenant" {
		t.Fatalf("dynamic managed client: response=%+v created=%v err=%v", response, created, err)
	}
	router := gin.New()
	SetupMappings(
		router,
		application.Config,
		application.UserService,
		application.TenantSvc,
		application.MemberSvc,
		application.RoleSvc,
		application.ClientSvc,
		application.WorkloadSvc,
		application.WorkloadAccountSvc,
		nil,
		nil,
	)
	found := false
	for _, route := range router.Routes() {
		if route.Method == http.MethodPut && route.Path == "/v1/admin/tenants/:tenantId/clients/code-admin-api:ensure" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("dynamic managed audience route is not mounted")
	}
}

func applicationRoleToken(t *testing.T, privateKey string, claims jwt.MapClaims) string {
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	claims["iss"], claims["aud"], claims["exp"] = "https://tikti", "code-admin", time.Now().Add(time.Hour).Unix()
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
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
