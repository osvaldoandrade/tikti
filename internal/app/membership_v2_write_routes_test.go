package app

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type membershipV2HTTPService struct{ calls int }

func (s *membershipV2HTTPService) Ensure(_ context.Context, tenantID, userID string, roles []string) (*domain.Membership, bool, error) {
	s.calls++
	switch userID {
	case "missing":
		return nil, false, domain.ErrMembershipDependencyNotFound
	case "inactive":
		return nil, false, errors.Join(errors.New("wrapped-canary"), domain.ErrMembershipDependencyInactive)
	case "conflict":
		return nil, false, errors.Join(errors.New("wrapped-canary"), domain.ErrMembershipConflict)
	case "storage":
		return nil, false, errors.New("redis-password=storage-canary")
	case "invalid":
		return nil, false, domain.ErrInvalidArgument
	}
	if len(roles) == 0 || len(roles) > 100 {
		return nil, false, domain.ErrInvalidArgument
	}
	return &domain.Membership{Id: "m2_safe", TenantId: tenantID, UserId: userID, Roles: roles, CreatedAt: time.Unix(1, 0).UTC()}, userID != "replay", nil
}

func TestMembershipV2WriteRouteContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := applicationTestPrivateKey(t, 2048)
	cfg := &config.Config{ApiKey: "api-key", IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin", JwksPrivateKey: key,
		MembershipV2WriteRoutesV1: true, MembershipV2WriteRoutesV1Tenants: []string{"bereia", "storifly"},
		TenantTargetDiscoveryV2: true, TenantTargetDiscoveryV2PrincipalTenants: []string{"local-tenant"}}
	service := &membershipV2HTTPService{}
	var audit bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&audit)
	t.Cleanup(func() { log.SetOutput(previous) })
	router := gin.New()
	setupMembershipV2WriteMappings(router, cfg, service)
	token := func(claims jwt.MapClaims) string { return "Bearer " + applicationRoleToken(t, key, claims) }
	platform := token(jwt.MapClaims{"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin, "tid": "home"})
	dynamicPlatform := token(jwt.MapClaims{"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin, "tid": "local-tenant"})
	dynamicForeign := token(jwt.MapClaims{"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin, "tid": "foreign-tenant"})
	noSubject := token(jwt.MapClaims{"scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin, "tid": "home"})
	adminWithoutProvenance := token(jwt.MapClaims{"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin), "tid": "home"})
	companyAdmin := token(jwt.MapClaims{"sub": "company-operator", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleCompanyAdmin), "tid": "bereia"})
	companyAdminForgedProvenance := token(jwt.MapClaims{"sub": "company-operator", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleCompanyAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin, "tid": "bereia"})
	local := token(jwt.MapClaims{"sub": "local-operator", "scope": "code-admin:identity:write", "tid": "bereia"})
	dynamicLocal := token(jwt.MapClaims{"sub": "local-operator", "scope": "code-admin:identity:write", "tid": "new-tenant"})
	dynamicLocalForeign := token(jwt.MapClaims{"sub": "local-operator", "scope": "code-admin:identity:write", "tid": "storifly"})
	dynamicLocalReadOnly := token(jwt.MapClaims{"sub": "local-operator", "scope": "code-admin:identity:read", "tid": "new-tenant"})
	roleOnly := token(jwt.MapClaims{"sub": "role-operator", "role": "ADMIN", "tid": "bereia"})
	hs, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "operator", "scope": "code-admin:tenants:admin", "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte("legacy"))
	validBody := `{"roles":["reader-secret-canary"]}`
	bodyAtLimit := validBody + strings.Repeat(" ", (16<<10)-len(validBody))
	tests := []struct {
		name, target, auth, apiKey, body, contentType string
		want, calls                                   int
	}{
		{"no key", "/v1/admin/tenants/bereia/memberships/user-1", platform, "", validBody, "application/json", 401, 0},
		{"query key", "/v1/admin/tenants/bereia/memberships/user-1?key=api-key", platform, "", validBody, "application/json", 401, 0},
		{"no bearer", "/v1/admin/tenants/bereia/memberships/user-1", "", "api-key", validBody, "application/json", 401, 0},
		{"no subject", "/v1/admin/tenants/bereia/memberships/user-1", noSubject, "api-key", validBody, "application/json", 403, 0},
		{"HS denied", "/v1/admin/tenants/bereia/memberships/user-1", "Bearer " + hs, "api-key", validBody, "application/json", 401, 0},
		{"local same tenant", "/v1/admin/tenants/bereia/memberships/user-1", local, "api-key", validBody, "application/json", 201, 1},
		{"dynamic local target", "/v1/admin/tenants/new-tenant/memberships/user-1", dynamicLocal, "api-key", validBody, "application/json", 201, 1},
		{"dynamic local foreign", "/v1/admin/tenants/new-tenant/memberships/user-1", dynamicLocalForeign, "api-key", validBody, "application/json", 403, 0},
		{"dynamic local read only", "/v1/admin/tenants/new-tenant/memberships/user-1", dynamicLocalReadOnly, "api-key", validBody, "application/json", 403, 0},
		{"role advisory", "/v1/admin/tenants/bereia/memberships/user-1", roleOnly, "api-key", validBody, "application/json", 403, 0},
		{"admin without provenance", "/v1/admin/tenants/storifly/memberships/user-1", adminWithoutProvenance, "api-key", validBody, "application/json", 403, 0},
		{"company admin foreign target", "/v1/admin/tenants/storifly/memberships/user-1", companyAdmin, "api-key", validBody, "application/json", 403, 0},
		{"company admin forged provenance", "/v1/admin/tenants/storifly/memberships/user-1", companyAdminForgedProvenance, "api-key", validBody, "application/json", 403, 0},
		{"unallowlisted", "/v1/admin/tenants/outside/memberships/user-1", platform, "api-key", validBody, "application/json", 404, 0},
		{"dynamic target", "/v1/admin/tenants/new-tenant/memberships/user-1", dynamicPlatform, "api-key", validBody, "application/json", 201, 1},
		{"dynamic foreign principal", "/v1/admin/tenants/new-tenant/memberships/user-1", dynamicForeign, "api-key", validBody, "application/json", 404, 0},
		{"bad tenant", "/v1/admin/tenants/Bereia/memberships/user-1", platform, "api-key", validBody, "application/json", 400, 0},
		{"dot", "/v1/admin/tenants/bereia/memberships/.", platform, "api-key", validBody, "application/json", 400, 0},
		{"dot dot", "/v1/admin/tenants/bereia/memberships/..", platform, "api-key", validBody, "application/json", 400, 0},
		{"encoded alias", "/v1/admin/tenants/bereia/memberships/%75ser-1", platform, "api-key", validBody, "application/json", 400, 0},
		{"slash alias", "/v1/admin/tenants/bereia/memberships/user-1/", platform, "api-key", validBody, "application/json", 400, 0},
		{"query", "/v1/admin/tenants/bereia/memberships/user-1?x=1", platform, "api-key", validBody, "application/json", 400, 0},
		{"force query", "/v1/admin/tenants/bereia/memberships/force-query-canary?", platform, "api-key", validBody, "application/json", 400, 0},
		{"duplicate media type", "/v1/admin/tenants/bereia/memberships/user-1", platform, "api-key", validBody, "text/plain", 415, 0},
		{"unknown", "/v1/admin/tenants/bereia/memberships/user-1", platform, "api-key", `{"roles":["reader"],"secret":"x"}`, "application/json", 400, 0},
		{"duplicate", "/v1/admin/tenants/bereia/memberships/user-1", platform, "api-key", `{"roles":["reader"],"roles":["reader"]}`, "application/json", 400, 0},
		{"truncated", "/v1/admin/tenants/bereia/memberships/user-1", platform, "api-key", `{"roles":`, "application/json", 400, 0},
		{"null", "/v1/admin/tenants/bereia/memberships/user-1", platform, "api-key", `{"roles":null}`, "application/json", 400, 0},
		{"trailing", "/v1/admin/tenants/bereia/memberships/user-1", platform, "api-key", validBody + `{}`, "application/json", 400, 0},
		{"body over", "/v1/admin/tenants/bereia/memberships/user-1", platform, "api-key", strings.Repeat(" ", (16<<10)+1), "application/json", 413, 0},
		{"empty roles", "/v1/admin/tenants/bereia/memberships/user-1", platform, "api-key", `{"roles":[]}`, "application/json", 400, 1},
		{"created", "/v1/admin/tenants/bereia/memberships/user-1", platform, "api-key", bodyAtLimit, "application/json", 201, 1},
		{"second tenant", "/v1/admin/tenants/storifly/memberships/user-1", platform, "api-key", validBody, "application/json", 201, 1},
		{"replay", "/v1/admin/tenants/bereia/memberships/replay", platform, "api-key", validBody, "application/json", 200, 1},
		{"missing", "/v1/admin/tenants/bereia/memberships/missing", platform, "api-key", validBody, "application/json", 404, 1},
		{"inactive", "/v1/admin/tenants/bereia/memberships/inactive", platform, "api-key", validBody, "application/json", 409, 1},
		{"conflict", "/v1/admin/tenants/bereia/memberships/conflict", platform, "api-key", validBody, "application/json", 409, 1},
		{"storage", "/v1/admin/tenants/bereia/memberships/storage", platform, "api-key", validBody, "application/json", 500, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := service.calls
			req := httptest.NewRequest(http.MethodPut, test.target, strings.NewReader(test.body))
			req.Header.Set("Authorization", test.auth)
			req.Header.Set("X-API-Key", test.apiKey)
			req.Header.Set("Content-Type", test.contentType)
			if test.name == "duplicate media type" {
				req.Header.Add("Content-Type", "application/json")
			}
			req.Header.Set("X-Request-Id", "request-1")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != test.want || service.calls-before != test.calls || rec.Header().Get("X-Tikti-Contract") != "membership-v2-write-v1" || strings.Contains(rec.Body.String(), "storage-canary") || strings.Contains(rec.Body.String(), "wrapped-canary") {
				t.Fatalf("response=%d calls=%d headers=%v body=%s", rec.Code, service.calls-before, rec.Header(), rec.Body.String())
			}
			if (test.name == "inactive" && rec.Body.String() != `{"error":"`+domain.ErrMembershipDependencyInactive.Error()+`"}`) ||
				(test.name == "conflict" && rec.Body.String() != `{"error":"`+domain.ErrMembershipConflict.Error()+`"}`) {
				t.Fatalf("non-canonical conflict body: %s", rec.Body.String())
			}
		})
	}
	logged := audit.String()
	for _, forbidden := range []string{"reader-secret-canary", "storage-canary", "wrapped-canary", "force-query-canary", strings.TrimPrefix(platform, "Bearer ")} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("audit leaked %q: %s", forbidden, logged)
		}
	}
	for _, expected := range []string{"phase=intent", "phase=completion", "result=create", "result=replay", "result=not_found", "result=conflict", "result=failure"} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("audit missing %q: %s", expected, logged)
		}
	}
}

func TestMembershipV2WriteLocalAuthorizationRequiresDiscoveryV2(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key := applicationTestPrivateKey(t, 2048)
	cfg := &config.Config{
		ApiKey: "api-key", IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin",
		JwksPrivateKey: key, MembershipV2WriteRoutesV1: true,
		MembershipV2WriteRoutesV1Tenants: []string{"bereia"},
	}
	service := &membershipV2HTTPService{}
	router := gin.New()
	setupMembershipV2WriteMappings(router, cfg, service)
	token := applicationRoleToken(t, key, jwt.MapClaims{
		"sub": "local-operator", "scope": "code-admin:identity:write", "tid": "bereia",
	})
	req := httptest.NewRequest(http.MethodPut, "/v1/admin/tenants/bereia/memberships/user-1", strings.NewReader(`{"roles":["reader"]}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-API-Key", "api-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || service.calls != 0 {
		t.Fatalf("response=%d calls=%d body=%s", rec.Code, service.calls, rec.Body.String())
	}
}

type membershipV2FailWriter struct{ writes, failAt int }

func (w *membershipV2FailWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return 0, errors.New("audit unavailable")
	}
	return len(p), nil
}

func TestMembershipV2WriteAuditFailsClosed(t *testing.T) {
	key := applicationTestPrivateKey(t, 2048)
	for _, failAt := range []int{1, 2} {
		service, writer := &membershipV2HTTPService{}, &membershipV2FailWriter{failAt: failAt}
		cfg := &config.Config{ApiKey: "api-key", JwksPrivateKey: key, IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin", MembershipV2WriteRoutesV1: true, MembershipV2WriteRoutesV1Tenants: []string{"bereia"}}
		previous := log.Writer()
		log.SetOutput(writer)
		router := gin.New()
		setupMembershipV2WriteMappings(router, cfg, service)
		log.SetOutput(previous)
		req := httptest.NewRequest(http.MethodPut, "/v1/admin/tenants/bereia/memberships/user-1", strings.NewReader(`{"roles":["reader"]}`))
		req.Header.Set("Authorization", "Bearer "+applicationRoleToken(t, key, jwt.MapClaims{"sub": "operator", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin}))
		req.Header.Set("X-API-Key", "api-key")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != 500 || service.calls != failAt-1 {
			t.Fatalf("failAt=%d status=%d calls=%d", failAt, rec.Code, service.calls)
		}
	}
}

func TestMembershipV2WriteRuntimeAndDefaultOff(t *testing.T) {
	server, key := miniredis.RunT(t), applicationTestPrivateKey(t, 2048)
	valid := &config.Config{RedisAddr: server.Addr(), ApiKey: "api-key", IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin", JwksKeyID: "kid", JwksPrivateKey: key, ExactMembershipPageTokenSecret: strings.Repeat("k", 32),
		MembershipV2WriteRoutesV1: true, MembershipV2WriteRoutesV1Tenants: []string{"bereia"}, ExactMembershipReadRoutesV1: true, ExactMembershipReadRoutesV1Tenants: []string{"bereia"}, TenantScopedTokenClaimsV1: true, TenantScopedTokenClaimsV1Tenants: []string{"bereia"}}
	if err := validateMembershipV2WriteRuntimeConfig(valid); err != nil {
		t.Fatal(err)
	}
	application, err := NewApplication(valid)
	if err != nil || len(application.Engine.Routes()) != 4 {
		t.Fatalf("enabled application = %#v, %v", application, err)
	}
	_ = application.Redis.Close()
	invalid := *valid
	invalid.TenantScopedTokenClaimsV1Tenants = []string{"storifly"}
	if validateMembershipV2WriteRuntimeConfig(&invalid) == nil || validateMembershipV2WriteRuntimeConfig(&config.Config{}) != nil {
		t.Fatal("unsafe runtime configuration accepted")
	}
	if _, err := NewApplication(&invalid); err == nil {
		t.Fatal("unsafe application startup accepted")
	}
	invalid = *valid
	invalid.TenantScopedTokenClaimsV1 = false
	if validateMembershipV2WriteRuntimeConfig(&invalid) == nil {
		t.Fatal("write routes accepted disabled tenant-scoped token claims")
	}
	if _, err := NewApplication(&invalid); err == nil {
		t.Fatal("application accepted disabled tenant-scoped token claims")
	}
	router := gin.New()
	setupMembershipV2WriteMappings(router, &config.Config{}, &membershipV2HTTPService{})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v1/admin/tenants/bereia/memberships/user-1", nil))
	if rec.Code != 404 || rec.Header().Get("X-Tikti-Contract") != "" {
		t.Fatalf("off route = %d %v", rec.Code, rec.Header())
	}
}
