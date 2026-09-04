package app

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

var errExactHTTPStorageCanary = errors.New("redis-password=storage-canary")

type exactHTTPTenants struct{ storageCalls *int }

func (f exactHTTPTenants) GetExact(_ context.Context, tenantID string) (*domain.Tenant, error) {
	if f.storageCalls != nil {
		(*f.storageCalls)++
	}
	switch tenantID {
	case "invalid-tenant":
		return nil, domain.ErrInvalidTenant
	case "missing-tenant":
		return nil, nil
	case "storage-tenant":
		return nil, errExactHTTPStorageCanary
	case "disabled":
		return &domain.Tenant{Id: tenantID, Status: domain.TenantStatusDisabled}, nil
	default:
		return &domain.Tenant{Id: tenantID, Status: domain.TenantStatusActive}, nil
	}
}

type exactHTTPMemberships struct{ storageCalls *int }

func (f exactHTTPMemberships) GetExact(_ context.Context, tenantID, userID string) (*domain.MembershipIdentity, error) {
	if f.storageCalls != nil {
		(*f.storageCalls)++
	}
	if userID == "missing" {
		return nil, nil
	}
	if userID == "storage" {
		return nil, errExactHTTPStorageCanary
	}
	if userID == "invalid" {
		return nil, domain.ErrInvalidArgument
	}
	return &domain.MembershipIdentity{Id: userID, TenantId: tenantID, UserId: userID, Roles: []string{tenantID + "-permission-canary"}}, nil
}

type exactHTTPList struct{ calls []string }

func (f *exactHTTPList) ListExact(_ context.Context, tenantID, token string, size int) (*domain.MembershipIdentitiesPage, error) {
	f.calls = append(f.calls, token+":"+strconv.Itoa(size))
	if token == "stale-token-canary" {
		return nil, repository.ErrExactMembershipListStaleCursor
	}
	if token == "storage-token-canary" {
		return nil, errExactHTTPStorageCanary
	}
	if token == "nil-token-canary" {
		return nil, nil
	}
	item := domain.MembershipIdentity{Id: "same-user", TenantId: tenantID, UserId: "same-user", Roles: []string{tenantID + "-permission-canary"}}
	return &domain.MembershipIdentitiesPage{Memberships: []domain.MembershipIdentity{item}, NextPageToken: "next-token-canary"}, nil
}

func TestExactMembershipRoutesContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	privateKey := applicationTestPrivateKey(t, 2048)
	cfg := &config.Config{ApiKey: "api-key-canary", IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin", JwksPrivateKey: privateKey,
		ExactMembershipReadRoutesV1: true, ExactMembershipReadRoutesV1Tenants: []string{"bereia", "disabled", "invalid-tenant", "missing-tenant", "storage-tenant", "storifly"},
		TenantTargetDiscoveryV2: true, TenantTargetDiscoveryV2PrincipalTenants: []string{"local-tenant"}}
	list := &exactHTTPList{}
	storageCalls := 0
	svc := services.NewExactMembershipReadService(exactHTTPTenants{storageCalls: &storageCalls}, exactHTTPMemberships{storageCalls: &storageCalls}, list)
	router := gin.New()
	setupExactMembershipReadMappings(router, cfg, svc)
	token := func(claims jwt.MapClaims) string { return "Bearer " + applicationRoleToken(t, privateKey, claims) }
	platform := token(jwt.MapClaims{
		"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope, "tid": "home", "role": string(domain.RoleAdmin),
		domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	platformWithoutProvenance := token(jwt.MapClaims{
		"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope, "tid": "home",
	})
	dynamicPlatform := token(jwt.MapClaims{"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin, "tid": "local-tenant"})
	dynamicForeign := token(jwt.MapClaims{"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin, "tid": "foreign-tenant"})
	dynamicWithoutProvenance := token(jwt.MapClaims{"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope, "tid": "local-tenant"})
	dynamicLocalRead := token(jwt.MapClaims{"sub": "local-operator", "scope": "code-admin:identity:read", "tid": "new-tenant"})
	dynamicLocalForeign := token(jwt.MapClaims{"sub": "local-operator", "scope": "code-admin:identity:read", "tid": "storifly"})
	localRead := token(jwt.MapClaims{"sub": "local-operator", "scope": "code-admin:identity:read", "tid": "bereia"})
	localWrite := token(jwt.MapClaims{"sub": "local-operator", "scope": "code-admin:identity:write", "tid": "bereia"})
	roleOnly := token(jwt.MapClaims{"sub": "operator", "role": "COMPANY_ADMIN", "tid": "bereia"})
	hs, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "operator", "scope": "code-admin:tenants:admin", "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte("legacy"))

	var audit bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&audit)
	t.Cleanup(func() { log.SetOutput(previous) })
	tests := []struct {
		name, target, auth, key, pageToken string
		want                               int
		body                               string
	}{
		{"no key allowed", "/v1/admin/tenants/bereia/memberships", "", "", "", 401, ""},
		{"no bearer allowed", "/v1/admin/tenants/bereia/memberships", "", "api-key-canary", "", 401, ""},
		{"no bearer outside", "/v1/admin/tenants/outside/memberships", "", "api-key-canary", "", 401, ""},
		{"no bearer invalid", "/v1/admin/tenants/Bad/memberships", "", "api-key-canary", "", 401, ""},
		{"query key", "/v1/admin/tenants/bereia/memberships?key=api-key-canary", platform, "", "", 401, ""},
		{"HS denied", "/v1/admin/tenants/bereia/memberships", "Bearer " + hs, "api-key-canary", "", 401, ""},
		{"role advisory", "/v1/admin/tenants/bereia/memberships", roleOnly, "api-key-canary", "", 403, ""},
		{"platform scope without provenance", "/v1/admin/tenants/bereia/memberships", platformWithoutProvenance, "api-key-canary", "", 403, ""},
		{"local foreign", "/v1/admin/tenants/storifly/memberships", localRead, "api-key-canary", "", 403, ""},
		{"local outside hides allowlist", "/v1/admin/tenants/outside/memberships", localRead, "api-key-canary", "", 403, ""},
		{"platform outside", "/v1/admin/tenants/outside/memberships", platform, "api-key-canary", "", 404, ""},
		{"dynamic target", "/v1/admin/tenants/new-tenant/memberships", dynamicPlatform, "api-key-canary", "", 200, `"tenantId":"new-tenant"`},
		{"dynamic local target", "/v1/admin/tenants/new-tenant/memberships", dynamicLocalRead, "api-key-canary", "", 200, `"tenantId":"new-tenant"`},
		{"dynamic local foreign", "/v1/admin/tenants/new-tenant/memberships", dynamicLocalForeign, "api-key-canary", "", 403, ""},
		{"dynamic foreign principal", "/v1/admin/tenants/new-tenant/memberships", dynamicForeign, "api-key-canary", "", 404, ""},
		{"dynamic missing provenance", "/v1/admin/tenants/new-tenant/memberships", dynamicWithoutProvenance, "api-key-canary", "", 403, ""},
		{"invalid tenant", "/v1/admin/tenants/Bad/memberships", platform, "api-key-canary", "", 400, "invalid argument"},
		{"long tenant", "/v1/admin/tenants/" + strings.Repeat("a", 64) + "/memberships", platform, "api-key-canary", "", 400, "invalid argument"},
		{"invalid user", "/v1/admin/tenants/bereia/memberships/user~bad", platform, "api-key-canary", "", 400, "invalid argument"},
		{"embedded dots remain valid", "/v1/admin/tenants/bereia/memberships/a..b", platform, "api-key-canary", "", 200, `"userId":"a..b"`},
		{"platform exact", "/v1/admin/tenants/bereia/memberships/same-user", platform, "api-key-canary", "", 200, `"tenantId":"bereia"`},
		{"local exact", "/v1/admin/tenants/bereia/memberships/same-user", localRead, "api-key-canary", "", 200, `"userId":"same-user"`},
		{"local write list", "/v1/admin/tenants/bereia/memberships", localWrite, "api-key-canary", "", 200, `"memberships":[`},
		{"second tenant no bleed", "/v1/admin/tenants/storifly/memberships/same-user", platform, "api-key-canary", "", 200, "storifly-permission-canary"},
		{"membership absent", "/v1/admin/tenants/bereia/memberships/missing", platform, "api-key-canary", "", 404, "membership not found"},
		{"disabled exact", "/v1/admin/tenants/disabled/memberships/same-user", platform, "api-key-canary", "", 500, "could not read membership"},
		{"disabled list", "/v1/admin/tenants/disabled/memberships", platform, "api-key-canary", "", 500, "could not list memberships"},
		{"missing tenant", "/v1/admin/tenants/missing-tenant/memberships/same-user", platform, "api-key-canary", "", 500, "could not read membership"},
		{"storage tenant", "/v1/admin/tenants/storage-tenant/memberships", platform, "api-key-canary", "", 500, "could not list memberships"},
		{"storage user", "/v1/admin/tenants/bereia/memberships/storage", platform, "api-key-canary", "", 500, "could not read membership"},
		{"service invalid", "/v1/admin/tenants/bereia/memberships/invalid", platform, "api-key-canary", "", 400, "invalid argument"},
		{"invalid tenant service", "/v1/admin/tenants/invalid-tenant/memberships", platform, "api-key-canary", "", 400, "invalid tenant"},
		{"stale", "/v1/admin/tenants/bereia/memberships?pageSize=1", platform, "api-key-canary", "stale-token-canary", 409, "restart pagination"},
		{"storage list", "/v1/admin/tenants/bereia/memberships", platform, "api-key-canary", "storage-token-canary", 500, "could not list memberships"},
		{"nil list", "/v1/admin/tenants/bereia/memberships", platform, "api-key-canary", "nil-token-canary", 500, "could not list memberships"},
		{"page one", "/v1/admin/tenants/bereia/memberships?pageSize=1", platform, "api-key-canary", "", 200, "nextPageToken"},
		{"page max", "/v1/admin/tenants/bereia/memberships?pageSize=200", platform, "api-key-canary", "", 200, "nextPageToken"},
		{"page zero", "/v1/admin/tenants/bereia/memberships?pageSize=0", platform, "api-key-canary", "", 400, "invalid argument"},
		{"page over", "/v1/admin/tenants/bereia/memberships?pageSize=201", platform, "api-key-canary", "", 400, "invalid argument"},
		{"page nondecimal", "/v1/admin/tenants/bereia/memberships?pageSize=+1", platform, "api-key-canary", "", 400, "invalid argument"},
		{"page empty", "/v1/admin/tenants/bereia/memberships?pageSize=", platform, "api-key-canary", "", 400, "invalid argument"},
		{"page duplicate", "/v1/admin/tenants/bereia/memberships?pageSize=1&pageSize=2", platform, "api-key-canary", "", 400, "invalid argument"},
		{"malformed query", "/v1/admin/tenants/bereia/memberships?pageSize=1;bad=2", platform, "api-key-canary", "", 401, "Invalid or missing API key"},
		{"query cursor", "/v1/admin/tenants/bereia/memberships?pageToken=query-canary", platform, "api-key-canary", "", 400, "invalid argument"},
		{"unknown query", "/v1/admin/tenants/bereia/memberships?unknown=query-canary", platform, "api-key-canary", "", 400, "invalid argument"},
		{"exact query", "/v1/admin/tenants/bereia/memberships/same-user?cursor=query-canary", platform, "api-key-canary", "", 400, "invalid argument"},
		{"token over", "/v1/admin/tenants/bereia/memberships", platform, "api-key-canary", strings.Repeat("x", 513), 400, "invalid argument"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			beforeStorageCalls, beforeListCalls := storageCalls, len(list.calls)
			req := httptest.NewRequest(http.MethodGet, test.target, nil)
			req.Header.Set("Authorization", test.auth)
			req.Header.Set("X-API-Key", test.key)
			req.Header.Set("X-Request-Id", "req-membership-1")
			if test.pageToken != "" {
				req.Header.Set("X-Page-Token", test.pageToken)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != test.want || rec.Header().Get("X-Tikti-Contract") != "exact-memberships-v1" || test.body != "" && !strings.Contains(rec.Body.String(), test.body) || strings.Contains(rec.Body.String(), errExactHTTPStorageCanary.Error()) {
				t.Fatalf("response = %d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
			}
			if test.name == "platform scope without provenance" && (storageCalls != beforeStorageCalls || len(list.calls) != beforeListCalls) {
				t.Fatalf("unauthorized request reached service: storage calls %d -> %d, list calls %d -> %d", beforeStorageCalls, storageCalls, beforeListCalls, len(list.calls))
			}
		})
	}
	for _, target := range []string{
		"/v1/admin/tenants/bereia/memberships/.",
		"/v1/admin/tenants/bereia/memberships/..",
	} {
		before := storageCalls
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Authorization", platform)
		req.Header.Set("X-API-Key", "api-key-canary")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || storageCalls != before || rec.Header().Get("X-Tikti-Contract") != "exact-memberships-v1" {
			t.Fatalf("dot segment %q = %d, storage calls %d -> %d", target, rec.Code, before, storageCalls)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/tenants/bereia/memberships", nil)
	req.Header.Set("X-API-Key", "api-key-canary")
	req.Header.Set("Authorization", platform)
	req.Header.Add("X-Page-Token", "first")
	req.Header.Add("X-Page-Token", "second")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != 400 || rec.Header().Get("X-Tikti-Contract") == "" {
		t.Fatalf("duplicate token = %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/admin/tenants/bereia/memberships", nil)
	req.Header.Set("X-API-Key", "api-key-canary")
	req.Header.Set("Authorization", platform)
	req.Header["X-Page-Token"] = []string{""}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("empty token = %d", rec.Code)
	}
	logged := audit.String()
	for _, forbidden := range []string{errExactHTTPStorageCanary.Error(), "permission-canary", "stale-token-canary", "storage-token-canary", "query-canary", strings.TrimPrefix(platform, "Bearer ")} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("audit leaked %q: %s", forbidden, logged)
		}
	}
	for _, expected := range []string{"action=membership_get", "action=membership_list", `actor="platform-operator"`, `tenant="bereia"`, `user="*"`, "result=success", "result=stale", "result=failure"} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("audit missing %q: %s", expected, logged)
		}
	}
}

func TestExactMembershipDynamicLocalTargetRequiresDiscoveryV2(t *testing.T) {
	gin.SetMode(gin.TestMode)
	privateKey := applicationTestPrivateKey(t, 2048)
	cfg := &config.Config{
		ApiKey: "api-key-canary", IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin",
		JwksPrivateKey: privateKey, ExactMembershipReadRoutesV1: true,
		ExactMembershipReadRoutesV1Tenants: []string{"bereia"},
	}
	list := &exactHTTPList{}
	router := gin.New()
	setupExactMembershipReadMappings(router, cfg, services.NewExactMembershipReadService(
		exactHTTPTenants{}, exactHTTPMemberships{}, list,
	))
	token := applicationRoleToken(t, privateKey, jwt.MapClaims{
		"sub": "local-operator", "scope": "code-admin:identity:read", "tid": "new-tenant",
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/tenants/new-tenant/memberships", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-API-Key", "api-key-canary")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || len(list.calls) != 0 {
		t.Fatalf("response=%d calls=%v body=%s", rec.Code, list.calls, rec.Body.String())
	}
}

func TestExactMembershipRoutesStartupAndDefaultOff(t *testing.T) {
	key := applicationTestPrivateKey(t, 2048)
	valid := &config.Config{ExactMembershipReadRoutesV1: true, ExactMembershipReadRoutesV1Tenants: []string{"bereia"}, ExactMembershipPageTokenSecret: strings.Repeat("k", 32), ApiKey: "key", IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin", JwksKeyID: "kid", JwksPrivateKey: key}
	derived, err := validateExactMembershipReadRuntimeConfig(valid)
	if err != nil || len(derived) != 32 {
		t.Fatalf("valid startup = %d, %v", len(derived), err)
	}
	derived[0] = 'x'
	if valid.ExactMembershipPageTokenSecret[0] != 'k' {
		t.Fatal("token key was not copied")
	}
	fallback := *valid
	fallback.ExactMembershipPageTokenSecret = ""
	fallback.JwtSecret = strings.Repeat("j", 32)
	if _, err = validateExactMembershipReadRuntimeConfig(&fallback); err != nil {
		t.Fatalf("fallback = %v", err)
	}
	for name, mutate := range map[string]func(*config.Config){
		"allowlist": func(c *config.Config) { c.ExactMembershipReadRoutesV1Tenants = nil }, "api key": func(c *config.Config) { c.ApiKey = "" },
		"issuer": func(c *config.Config) { c.IssuerBaseURL = "" }, "audience": func(c *config.Config) { c.DefaultAudience = "" },
		"kid": func(c *config.Config) { c.JwksKeyID = "" }, "RSA": func(c *config.Config) { c.JwksPrivateKey = "bad" },
		"secret": func(c *config.Config) { c.ExactMembershipPageTokenSecret = "short" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := *valid
			mutate(&copy)
			if _, err := validateExactMembershipReadRuntimeConfig(&copy); err == nil {
				t.Fatal("unsafe startup accepted")
			}
		})
	}
	if got, err := validateExactMembershipReadRuntimeConfig(&config.Config{}); err != nil || got != nil {
		t.Fatalf("off = %v, %v", got, err)
	}
	off := gin.New()
	setupExactMembershipReadMappings(off, &config.Config{}, services.NewExactMembershipReadService(exactHTTPTenants{}, exactHTTPMemberships{}, &exactHTTPList{}))
	rec := httptest.NewRecorder()
	off.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/admin/tenants/bereia/memberships", nil))
	if rec.Code != 404 || rec.Header().Get("X-Tikti-Contract") != "" {
		t.Fatalf("off route = %d %v", rec.Code, rec.Header())
	}
	server := miniredis.RunT(t)
	valid.RedisAddr = server.Addr()
	application, err := NewApplication(valid)
	if err != nil || application == nil || len(application.Engine.Routes()) != 2 {
		t.Fatalf("enabled application = %#v, %v", application, err)
	}
	_ = application.Redis.Close()
}
