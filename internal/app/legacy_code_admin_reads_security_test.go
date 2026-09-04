package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type legacyReadTenantService struct {
	getCalls  int
	listCalls int
}

func (*legacyReadTenantService) Create(context.Context, domain.TenantCreateReq) (*domain.TenantResp, error) {
	return nil, nil
}

func (*legacyReadTenantService) CreateWithID(context.Context, string, domain.TenantCreateReq) (*domain.TenantResp, bool, error) {
	return nil, false, nil
}

func (s *legacyReadTenantService) Get(_ context.Context, tenantID string) (*domain.TenantResp, error) {
	s.getCalls++
	return &domain.TenantResp{Id: tenantID, Name: tenantID, Slug: tenantID, Status: domain.TenantStatusActive}, nil
}

func (s *legacyReadTenantService) List(context.Context, uint64, int64) (*domain.TenantsPage, error) {
	s.listCalls++
	return &domain.TenantsPage{Tenants: []domain.TenantResp{{Id: "storifly", Name: "Storifly", Slug: "storifly", Status: domain.TenantStatusActive}}}, nil
}

func (*legacyReadTenantService) EnsureDefault(context.Context) (*domain.TenantResp, error) {
	return nil, nil
}

type legacyReadRoleService struct{ listCalls int }

func (*legacyReadRoleService) Create(context.Context, string, domain.RoleCreateReq) (*domain.RoleResp, error) {
	return nil, nil
}

func (*legacyReadRoleService) CreateWithName(context.Context, string, string, domain.RolePutReq) (*domain.RoleResp, bool, error) {
	return nil, false, nil
}

func (*legacyReadRoleService) GetByName(context.Context, string, string) (*domain.RoleResp, error) {
	return nil, nil
}

func (*legacyReadRoleService) ListCanonical(context.Context, string) ([]*domain.RoleResp, error) {
	return nil, nil
}

func (s *legacyReadRoleService) List(_ context.Context, tenantID string) ([]*domain.RoleResp, error) {
	s.listCalls++
	return []*domain.RoleResp{{Name: tenantID + "-admin", Permissions: []string{"code-admin:identity:write"}}}, nil
}

func (*legacyReadRoleService) ResolvePermissions(context.Context, string, []string) ([]string, error) {
	return nil, nil
}

type legacyReadClientService struct {
	getCalls  int
	listCalls int
}

func (*legacyReadClientService) Create(context.Context, string, domain.ClientCreateReq) (*domain.ClientResp, error) {
	return nil, nil
}

func (*legacyReadClientService) EnsureCodeAdminAudience(context.Context, string, domain.ManagedAudienceClientEnsureReq) (*domain.ManagedAudienceClientResp, bool, error) {
	return nil, false, nil
}

func (s *legacyReadClientService) Get(_ context.Context, tenantID, clientID string) (*domain.ClientResp, error) {
	s.getCalls++
	return &domain.ClientResp{ClientId: clientID, Type: "SERVICE", DefaultScopes: []string{"code-admin:identity:read"}}, nil
}

func (s *legacyReadClientService) List(_ context.Context, tenantID string) ([]*domain.ClientResp, error) {
	s.listCalls++
	return []*domain.ClientResp{{ClientId: "code-admin-api", Type: "SERVICE", DefaultScopes: []string{"code-admin:identity:read"}}}, nil
}

func (*legacyReadClientService) GetClient(context.Context, string, string) (*domain.Client, error) {
	return nil, nil
}

func TestLegacyCodeAdminReadsUseExactTenantAuthority(t *testing.T) {
	gin.SetMode(gin.TestMode)
	privateKey := applicationTestPrivateKey(t, 2048)
	cfg := &config.Config{
		ApiKey: "api-key", JwtSecret: "legacy-secret", JwksPrivateKey: privateKey,
		IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin",
	}
	tenants := &legacyReadTenantService{}
	roles := &legacyReadRoleService{}
	clients := &legacyReadClientService{}
	router := gin.New()
	SetupMappings(router, cfg, nil, tenants, nil, roles, clients, nil, nil, nil, nil)

	token := func(claims jwt.MapClaims) string {
		return "Bearer " + applicationRoleToken(t, privateKey, claims)
	}
	localRead := token(jwt.MapClaims{
		"sub": "storifly-admin", "scope": "code-admin:identity:read", "tid": "storifly",
	})
	localWrite := token(jwt.MapClaims{
		"sub": "storifly-admin", "scope": "code-admin:identity:write", "tid": "storifly",
	})
	foreignRoleAdmin := token(jwt.MapClaims{
		"sub": "foreign-admin", "scope": "code-admin:identity:write", "tid": "foreign",
		"role": string(domain.RoleAdmin),
	})
	platform := token(jwt.MapClaims{
		"sub": "platform-admin", "scope": domain.PlatformTenantAdminScope, "tid": "home",
		"role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	platformWithoutProvenance := token(jwt.MapClaims{
		"sub": "platform-admin", "scope": domain.PlatformTenantAdminScope, "tid": "home",
		"role": string(domain.RoleAdmin),
	})
	legacyHSToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "storifly-admin", "scope": "code-admin:identity:read", "tid": "storifly",
		"role": string(domain.RoleAdmin), "iss": "https://tikti", "aud": "code-admin",
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(cfg.JwtSecret))
	if err != nil {
		t.Fatalf("sign legacy HS256 token: %v", err)
	}

	totalCalls := func() int {
		return tenants.getCalls + tenants.listCalls + roles.listCalls + clients.getCalls + clients.listCalls
	}
	request := func(path, authorization string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", authorization)
		req.Header.Set("X-API-Key", cfg.ApiKey)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}

	for _, test := range []struct {
		name, path, authorization string
	}{
		{name: "target token reads tenant", path: "/v1/tenants/id/storifly", authorization: localRead},
		{name: "target write token reads roles", path: "/v1/tenants/storifly/roles", authorization: localWrite},
		{name: "target token lists clients", path: "/v1/tenants/storifly/clients", authorization: localRead},
		{name: "target token reads client", path: "/v1/tenants/storifly/clients/code-admin-api", authorization: localRead},
		{name: "provenance platform token lists tenants", path: "/v1/tenants", authorization: platform},
		{name: "provenance platform token reads foreign tenant", path: "/v1/tenants/id/storifly", authorization: platform},
		{name: "provenance platform token reads foreign roles", path: "/v1/tenants/storifly/roles", authorization: platform},
		{name: "provenance platform token reads foreign clients", path: "/v1/tenants/storifly/clients", authorization: platform},
		{name: "provenance platform token reads foreign client", path: "/v1/tenants/storifly/clients/code-admin-api", authorization: platform},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := totalCalls()
			response := request(test.path, test.authorization)
			if response.Code != http.StatusOK {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
			if totalCalls()-before != 1 {
				t.Fatalf("service call delta = %d, want 1", totalCalls()-before)
			}
		})
	}

	for _, test := range []struct {
		name, path, authorization string
		want                      int
	}{
		{name: "foreign role admin cannot read tenant", path: "/v1/tenants/id/storifly", authorization: foreignRoleAdmin, want: http.StatusForbidden},
		{name: "foreign role admin cannot read roles", path: "/v1/tenants/storifly/roles", authorization: foreignRoleAdmin, want: http.StatusForbidden},
		{name: "foreign role admin cannot list clients", path: "/v1/tenants/storifly/clients", authorization: foreignRoleAdmin, want: http.StatusForbidden},
		{name: "foreign role admin cannot read client", path: "/v1/tenants/storifly/clients/code-admin-api", authorization: foreignRoleAdmin, want: http.StatusForbidden},
		{name: "local target cannot list global tenants", path: "/v1/tenants", authorization: localRead, want: http.StatusForbidden},
		{name: "platform scope without provenance cannot list tenants", path: "/v1/tenants", authorization: platformWithoutProvenance, want: http.StatusForbidden},
		{name: "platform scope without provenance cannot read target", path: "/v1/tenants/id/storifly", authorization: platformWithoutProvenance, want: http.StatusForbidden},
		{name: "legacy HS256 admin token is rejected", path: "/v1/tenants/id/storifly", authorization: "Bearer " + legacyHSToken, want: http.StatusUnauthorized},
		{name: "missing authentication retains legacy response", path: "/v1/tenants/id/storifly", want: http.StatusUnauthorized},
		{name: "non canonical target is rejected", path: "/v1/tenants/id/Storifly", authorization: platform, want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := totalCalls()
			response := request(test.path, test.authorization)
			if response.Code != test.want {
				t.Fatalf("response = %d %s, want %d", response.Code, response.Body.String(), test.want)
			}
			if test.name == "missing authentication retains legacy response" && response.Body.String() != "{\"error\":\"missing authentication\"}" {
				t.Fatalf("response body = %s, want legacy error", response.Body.String())
			}
			if totalCalls() != before {
				t.Fatalf("denied request reached a service: before=%d after=%d", before, totalCalls())
			}
		})
	}
}

var (
	_ services.TenantService = (*legacyReadTenantService)(nil)
	_ services.RoleService   = (*legacyReadRoleService)(nil)
	_ services.ClientService = (*legacyReadClientService)(nil)
)
