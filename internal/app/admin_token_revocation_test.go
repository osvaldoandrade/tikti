package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type revocableAdminTokenService struct {
	services.UserService
	revoked atomic.Bool
}

func (s *revocableAdminTokenService) ValidateAccessToken(context.Context, string, string, string) (jwt.MapClaims, error) {
	if s.revoked.Load() {
		return nil, domain.ErrInvalidToken
	}
	return jwt.MapClaims{
		"sub":                         "platform-operator",
		"tid":                         domain.MasterTenantID,
		"role":                        string(domain.RoleAdmin),
		"scope":                       domain.PlatformTenantAdminScope,
		domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	}, nil
}

type countingTenantInventoryService struct {
	services.TenantService
	calls atomic.Int32
}

func (s *countingTenantInventoryService) List(context.Context, uint64, int64) (*domain.TenantsPage, error) {
	s.calls.Add(1)
	return &domain.TenantsPage{Tenants: []domain.TenantResp{{
		Id: domain.MasterTenantID, Slug: domain.MasterTenantID, Name: domain.MasterTenantName,
		Status: domain.TenantStatusActive, TenantType: domain.TenantTypeMaster,
	}}}, nil
}

func TestAdministrativeHTTPBoundaryRejectsReusedRevokedAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokens := &revocableAdminTokenService{}
	tenants := &countingTenantInventoryService{}
	router := gin.New()
	cfg := &config.Config{ApiKey: "server-key", IssuerBaseURL: "https://issuer.example", DefaultAudience: "code-admin"}
	SetupMappings(router, cfg, tokens, tenants, nil, nil, nil, nil, nil, nil)

	request := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer captured-access-token")
		req.Header.Set("X-API-Key", "server-key")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}

	if response := request("/v1/admin/identity/tenant-inventory"); response.Code != http.StatusOK || tenants.calls.Load() != 1 {
		t.Fatalf("current token status=%d calls=%d body=%s", response.Code, tenants.calls.Load(), response.Body.String())
	}
	tokens.revoked.Store(true)
	if response := request("/v1/admin/identity/tenant-inventory"); response.Code != http.StatusUnauthorized || tenants.calls.Load() != 1 {
		t.Fatalf("revoked token status=%d calls=%d body=%s", response.Code, tenants.calls.Load(), response.Body.String())
	}
}

func TestPrivateCurrentAccessTokenAuthorityIsBodylessAndStateful(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokens := &revocableAdminTokenService{}
	router := gin.New()
	cfg := &config.Config{ApiKey: "server-key", IssuerBaseURL: "https://issuer.example", DefaultAudience: "code-admin"}
	SetupMappings(router, cfg, tokens, nil, nil, nil, nil, nil, nil, nil)

	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/internal/access-tokens:validate", nil)
		req.Header.Set("Authorization", "Bearer captured-access-token")
		req.Header.Set("X-API-Key", "server-key")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}

	if response := request(); response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("current authority status=%d body=%q", response.Code, response.Body.String())
	}
	tokens.revoked.Store(true)
	if response := request(); response.Code != http.StatusUnauthorized || response.Body.String() == "captured-access-token" {
		t.Fatalf("revoked authority status=%d body=%q", response.Code, response.Body.String())
	}
}
