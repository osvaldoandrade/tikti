package controllers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeAIGatewayIdentityService struct {
	calls   []string
	created bool
	err     error
}

func (f *fakeAIGatewayIdentityService) Ensure(_ context.Context, tenantID string) (*domain.AIGatewayIdentityResp, bool, error) {
	f.calls = append(f.calls, tenantID)
	if f.err != nil {
		return nil, false, f.err
	}
	return &domain.AIGatewayIdentityResp{TenantId: tenantID, Client: domain.ManagedAudienceClientResp{
		ClientId: domain.AIGatewayAudienceClientID, TenantId: tenantID, Type: domain.ClientTypeService,
		AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: []string{"code-llm:invoke", "code-llm:models:read", "code-llm:usage:read"},
		Status: domain.ClientStatusActive,
	}, Roles: []domain.RoleResp{{Name: tenantID + "-ai-admin"}, {Name: tenantID + "-ai-user"}}}, f.created, nil
}

func TestAIGatewayIdentityControllerAuthorityAndContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config, key := roleAccessConfig(t)
	config.AIGateway.Enabled = true
	service := &fakeAIGatewayIdentityService{created: true}
	router := gin.New()
	router.PUT("/v1/admin/tenants/:tenantId/ai-gateway/identity", NewAIGatewayIdentityController(service, config).Ensure)
	token := func(claims jwt.MapClaims) string { return "Bearer " + signRoleAccessToken(t, key, claims) }
	local := token(jwt.MapClaims{"sub": "admin-1", "tid": "bereia", "scope": "code-admin:identity:write code-admin:features:write"})
	call := func(tenant, auth, body, contentType string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/v1/admin/tenants/"+tenant+"/ai-gateway/identity", strings.NewReader(body))
		req.Header.Set("Authorization", auth)
		req.Header.Set("Content-Type", contentType)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}
	if r := call("bereia", local, `{}`, "application/json"); r.Code != http.StatusCreated || !strings.Contains(r.Body.String(), `"clientId":"code-llm-service"`) || strings.Contains(strings.ToLower(r.Body.String()), "secret") {
		t.Fatalf("create=%d %s", r.Code, r.Body.String())
	}
	service.created = false
	if r := call("bereia", local, ` { } `, "application/json; charset=utf-8"); r.Code != http.StatusOK {
		t.Fatalf("replay=%d %s", r.Code, r.Body.String())
	}
	before := len(service.calls)
	for name, test := range map[string]struct {
		tenant, auth, body, contentType string
		status                          int
	}{
		"cross-tenant local admin": {"wecare", local, `{}`, "application/json", http.StatusForbidden},
		"read-only identity":       {"bereia", token(jwt.MapClaims{"sub": "a", "tid": "bereia", "scope": "code-admin:identity:read code-admin:features:write"}), `{}`, "application/json", http.StatusForbidden},
		"features-only":            {"bereia", token(jwt.MapClaims{"sub": "a", "tid": "bereia", "scope": "code-admin:features:write"}), `{}`, "application/json", http.StatusForbidden},
		"missing subject":          {"bereia", token(jwt.MapClaims{"tid": "bereia", "scope": "code-admin:identity:write"}), `{}`, "application/json", http.StatusForbidden},
		"no bearer":                {"bereia", "", `{}`, "application/json", http.StatusUnauthorized},
		"caller-selected scopes":   {"bereia", local, `{"defaultScopes":["code-admin:ai:platform"]}`, "application/json", http.StatusBadRequest},
		"trailing value":           {"bereia", local, `{}{}`, "application/json", http.StatusBadRequest},
		"array body":               {"bereia", local, `[]`, "application/json", http.StatusBadRequest},
		"wrong media type":         {"bereia", local, `{}`, "text/plain", http.StatusUnsupportedMediaType},
		"non-canonical tenant":     {"Bereia", local, `{}`, "application/json", http.StatusBadRequest},
		"oversized body":           {"bereia", local, `{` + strings.Repeat(" ", 5<<10) + `}`, "application/json", http.StatusRequestEntityTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			if r := call(test.tenant, test.auth, test.body, test.contentType); r.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", r.Code, test.status, r.Body.String())
			}
		})
	}
	if len(service.calls) != before {
		t.Fatalf("rejected requests reached the service: %v", service.calls[before:])
	}
	platform := token(jwt.MapClaims{"sub": "operator", "tid": "local-tenant", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin})
	if r := call("wecare", platform, `{}`, "application/json"); r.Code != http.StatusOK || service.calls[len(service.calls)-1] != "wecare" {
		t.Fatalf("platform=%d %s", r.Code, r.Body.String())
	}
	for err, status := range map[error]int{
		domain.ErrRoleConflict:                         http.StatusConflict,
		domain.ErrManagedClientConflict:                http.StatusConflict,
		domain.ErrInvalidTenant:                        http.StatusBadRequest,
		errors.New("redis password must stay private"): http.StatusInternalServerError,
	} {
		service.err = err
		if r := call("bereia", local, `{}`, "application/json"); r.Code != status || strings.Contains(r.Body.String(), "redis") {
			t.Fatalf("%v: status=%d body=%s", err, r.Code, r.Body.String())
		}
	}
}

func TestAIGatewayIdentityControllerIsAbsentWhileAIIsDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config, key := roleAccessConfig(t)
	service := &fakeAIGatewayIdentityService{}
	router := gin.New()
	router.PUT("/v1/admin/tenants/:tenantId/ai-gateway/identity", NewAIGatewayIdentityController(service, config).Ensure)
	req := httptest.NewRequest(http.MethodPut, "/v1/admin/tenants/bereia/ai-gateway/identity", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+signRoleAccessToken(t, key, jwt.MapClaims{"sub": "a", "tid": "bereia", "scope": "code-admin:identity:write"}))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound || len(service.calls) != 0 {
		t.Fatalf("disabled AI ensured identity: %d %v", recorder.Code, service.calls)
	}
}
