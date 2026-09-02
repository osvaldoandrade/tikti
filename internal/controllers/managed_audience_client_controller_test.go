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

func TestManagedAudienceClientController_EnsureContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config, key := roleAccessConfig(t)
	config.TenantScopedTokenClaimsV1 = true
	config.TenantScopedTokenClaimsV1Tenants = []string{"bereia"}
	created := true
	var serviceError error
	service := &fakeClientService{ensureFn: func(
		_ context.Context,
		tenantID string,
		request domain.ManagedAudienceClientEnsureReq,
	) (*domain.ManagedAudienceClientResp, bool, error) {
		if serviceError != nil {
			return nil, false, serviceError
		}
		return &domain.ManagedAudienceClientResp{
			ClientId: domain.CodeAdminAudienceClientID, TenantId: tenantID,
			Type: domain.ClientTypeService, AllowedGrantTypes: []string{"token_exchange"},
			DefaultScopes: request.DefaultScopes, Status: domain.ClientStatusActive,
		}, created, nil
	}}
	router := gin.New()
	router.PUT("/admin/tenants/:tenantId/clients/code-admin-api:ensure", NewManagedAudienceClientController(service, config).Ensure)
	auth := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{
		"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope,
		"role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	request := func(body, contentType string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/bereia/clients/code-admin-api:ensure", strings.NewReader(body))
		req.Header.Set("Authorization", auth)
		req.Header.Set("Content-Type", contentType)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}
	body := `{"defaultScopes":["code-admin:clusters:read","code-admin:workloads:read","console:clusters:read"]}`
	recorder := request(body, "application/json; charset=utf-8")
	if recorder.Code != http.StatusCreated || strings.Contains(strings.ToLower(recorder.Body.String()), "secret") ||
		!strings.Contains(recorder.Body.String(), `"clientId":"code-admin-api"`) {
		t.Fatalf("create response=%d %s", recorder.Code, recorder.Body.String())
	}
	created = false
	if recorder = request(body, "application/json"); recorder.Code != http.StatusOK {
		t.Fatalf("replay response=%d %s", recorder.Code, recorder.Body.String())
	}
	serviceError = domain.ErrManagedClientConflict
	if recorder = request(body, "application/json"); recorder.Code != http.StatusConflict {
		t.Fatalf("conflict response=%d %s", recorder.Code, recorder.Body.String())
	}
	serviceError = errors.New("redis password must stay private")
	if recorder = request(body, "application/json"); recorder.Code != http.StatusInternalServerError ||
		strings.Contains(recorder.Body.String(), "redis") {
		t.Fatalf("failure response=%d %s", recorder.Code, recorder.Body.String())
	}
}

func TestManagedAudienceClientController_RejectsInvalidInput(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config, key := roleAccessConfig(t)
	config.TenantScopedTokenClaimsV1 = true
	config.TenantScopedTokenClaimsV1Tenants = []string{"bereia"}
	calls := 0
	service := &fakeClientService{ensureFn: func(
		context.Context,
		string,
		domain.ManagedAudienceClientEnsureReq,
	) (*domain.ManagedAudienceClientResp, bool, error) {
		calls++
		return &domain.ManagedAudienceClientResp{}, true, nil
	}}
	router := gin.New()
	router.PUT("/admin/tenants/:tenantId/clients/code-admin-api:ensure", NewManagedAudienceClientController(service, config).Ensure)
	auth := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{
		"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope,
		"role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	for _, test := range []struct {
		name, body, contentType string
		status                  int
	}{
		{name: "unknown field", body: `{"defaultScopes":["scope:a"],"type":"SERVICE"}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "duplicate field", body: `{"defaultScopes":["scope:a"],"defaultScopes":["scope:b"]}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "null scopes", body: `{"defaultScopes":null}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "missing scopes", body: `{}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "trailing JSON", body: `{"defaultScopes":["scope:a"]} {}`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "wrong content type", body: `{"defaultScopes":["scope:a"]}`, contentType: "text/plain", status: http.StatusUnsupportedMediaType},
		{name: "oversized", body: `{"defaultScopes":["` + strings.Repeat("x", managedAudienceClientBodyLimit) + `"]}`, contentType: "application/json", status: http.StatusRequestEntityTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/admin/tenants/bereia/clients/code-admin-api:ensure", strings.NewReader(test.body))
			req.Header.Set("Authorization", auth)
			req.Header.Set("Content-Type", test.contentType)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if recorder.Code != test.status {
				t.Fatalf("response=%d %s", recorder.Code, recorder.Body.String())
			}
		})
	}
	if calls != 0 {
		t.Fatalf("invalid inputs called service %d times", calls)
	}
}

func TestManagedAudienceClientController_DynamicTargetRequiresPrincipalCanary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	cfg.TenantScopedTokenClaimsV1 = true
	cfg.TenantScopedTokenClaimsV1Tenants = []string{"bereia"}
	cfg.TenantTargetDiscoveryV2 = true
	cfg.TenantTargetDiscoveryV2PrincipalTenants = []string{"local-tenant"}
	calls := 0
	service := &fakeClientService{ensureFn: func(
		_ context.Context,
		tenantID string,
		request domain.ManagedAudienceClientEnsureReq,
	) (*domain.ManagedAudienceClientResp, bool, error) {
		calls++
		return &domain.ManagedAudienceClientResp{
			ClientId: domain.CodeAdminAudienceClientID, TenantId: tenantID,
			Type: domain.ClientTypeService, AllowedGrantTypes: []string{"token_exchange"},
			DefaultScopes: request.DefaultScopes, Status: domain.ClientStatusActive,
		}, true, nil
	}}
	router := gin.New()
	router.PUT("/admin/tenants/:tenantId/clients/code-admin-api:ensure", NewManagedAudienceClientController(service, cfg).Ensure)
	request := func(target, principal string) *httptest.ResponseRecorder {
		auth := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{
			"sub": "platform-operator", "tid": principal, "scope": domain.PlatformTenantAdminScope,
			"role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
		})
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/"+target+"/clients/code-admin-api:ensure", strings.NewReader(`{"defaultScopes":["code-admin:workloads:read"]}`))
		req.Header.Set("Authorization", auth)
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}
	if response := request("new-tenant", "local-tenant"); response.Code != http.StatusCreated || calls != 1 {
		t.Fatalf("canary response=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
	if response := request("new-tenant", "foreign-tenant"); response.Code != http.StatusNotFound || calls != 1 {
		t.Fatalf("foreign response=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
	cfg.TenantTargetDiscoveryV2 = false
	if response := request("new-tenant", "local-tenant"); response.Code != http.StatusNotFound || calls != 1 {
		t.Fatalf("disabled response=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
	if response := request("bereia", "foreign-tenant"); response.Code != http.StatusCreated || calls != 2 {
		t.Fatalf("static response=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
}
