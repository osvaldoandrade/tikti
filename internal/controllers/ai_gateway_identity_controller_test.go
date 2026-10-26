package controllers

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeAIGatewayIdentityService struct {
	calls          []string
	administrators []string
	deactivations  []string
	created        bool
	err            error
}

func (f *fakeAIGatewayIdentityService) Deactivate(_ context.Context, tenantID string) (*domain.AIGatewayDeactivationResp, bool, error) {
	f.deactivations = append(f.deactivations, tenantID)
	if f.err != nil {
		return nil, false, f.err
	}
	return &domain.AIGatewayDeactivationResp{TenantId: tenantID, ClientId: domain.AIGatewayAudienceClientID, Status: domain.ClientStatusInactive}, f.created, nil
}

func (f *fakeAIGatewayIdentityService) Ensure(_ context.Context, tenantID, administratorID string) (*domain.AIGatewayIdentityResp, bool, error) {
	f.calls = append(f.calls, tenantID)
	f.administrators = append(f.administrators, administratorID)
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
	if service.administrators[0] != "admin-1" {
		t.Fatalf("activation did not target the caller's own user: %v", service.administrators)
	}
	// A platform administrator acting on another tenant has no own user there
	// to receive the tenant AI admin role, so activation fails closed.
	platform := token(jwt.MapClaims{"sub": "operator", "tid": "local-tenant", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin})
	if r := call("wecare", platform, `{}`, "application/json"); r.Code != http.StatusForbidden || len(service.calls) != before {
		t.Fatalf("cross-tenant platform=%d %s", r.Code, r.Body.String())
	}
	platformInTenant := token(jwt.MapClaims{"sub": "operator", "tid": "wecare", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin})
	if r := call("wecare", platformInTenant, `{}`, "application/json"); r.Code != http.StatusOK || service.calls[len(service.calls)-1] != "wecare" || service.administrators[len(service.administrators)-1] != "operator" {
		t.Fatalf("platform in tenant=%d %s", r.Code, r.Body.String())
	}
	for err, status := range map[error]int{
		domain.ErrRoleConflict:                         http.StatusConflict,
		domain.ErrManagedClientConflict:                http.StatusConflict,
		domain.ErrVersionConflict:                      http.StatusConflict,
		domain.ErrAIGatewayAdministrator:               http.StatusForbidden,
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

func TestAIGatewayIdentityDeactivationControllerAuthorityAndContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config, key := roleAccessConfig(t)
	config.AIGateway.Enabled = true
	service := &fakeAIGatewayIdentityService{created: true}
	router := gin.New()
	router.PUT("/v1/admin/tenants/:tenantId/ai-gateway/identity/deactivation", NewAIGatewayIdentityController(service, config).Deactivate)
	token := func(claims jwt.MapClaims) string { return "Bearer " + signRoleAccessToken(t, key, claims) }
	local := token(jwt.MapClaims{"sub": "admin-1", "tid": "bereia", "scope": "code-admin:identity:write"})
	call := func(tenant, auth, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/v1/admin/tenants/"+tenant+"/ai-gateway/identity/deactivation", strings.NewReader(body))
		req.Header.Set("Authorization", auth)
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}
	if r := call("bereia", local, `{}`); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), `"status":"INACTIVE"`) {
		t.Fatalf("deactivate=%d %s", r.Code, r.Body.String())
	}
	for name, test := range map[string]struct {
		tenant, auth, body string
		status             int
	}{
		"cross-tenant local admin": {"wecare", local, `{}`, http.StatusForbidden},
		"non-admin":                {"bereia", token(jwt.MapClaims{"sub": "a", "tid": "bereia", "scope": "code-admin:features:write code-admin:identity:read"}), `{}`, http.StatusForbidden},
		"no bearer":                {"bereia", "", `{}`, http.StatusUnauthorized},
		"caller-selected status":   {"bereia", local, `{"status":"ACTIVE"}`, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			if r := call(test.tenant, test.auth, test.body); r.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", r.Code, test.status, r.Body.String())
			}
		})
	}
	if len(service.deactivations) != 1 || len(service.calls) != 0 {
		t.Fatalf("rejected requests reached the service: %v %v", service.deactivations, service.calls)
	}
	platform := token(jwt.MapClaims{"sub": "operator", "tid": "local-tenant", "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin})
	if r := call("wecare", platform, `{}`); r.Code != http.StatusOK || service.deactivations[len(service.deactivations)-1] != "wecare" {
		t.Fatalf("platform deactivation=%d %s", r.Code, r.Body.String())
	}
	service.err = domain.ErrManagedClientConflict
	if r := call("bereia", local, `{}`); r.Code != http.StatusConflict {
		t.Fatalf("look-alike=%d %s", r.Code, r.Body.String())
	}
}

// Directory and dependency states an operator can repair are stable 409s with
// a code; the audit line names the closed stage and error class and never
// carries error text, tokens or values.
func TestAIGatewayIdentityControllerStableCodesAndAuditStage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	config, key := roleAccessConfig(t)
	config.AIGateway.Enabled = true
	service := &fakeAIGatewayIdentityService{}
	router := gin.New()
	router.PUT("/v1/admin/tenants/:tenantId/ai-gateway/identity", NewAIGatewayIdentityController(service, config).Ensure)
	bearer := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{"sub": "admin-1", "tid": "bereia", "scope": "code-admin:identity:write"})
	var audit bytes.Buffer
	previous, flags := log.Writer(), log.Flags()
	log.SetOutput(&audit)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(previous); log.SetFlags(flags) })
	call := func() *httptest.ResponseRecorder {
		audit.Reset()
		req := httptest.NewRequest(http.MethodPut, "/v1/admin/tenants/bereia/ai-gateway/identity", strings.NewReader(`{}`))
		req.Header.Set("Authorization", bearer)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-Id", "req-1")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}
	staged := func(stage string, err error) error { return &services.AIGatewayIdentityError{Stage: stage, Err: err} }
	secret := errors.New("redis password must stay private")
	for name, test := range map[string]struct {
		err          error
		status       int
		code, stage  string
		class, about string
	}{
		"administrator":         {staged(services.AIGatewayStageAssignment, domain.ErrAIGatewayAdministrator), http.StatusForbidden, "AIIdentityAdministratorRequired", "assignment", "administrator", "denied"},
		"invalid tenant":        {staged(services.AIGatewayStageTenant, domain.ErrInvalidTenant), http.StatusBadRequest, "AIIdentityInvalidRequest", "tenant", "invalid", "invalid"},
		"role conflict":         {staged(services.AIGatewayStageRoles, domain.ErrRoleConflict), http.StatusConflict, "AIIdentityRoleConflict", "roles", "role_conflict", "conflict"},
		"client conflict":       {staged(services.AIGatewayStageCeiling, domain.ErrManagedClientConflict), http.StatusConflict, "AIIdentityClientConflict", "ceiling", "client_conflict", "conflict"},
		"version conflict":      {staged(services.AIGatewayStageAssignment, domain.ErrVersionConflict), http.StatusConflict, "AIIdentityVersionConflict", "assignment", "version_conflict", "conflict"},
		"directory invariant":   {staged(services.AIGatewayStageAssignment, domain.ErrDirectoryInvariant), http.StatusConflict, "AIIdentityDirectoryInvariant", "assignment", "directory_invariant", "conflict"},
		"dependency missing":    {staged(services.AIGatewayStageAssignment, domain.ErrMembershipDependencyNotFound), http.StatusConflict, "AIIdentityDependencyMissingOrInactive", "assignment", "dependency", "conflict"},
		"dependency inactive":   {staged(services.AIGatewayStageAssignment, domain.ErrMembershipDependencyInactive), http.StatusConflict, "AIIdentityDependencyMissingOrInactive", "assignment", "dependency", "conflict"},
		"audience internal":     {staged(services.AIGatewayStageAudience, secret), http.StatusInternalServerError, "AIIdentityInternal", "audience", "internal", "failure"},
		"unstaged internal":     {secret, http.StatusInternalServerError, "AIIdentityInternal", "unknown", "internal", "failure"},
		"unconfigured internal": {staged(services.AIGatewayStageRequest, domain.ErrAuthenticationUnavailable), http.StatusInternalServerError, "AIIdentityInternal", "request", "unavailable", "failure"},
	} {
		t.Run(name, func(t *testing.T) {
			service.err = test.err
			r := call()
			if r.Code != test.status || !strings.Contains(r.Body.String(), `"code":"`+test.code+`"`) || strings.Contains(r.Body.String(), "redis") {
				t.Fatalf("status=%d body=%s", r.Code, r.Body.String())
			}
			line := audit.String()
			if !strings.Contains(line, "result="+test.about+" stage="+test.stage+" error_class="+test.class+"\n") ||
				!strings.Contains(line, `request_id="req-1"`) || strings.Contains(line, "redis") || strings.Contains(line, "Bearer") {
				t.Fatalf("audit=%q", line)
			}
		})
	}
	service.err = nil
	if r := call(); r.Code != http.StatusOK || !strings.Contains(audit.String(), "result=replay stage=none error_class=none") {
		t.Fatalf("success audit=%q status=%d", audit.String(), r.Code)
	}
}
