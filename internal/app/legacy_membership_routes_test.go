package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type legacyMembershipHTTPService struct {
	listCalls, createCalls, removeCalls int
}

func (s *legacyMembershipHTTPService) List(_ context.Context, tenantID string, _ uint64, _ int64) (*domain.TenantUsersPage, error) {
	s.listCalls++
	return &domain.TenantUsersPage{Users: []domain.TenantUserResp{{Id: tenantID + "-user-1"}}}, nil
}

func (s *legacyMembershipHTTPService) Create(_ context.Context, tenantID string, req domain.MembershipCreateReq) (*domain.MembershipResp, error) {
	s.createCalls++
	return &domain.MembershipResp{TenantId: tenantID, Email: req.Email}, nil
}

func (s *legacyMembershipHTTPService) Remove(_ context.Context, tenantID string, req domain.MembershipRemoveReq) (*domain.MembershipRemoveResp, error) {
	s.removeCalls++
	return &domain.MembershipRemoveResp{TenantId: tenantID, Email: req.Email}, nil
}

func (*legacyMembershipHTTPService) ListTenantIDsByUser(context.Context, string) ([]string, error) {
	return nil, nil
}

func TestLegacyMembershipRoutesRejectQueryStringAPIKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	privateKey := applicationTestPrivateKey(t, 2048)
	cfg := &config.Config{
		ApiKey: "api-key", JwksPrivateKey: privateKey,
		IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin",
	}
	svc := &legacyMembershipHTTPService{}
	router := gin.New()
	SetupMappings(router, cfg, nil, nil, svc, nil, nil, nil, nil, saml.NewRedisStore(nil), nil)
	auth := "Bearer " + applicationRoleToken(t, privateKey, jwt.MapClaims{
		"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope, "tid": "home",
		"role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})

	tests := []struct {
		name, method, target string
		body                 string
		headerKey            string
		want                 int
	}{
		{name: "list query key", method: http.MethodGet, target: "/v1/tenants/bereia/users?key=api-key", want: http.StatusUnauthorized},
		{name: "create query key", method: http.MethodPost, target: "/v1/tenants/bereia/users?key=api-key", body: `{"email":"u@example.com"}`, want: http.StatusUnauthorized},
		{name: "remove query key", method: http.MethodPost, target: "/v1/tenants/bereia/users/remove?key=api-key", body: `{"email":"u@example.com"}`, want: http.StatusUnauthorized},
		{name: "header plus leaked query key", method: http.MethodGet, target: "/v1/tenants/bereia/users?key=api-key", headerKey: "api-key", want: http.StatusUnauthorized},
		{name: "list header key", method: http.MethodGet, target: "/v1/tenants/bereia/users?pageSize=20", headerKey: "api-key", want: http.StatusOK},
		{name: "create header key", method: http.MethodPost, target: "/v1/tenants/bereia/users", body: `{"email":"u@example.com"}`, headerKey: "api-key", want: http.StatusOK},
		{name: "remove header key", method: http.MethodPost, target: "/v1/tenants/bereia/users/remove", body: `{"email":"u@example.com"}`, headerKey: "api-key", want: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := svc.listCalls + svc.createCalls + svc.removeCalls
			req := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			req.Header.Set("Authorization", auth)
			if test.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			if test.headerKey != "" {
				req.Header.Set("X-API-Key", test.headerKey)
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if recorder.Code != test.want {
				t.Fatalf("response = %d %s, want %d", recorder.Code, recorder.Body.String(), test.want)
			}
			after := svc.listCalls + svc.createCalls + svc.removeCalls
			wantDelta := 0
			if test.want == http.StatusOK {
				wantDelta = 1
			}
			if after-before != wantDelta {
				t.Fatalf("service call delta = %d, want %d", after-before, wantDelta)
			}
		})
	}
}

func TestCodeAdminLegacyReadsRejectQueryStringAPIKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	privateKey := applicationTestPrivateKey(t, 2048)
	cfg := &config.Config{
		ApiKey: "api-key", JwksPrivateKey: privateKey,
		IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin",
	}
	router := gin.New()
	SetupMappings(router, cfg, nil, nil, nil, nil, nil, nil, nil, saml.NewRedisStore(nil), nil)
	auth := "Bearer " + applicationRoleToken(t, privateKey, jwt.MapClaims{
		"sub": "platform-operator", "scope": domain.PlatformTenantAdminScope, "tid": "home",
		"role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	for _, target := range []string{
		"/v1/tenants?key=api-key",
		"/v1/tenants/id/bereia?key=api-key",
		"/v1/tenants/bereia/roles?key=api-key",
		"/v1/tenants/bereia/clients?key=api-key",
		"/v1/tenants/bereia/clients/code-admin-api?key=api-key",
	} {
		for _, includeHeader := range []bool{false, true} {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			req.Header.Set("Authorization", auth)
			if includeHeader {
				req.Header.Set("X-API-Key", "api-key")
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), "Invalid or missing API key") {
				t.Fatalf("target=%s header=%t response=%d %s", target, includeHeader, recorder.Code, recorder.Body.String())
			}
		}
	}
	for _, target := range []string{
		"/v1/tenants",
		"/v1/tenants/id/bereia",
		"/v1/tenants/bereia/roles",
		"/v1/tenants/bereia/clients",
		"/v1/tenants/bereia/clients/code-admin-api",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("X-API-Key", "api-key")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), "missing authentication") {
			t.Fatalf("header-only request did not pass API-key middleware: target=%s response=%d %s", target, recorder.Code, recorder.Body.String())
		}
	}
}
