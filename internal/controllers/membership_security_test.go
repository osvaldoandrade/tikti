package controllers

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestLegacyMembershipControllerEnforcesTenantAuthority(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	cfg.JwtSecret = "legacy-secret"

	type calls struct{ list, create, remove int }
	serviceCalls := &calls{}
	svc := &fakeMembershipService{
		listFn: func(_ context.Context, tenantID string, _ uint64, _ int64) (*domain.TenantUsersPage, error) {
			serviceCalls.list++
			return &domain.TenantUsersPage{Users: []domain.TenantUserResp{{Id: tenantID + "-user-1"}}}, nil
		},
		createFn: func(_ context.Context, tenantID string, req domain.MembershipCreateReq) (*domain.MembershipResp, error) {
			serviceCalls.create++
			return &domain.MembershipResp{TenantId: tenantID, Email: req.Email}, nil
		},
		removeFn: func(_ context.Context, tenantID string, req domain.MembershipRemoveReq) (*domain.MembershipRemoveResp, error) {
			serviceCalls.remove++
			return &domain.MembershipRemoveResp{TenantId: tenantID, Email: req.Email}, nil
		},
	}
	controller := NewMembershipController(svc, cfg)
	router := gin.New()
	router.GET("/tenants/:tenantId/users", controller.List)
	router.POST("/tenants/:tenantId/users", controller.Create)
	router.POST("/tenants/:tenantId/users/remove", controller.Remove)

	bearer := func(claims jwt.MapClaims) string {
		return "Bearer " + signRoleAccessToken(t, key, claims)
	}
	platform := bearer(jwt.MapClaims{
		"sub": "platform-operator", "scope": platformTenantAdminScope, "tid": "home",
		"role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	platformWithoutProvenance := bearer(jwt.MapClaims{
		"sub": "platform-operator", "scope": platformTenantAdminScope, "tid": "home", "role": string(domain.RoleAdmin),
	})
	localRead := bearer(jwt.MapClaims{
		"sub": "tenant-operator", "scope": tenantIdentityReadScope, "tid": "bereia",
	})
	localWrite := bearer(jwt.MapClaims{
		"sub": "tenant-operator", "scope": tenantIdentityWriteScope, "tid": "bereia",
	})
	foreignWrite := bearer(jwt.MapClaims{
		"sub": "tenant-operator", "scope": tenantIdentityWriteScope, "tid": "storifly", "role": string(domain.RoleAdmin),
	})
	hsToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "legacy-admin", "role": string(domain.RoleAdmin), "tid": "bereia", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(cfg.JwtSecret))
	if err != nil {
		t.Fatalf("sign legacy token: %v", err)
	}

	tests := []struct {
		name, method, path, auth string
		body                     any
		want                     int
		wantCalls                calls
	}{
		{name: "platform read", method: http.MethodGet, path: "/tenants/bereia/users", auth: platform, want: http.StatusOK, wantCalls: calls{list: 1}},
		{name: "platform write", method: http.MethodPost, path: "/tenants/bereia/users", auth: platform, body: domain.MembershipCreateReq{Email: "u@example.com"}, want: http.StatusOK, wantCalls: calls{create: 1}},
		{name: "local read", method: http.MethodGet, path: "/tenants/bereia/users", auth: localRead, want: http.StatusOK, wantCalls: calls{list: 1}},
		{name: "local write implies read", method: http.MethodGet, path: "/tenants/bereia/users", auth: localWrite, want: http.StatusOK, wantCalls: calls{list: 1}},
		{name: "local create", method: http.MethodPost, path: "/tenants/bereia/users", auth: localWrite, body: domain.MembershipCreateReq{Email: "u@example.com"}, want: http.StatusOK, wantCalls: calls{create: 1}},
		{name: "local remove", method: http.MethodPost, path: "/tenants/bereia/users/remove", auth: localWrite, body: domain.MembershipRemoveReq{Email: "u@example.com"}, want: http.StatusOK, wantCalls: calls{remove: 1}},
		{name: "read cannot write", method: http.MethodPost, path: "/tenants/bereia/users", auth: localRead, body: domain.MembershipCreateReq{Email: "u@example.com"}, want: http.StatusForbidden},
		{name: "foreign tenant read", method: http.MethodGet, path: "/tenants/bereia/users", auth: foreignWrite, want: http.StatusForbidden},
		{name: "foreign tenant create", method: http.MethodPost, path: "/tenants/bereia/users", auth: foreignWrite, body: domain.MembershipCreateReq{Email: "u@example.com"}, want: http.StatusForbidden},
		{name: "foreign tenant remove", method: http.MethodPost, path: "/tenants/bereia/users/remove", auth: foreignWrite, body: domain.MembershipRemoveReq{Email: "u@example.com"}, want: http.StatusForbidden},
		{name: "platform scope without provenance", method: http.MethodGet, path: "/tenants/bereia/users", auth: platformWithoutProvenance, want: http.StatusForbidden},
		{name: "legacy role token", method: http.MethodGet, path: "/tenants/bereia/users", auth: "Bearer " + hsToken, want: http.StatusUnauthorized},
		{name: "raw token", method: http.MethodGet, path: "/tenants/bereia/users", auth: strings.TrimPrefix(localRead, "Bearer "), want: http.StatusUnauthorized},
		{name: "missing bearer", method: http.MethodGet, path: "/tenants/bereia/users", want: http.StatusUnauthorized},
		{name: "invalid tenant", method: http.MethodGet, path: "/tenants/Bereia/users", auth: platform, want: http.StatusBadRequest},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			*serviceCalls = calls{}
			recorder := performJSON(t, router, test.method, test.path, test.body, test.auth)
			if recorder.Code != test.want {
				t.Fatalf("response = %d %s, want %d", recorder.Code, recorder.Body.String(), test.want)
			}
			if *serviceCalls != test.wantCalls {
				t.Fatalf("service calls = %+v, want %+v", *serviceCalls, test.wantCalls)
			}
		})
	}
}
