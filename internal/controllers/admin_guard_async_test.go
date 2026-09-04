package controllers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestRequirePlatformTenantAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	cfg.JwtSecret = "legacy-secret"
	bearer := func(claims jwt.MapClaims) string { return "Bearer " + signRoleAccessToken(t, key, claims) }
	valid := bearer(jwt.MapClaims{
		"sub": "platform-admin", "role": string(domain.RoleAdmin), "scope": platformTenantAdminScope, "tid": "home",
		domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	tests := []struct {
		name, authorization string
		wantOK              bool
		wantStatus          int
	}{
		{name: "missing", wantStatus: http.StatusUnauthorized},
		{name: "legacy HS256", authorization: "Bearer " + adminToken(t, cfg.JwtSecret, "ADMIN"), wantStatus: http.StatusUnauthorized},
		{name: "tenant admin", authorization: bearer(jwt.MapClaims{"sub": "tenant-admin", "role": string(domain.RoleAdmin), "scope": tenantIdentityWriteScope, "tid": "bereia"}), wantStatus: http.StatusForbidden},
		{name: "platform scope without provenance", authorization: bearer(jwt.MapClaims{"sub": "platform-admin", "role": string(domain.RoleAdmin), "scope": platformTenantAdminScope, "tid": "home"}), wantStatus: http.StatusForbidden},
		{name: "raw token", authorization: valid[len("Bearer "):], wantStatus: http.StatusUnauthorized},
		{name: "provenance bound platform", authorization: valid, wantOK: true, wantStatus: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("Authorization", test.authorization)
			ctx.Request = request
			_, ok := requirePlatformTenantAdmin(ctx, cfg)
			if ok != test.wantOK || !test.wantOK && recorder.Code != test.wantStatus {
				t.Fatalf("ok=%v want=%v status=%d want=%d body=%s", ok, test.wantOK, recorder.Code, test.wantStatus, recorder.Body.String())
			}
		})
	}
}

func TestRunCommandAsync(t *testing.T) {
	success := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return "ok", nil
	})
	if got := <-success; got != "ok" {
		t.Fatalf("unexpected result: %#v", got)
	}

	fail := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("boom")
	})
	got := <-fail
	if err, ok := got.(error); !ok || err.Error() != "boom" {
		t.Fatalf("expected boom error, got %#v", got)
	}
}
