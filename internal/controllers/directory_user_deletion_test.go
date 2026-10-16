package controllers

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type deletionHTTPService struct {
	services.IdentityDirectoryService
	calls   int
	err     error
	userID  string
	version int64
	actor   domain.DirectoryDeletionActor
}

func (s *deletionHTTPService) DeleteDirectoryUser(_ context.Context, id string, version int64, actor domain.DirectoryDeletionActor) (bool, error) {
	s.calls++
	s.userID = id
	s.version = version
	s.actor = actor
	return s.err == nil, s.err
}

type deletionHTTPAuthority struct {
	services.UserService
	err error
}

func (s deletionHTTPAuthority) CurrentDirectoryDeletionActor(context.Context, string, string, string) (domain.DirectoryDeletionActor, error) {
	return domain.DirectoryDeletionActor{UserID: "platform-admin", TokenVersion: 2, Revision: 4}, s.err
}

func TestDirectoryUserDeletionHTTPContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	cfg.ApiKey = "service-key"
	platform := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{"sub": "platform-admin", "role": "ADMIN", "scope": platformTenantAdminScope, domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin})
	tenant := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{"sub": "tenant-admin", "role": "COMPANY_ADMIN", "scope": tenantIdentityWriteScope, "tid": "conveste"})
	for _, tc := range []struct {
		name, path, body, auth, apiKey, condition string
		upstream                                  error
		authority                                 error
		want, calls                               int
	}{
		{name: "deleted", path: "/users/target-user", auth: platform, apiKey: "service-key", condition: `"1"`, want: 204, calls: 1},
		{name: "missing key", path: "/users/target-user", auth: platform, condition: `"1"`, want: 401},
		{name: "missing bearer", path: "/users/target-user", apiKey: "service-key", condition: `"1"`, want: 401},
		{name: "tenant administrator", path: "/users/target-user", auth: tenant, apiKey: "service-key", condition: `"1"`, want: 403},
		{name: "self deletion", path: "/users/platform-admin", auth: platform, apiKey: "service-key", condition: `"1"`, want: 403},
		{name: "missing condition", path: "/users/target-user", auth: platform, apiKey: "service-key", want: 400},
		{name: "wildcard condition", path: "/users/target-user", auth: platform, apiKey: "service-key", condition: "*", want: 400},
		{name: "weak condition", path: "/users/target-user", auth: platform, apiKey: "service-key", condition: `W/"1"`, want: 400},
		{name: "unquoted condition", path: "/users/target-user", auth: platform, apiKey: "service-key", condition: "1", want: 400},
		{name: "zero condition", path: "/users/target-user", auth: platform, apiKey: "service-key", condition: `"0"`, want: 400},
		{name: "leading zero condition", path: "/users/target-user", auth: platform, apiKey: "service-key", condition: `"01"`, want: 400},
		{name: "multiple condition", path: "/users/target-user", auth: platform, apiKey: "service-key", condition: `"1","2"`, want: 400},
		{name: "request body", path: "/users/target-user", auth: platform, apiKey: "service-key", condition: `"1"`, body: `{}`, want: 400},
		{name: "query", path: "/users/target-user?preview=true", auth: platform, apiKey: "service-key", condition: `"1"`, want: 400},
		{name: "empty query", path: "/users/target-user?", auth: platform, apiKey: "service-key", condition: `"1"`, want: 400},
		{name: "stale", path: "/users/target-user", auth: platform, apiKey: "service-key", condition: `"1"`, upstream: domain.ErrVersionConflict, want: 412, calls: 1},
		{name: "current actor denied", path: "/users/target-user", auth: platform, apiKey: "service-key", condition: `"1"`, authority: domain.ErrDirectoryDeletionDenied, want: 403},
		{name: "storage unavailable", path: "/users/target-user", auth: platform, apiKey: "service-key", condition: `"1"`, upstream: errors.New("private storage details"), want: 500, calls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &deletionHTTPService{err: tc.upstream}
			authority := deletionHTTPAuthority{err: tc.authority}
			controller := NewIdentityDirectoryController(service, cfg, authority)
			router := gin.New()
			router.DELETE("/users/:userId", utils.RequiredApiKeyHeader(cfg.ApiKey), controller.DeleteUser)
			response := performIdentityRequest(t, router, http.MethodDelete, tc.path, tc.body, tc.auth, tc.apiKey, tc.condition)
			if response.Code != tc.want || service.calls != tc.calls {
				t.Fatalf("status=%d calls=%d want=%d/%d body=%s", response.Code, service.calls, tc.want, tc.calls, response.Body.String())
			}
			if tc.calls == 1 && (service.userID != "target-user" || service.version != 1 || service.actor.UserID != "platform-admin" || service.actor.Revision != 4) {
				t.Fatalf("bound deletion=%#v", service)
			}
			if tc.want == 204 && response.Body.Len() != 0 {
				t.Fatal("204 has response body")
			}
		})
	}
}

func TestDirectoryUserDeletionNoSignatureOnlyFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	token := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{"sub": "platform-admin", "role": "ADMIN", "scope": platformTenantAdminScope, domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin})
	service := &deletionHTTPService{}
	router := gin.New()
	router.DELETE("/users/:userId", NewIdentityDirectoryController(service, cfg).DeleteUser)
	response := performIdentityRequest(t, router, http.MethodDelete, "/users/target-user", "", token, "", `"1"`)
	if response.Code != 500 || service.calls != 0 {
		t.Fatalf("signature fallback=%d calls=%d", response.Code, service.calls)
	}
}
