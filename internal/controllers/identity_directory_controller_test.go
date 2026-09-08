package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type identityDirectoryHTTPStub struct {
	services.IdentityDirectoryService
	createInput     domain.DirectoryUserCreateReq
	findInput       string
	listInput       string
	tenantListInput string
	globalListCalls int
	changeErr       error
	putETag         string
	putTenant       string
}

func (s *identityDirectoryHTTPStub) ChangeTemporaryPassword(_ context.Context, _ domain.TemporaryPasswordChangeReq) error {
	return s.changeErr
}

func (s *identityDirectoryHTTPStub) CreateUser(_ context.Context, input domain.DirectoryUserCreateReq) (*domain.DirectoryUser, error) {
	s.createInput = input
	return &domain.DirectoryUser{ID: "user-1", Email: strings.ToLower(input.Email), Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, PasswordChangeRequired: true, CreatedAt: time.Now()}, nil
}
func (s *identityDirectoryHTTPStub) FindUserByEmail(_ context.Context, email string) (*domain.DirectoryUser, error) {
	s.findInput = email
	userID := "user-1"
	if email == "external@example.com" {
		userID = "user-2"
	}
	return &domain.DirectoryUser{ID: userID, Email: email, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now()}, nil
}
func (s *identityDirectoryHTTPStub) ListUsers(_ context.Context, query, _ string, _ int) (*domain.DirectoryUserPage, error) {
	s.globalListCalls++
	s.listInput = query
	return &domain.DirectoryUserPage{Users: []domain.DirectoryUser{
		{ID: "user-1", Email: "user@example.com", Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now()},
		{ID: "user-2", Email: "external@example.com", Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now()},
	}}, nil
}
func (s *identityDirectoryHTTPStub) ListTenantUsers(_ context.Context, tenantID, query, _ string, _ int) (*domain.DirectoryUserPage, error) {
	s.tenantListInput = tenantID + ":" + query
	return &domain.DirectoryUserPage{Users: []domain.DirectoryUser{
		{ID: "user-1", Email: "user@example.com", Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now()},
	}}, nil
}
func (s *identityDirectoryHTTPStub) GetEffectiveTenantRoles(_ context.Context, userID, tenantID string) ([]string, []domain.AccessProvenance, error) {
	if userID == "user-1" && tenantID == "bereia" {
		return []string{"reader"}, nil, nil
	}
	return nil, nil, nil
}
func (s *identityDirectoryHTTPStub) PutAssignment(_ context.Context, tenantID string, kind domain.AccessPrincipalType, principalID string, roles []string, etag string) (*domain.AccessAssignment, bool, error) {
	s.putETag, s.putTenant = etag, tenantID
	return &domain.AccessAssignment{TenantID: tenantID, PrincipalType: kind, PrincipalID: principalID, Roles: roles, Version: 2, CreatedAt: time.Now(), UpdatedAt: time.Now()}, false, nil
}

func TestIdentityDirectoryControllerNoLeakExactResolutionAndTenantIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	cfg.ApiKey = "service-key"
	stub := &identityDirectoryHTTPStub{}
	controller := NewIdentityDirectoryController(stub, cfg)
	router := gin.New()
	admin := router.Group("/admin", func(c *gin.Context) {
		if c.GetHeader("X-API-Key") != cfg.ApiKey {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	})
	admin.POST("/users", controller.CreateUser)
	admin.GET("/users", controller.ListUsers)
	admin.PUT("/tenants/:tenantId/users/:userId", controller.PutUserAssignment)

	platform := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{
		"sub": "platform-admin", "role": string(domain.RoleAdmin), "scope": platformTenantAdminScope,
		"tid": "local-tenant", domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	missingSubject := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{
		"role": string(domain.RoleAdmin), "scope": platformTenantAdminScope,
		"tid": "local-tenant", domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	deniedSubjectlessRead := performIdentityRequest(t, router, http.MethodGet, "/admin/users", "", missingSubject, "service-key", "")
	if deniedSubjectlessRead.Code != http.StatusForbidden || stub.globalListCalls != 0 {
		t.Fatalf("subjectless platform read = %d globalCalls=%d", deniedSubjectlessRead.Code, stub.globalListCalls)
	}
	body := `{"email":"New@Example.com","temporaryPassword":"one-time-secret"}`
	created := performIdentityRequest(t, router, http.MethodPost, "/admin/users", body, platform, "service-key", "")
	if created.Code != http.StatusCreated || strings.Contains(created.Body.String(), "one-time-secret") || stub.createInput.TemporaryPassword != "one-time-secret" {
		t.Fatalf("create = %d %s input=%#v", created.Code, created.Body.String(), stub.createInput)
	}

	workload := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{
		"sub": "tenant-admin", "role": string(domain.RoleCompanyAdmin), "scope": tenantIdentityReadScope + " " + tenantIdentityWriteScope, "tid": "bereia",
	})
	prefix := performIdentityRequest(t, router, http.MethodGet, "/admin/users?query=user@", "", workload, "service-key", "")
	if prefix.Code != http.StatusOK || stub.tenantListInput != "bereia:user@" || stub.globalListCalls != 0 ||
		!strings.Contains(prefix.Body.String(), "user-1") || strings.Contains(prefix.Body.String(), "user-2") {
		t.Fatalf("tenant-filtered prefix = %d %s tenantInput=%q globalCalls=%d", prefix.Code, prefix.Body.String(), stub.tenantListInput, stub.globalListCalls)
	}
	exact := performIdentityRequest(t, router, http.MethodGet, "/admin/users?query=User%40Example.com", "", workload, "service-key", "")
	if exact.Code != http.StatusOK || stub.findInput != "user@example.com" || !strings.Contains(exact.Body.String(), "user-1") {
		t.Fatalf("exact = %d %s input=%q", exact.Code, exact.Body.String(), stub.findInput)
	}
	external := performIdentityRequest(t, router, http.MethodGet, "/admin/users?query=external%40example.com", "", workload, "service-key", "")
	if external.Code != http.StatusOK || stub.findInput != "external@example.com" || !strings.Contains(external.Body.String(), "user-2") {
		t.Fatalf("external exact resolver = %d %s input=%q", external.Code, external.Body.String(), stub.findInput)
	}
	malformedVersion := performIdentityRequest(t, router, http.MethodPut, "/admin/tenants/bereia/users/user-1", `{"roles":["reader"]}`, workload, "service-key", `W/"1"`)
	if malformedVersion.Code != http.StatusBadRequest || stub.putTenant != "" {
		t.Fatalf("malformed If-Match = %d tenant=%q", malformedVersion.Code, stub.putTenant)
	}
	foreign := performIdentityRequest(t, router, http.MethodPut, "/admin/tenants/storifly/users/user-1", `{"roles":["reader"]}`, workload, "service-key", `"1"`)
	if foreign.Code != http.StatusForbidden || stub.putTenant != "" {
		t.Fatalf("foreign = %d tenant=%q", foreign.Code, stub.putTenant)
	}
}

func TestIdentityDirectoryControllerReturnsStandardRateLimitResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stub := &identityDirectoryHTTPStub{changeErr: domain.ErrRateLimited}
	router := gin.New()
	router.POST("/change", NewIdentityDirectoryController(stub, &config.Config{}).ChangeTemporaryPassword)
	response := performIdentityRequest(
		t, router, http.MethodPost, "/change",
		`{"email":"user@example.com","temporaryPassword":"temporary-1234","newPassword":"permanent-1234"}`,
		"", "", "",
	)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "60" ||
		!strings.Contains(response.Body.String(), "too many attempts") {
		t.Fatalf("rate limit = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func performIdentityRequest(t *testing.T, router http.Handler, method, path, body, authorization, apiKey, ifMatch string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", authorization)
	request.Header.Set("X-API-Key", apiKey)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}
