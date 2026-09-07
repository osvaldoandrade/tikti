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

func TestUserAdminController_Handle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	cfg.JwtSecret = "s1"
	svc := &fakeUserService{}
	ctrl := NewUserAdminController(svc, cfg)
	r := gin.New()
	r.POST("/status", ctrl.SetStatus)
	r.POST("/revoke", ctrl.Revoke)

	admin := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{
		"sub": "platform-admin", "role": string(domain.RoleAdmin), "scope": platformTenantAdminScope, "tid": "home",
		domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})

	rec := performJSON(t, r, http.MethodPost, "/status", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status bad req: expected 400, got %d", rec.Code)
	}
	svc.setStatusFn = func(ctx context.Context, email string, status string) (*domain.StatusResp, error) {
		return nil, domain.ErrInvalidArgument
	}
	rec = performJSON(t, r, http.MethodPost, "/status", map[string]any{"email": "u@x.com", "status": "ACTIVE"}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status invalid arg: expected 400, got %d", rec.Code)
	}
	svc.setStatusFn = func(ctx context.Context, email string, status string) (*domain.StatusResp, error) {
		return nil, domain.ErrNotFound
	}
	rec = performJSON(t, r, http.MethodPost, "/status", map[string]any{"email": "u@x.com", "status": "ACTIVE"}, admin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status not found: expected 404, got %d", rec.Code)
	}
	svc.setStatusFn = func(ctx context.Context, email string, status string) (*domain.StatusResp, error) {
		return nil, errors.New("x")
	}
	rec = performJSON(t, r, http.MethodPost, "/status", map[string]any{"email": "u@x.com", "status": "ACTIVE"}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status default err: expected 400, got %d", rec.Code)
	}
	svc.setStatusFn = func(ctx context.Context, email string, status string) (*domain.StatusResp, error) {
		return &domain.StatusResp{Email: email, Status: status}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/status", map[string]any{"email": "u@x.com", "status": "ACTIVE"}, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("status ok: expected 200, got %d", rec.Code)
	}

	rec = performJSON(t, r, http.MethodPost, "/revoke", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("revoke bad req: expected 400, got %d", rec.Code)
	}
	svc.revokeTokensFn = func(ctx context.Context, email, tenantID, scope string) (*domain.RevokeResp, error) {
		return nil, domain.ErrInvalidArgument
	}
	rec = performJSON(t, r, http.MethodPost, "/revoke", map[string]any{"email": "u@x.com"}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("revoke invalid arg: expected 400, got %d", rec.Code)
	}
	svc.revokeTokensFn = func(ctx context.Context, email, tenantID, scope string) (*domain.RevokeResp, error) {
		return nil, domain.ErrNotFound
	}
	rec = performJSON(t, r, http.MethodPost, "/revoke", map[string]any{"email": "u@x.com"}, admin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoke not found: expected 404, got %d", rec.Code)
	}
	svc.revokeTokensFn = func(ctx context.Context, email, tenantID, scope string) (*domain.RevokeResp, error) {
		return nil, errors.New("x")
	}
	rec = performJSON(t, r, http.MethodPost, "/revoke", map[string]any{"email": "u@x.com"}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("revoke default err: expected 400, got %d", rec.Code)
	}
	svc.revokeTokensFn = func(ctx context.Context, email, tenantID, scope string) (*domain.RevokeResp, error) {
		return &domain.RevokeResp{Email: email}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/revoke", map[string]any{"email": "u@x.com"}, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke ok: expected 200, got %d", rec.Code)
	}
}

func TestUserAdminController_RevokeRejectsUnsupportedTenantScopeBeforeService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	cfg.JwtSecret = "s1"
	svc := &fakeUserService{}
	ctrl := NewUserAdminController(svc, cfg)
	r := gin.New()
	r.POST("/revoke", ctrl.Revoke)

	admin := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{
		"sub": "platform-admin", "role": string(domain.RoleAdmin), "scope": platformTenantAdminScope, "tid": "home",
		domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})

	captured := struct {
		email    string
		tenantID string
		scope    string
	}{}
	svc.revokeTokensFn = func(ctx context.Context, email, tenantID, scope string) (*domain.RevokeResp, error) {
		captured.email = email
		captured.tenantID = tenantID
		captured.scope = scope
		return &domain.RevokeResp{Email: email, TokenVersion: 1}, nil
	}

	for _, body := range []map[string]any{
		{"email": "u@x.com", "tenantId": "tenant-1", "scope": "tenant"},
		{"email": "u@x.com", "tenantId": "tenant-1", "scope": "global"},
		{"email": "u@x.com", "scope": "tenant"},
	} {
		rec := performJSON(t, r, http.MethodPost, "/revoke", body, admin)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "only global token revocation is supported") {
			t.Fatalf("unsupported tenant revocation response = %d %s", rec.Code, rec.Body.String())
		}
		if captured.email != "" || captured.tenantID != "" || captured.scope != "" {
			t.Fatalf("service called for unsupported tenant revocation: %+v", captured)
		}
	}

	for _, body := range []string{
		`{"email":"u@x.com","tenant_id":"tenant-1"}`,
		`{"email":"u@x.com","tenantId":"tenant-1","tenantId":""}`,
		`{"email":"u@x.com"}{"scope":"global"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(body))
		req.Header.Set("Authorization", admin)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("ambiguous global revocation payload %s: expected 400, got %d %s", body, rec.Code, rec.Body.String())
		}
		if captured.email != "" || captured.tenantID != "" || captured.scope != "" {
			t.Fatalf("service called for ambiguous global revocation payload %s: %+v", body, captured)
		}
	}

	rec := performJSON(t, r, http.MethodPost, "/revoke", map[string]any{"email": "u@x.com", "scope": "global"}, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for global revocation, got %d", rec.Code)
	}
	if captured.email != "u@x.com" || captured.tenantID != "" || captured.scope != "global" {
		t.Fatalf("revoke payload forwarding mismatch: %+v", captured)
	}
}

func TestAdminMutationsRejectUnscopedAuthorityBeforeService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	cfg.JwtSecret = "legacy-secret"
	calls := map[string]int{}
	userSvc := &fakeUserService{
		signUpFn: func(context.Context, domain.SignUpReq) (*domain.SignUpResp, error) {
			calls["signup"]++
			return &domain.SignUpResp{LocalId: "user-1", Email: "u@example.com"}, nil
		},
		setStatusFn: func(context.Context, string, string) (*domain.StatusResp, error) {
			calls["status"]++
			return &domain.StatusResp{LocalId: "user-1", Email: "u@example.com", Status: "ACTIVE"}, nil
		},
		revokeTokensFn: func(context.Context, string, string, string) (*domain.RevokeResp, error) {
			calls["revoke"]++
			return &domain.RevokeResp{LocalId: "user-1", Email: "u@example.com", TokenVersion: 2}, nil
		},
		validateAccessTokenFn: func(context.Context, string, string, string) (jwt.MapClaims, error) {
			calls["validate"]++
			return jwt.MapClaims{"sub": "user-1"}, nil
		},
	}
	clientSvc := &fakeClientService{createFn: func(context.Context, string, domain.ClientCreateReq) (*domain.ClientResp, error) {
		calls["client"]++
		return &domain.ClientResp{ClientId: "client-1"}, nil
	}}

	router := gin.New()
	router.POST("/signup", NewSignUpController(userSvc, cfg).Handle)
	adminUser := NewUserAdminController(userSvc, cfg)
	router.POST("/status", adminUser.SetStatus)
	router.POST("/revoke", adminUser.Revoke)
	router.POST("/validate", NewValidateController(userSvc, cfg).Handle)
	router.POST("/tenants/:tenantId/clients", NewClientController(clientSvc, cfg).Create)

	bearer := func(claims jwt.MapClaims) string {
		return "Bearer " + signRoleAccessToken(t, key, claims)
	}
	localAdmin := bearer(jwt.MapClaims{
		"sub": "tenant-admin", "role": string(domain.RoleAdmin), "scope": tenantIdentityWriteScope, "tid": "bereia",
	})
	foreignAdmin := bearer(jwt.MapClaims{
		"sub": "tenant-admin", "role": string(domain.RoleAdmin), "scope": tenantIdentityWriteScope, "tid": "storifly",
	})
	platformWithoutProvenance := bearer(jwt.MapClaims{
		"sub": "platform-admin", "role": string(domain.RoleAdmin), "scope": platformTenantAdminScope, "tid": "home",
	})
	platformToken := strings.TrimPrefix(bearer(jwt.MapClaims{
		"sub": "platform-admin", "role": string(domain.RoleAdmin), "scope": platformTenantAdminScope, "tid": "home",
		domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	}), "Bearer ")
	legacyAdmin := "Bearer " + adminToken(t, cfg.JwtSecret, "ADMIN")

	tests := []struct {
		name, path, authorization, call string
		body                            any
		want                            int
	}{
		{name: "signup tenant admin", path: "/signup", authorization: localAdmin, call: "signup", body: domain.SignUpReq{Email: "u@example.com", Password: "password"}, want: http.StatusForbidden},
		{name: "status legacy HS256", path: "/status", authorization: legacyAdmin, call: "status", body: map[string]any{"email": "u@example.com", "status": "ACTIVE"}, want: http.StatusUnauthorized},
		{name: "status raw platform token", path: "/status", authorization: platformToken, call: "status", body: map[string]any{"email": "u@example.com", "status": "ACTIVE"}, want: http.StatusUnauthorized},
		{name: "revoke tenant admin", path: "/revoke", authorization: localAdmin, call: "revoke", body: map[string]any{"email": "u@example.com", "scope": "global"}, want: http.StatusForbidden},
		{name: "validate platform without provenance", path: "/validate", authorization: platformWithoutProvenance, call: "validate", body: map[string]any{"token": "candidate", "audience": "workload"}, want: http.StatusForbidden},
		{name: "client create foreign tenant", path: "/tenants/bereia/clients", authorization: foreignAdmin, call: "client", body: domain.ClientCreateReq{ClientId: "client-1"}, want: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := calls[test.call]
			response := performJSON(t, router, http.MethodPost, test.path, test.body, test.authorization)
			if response.Code != test.want || calls[test.call] != before {
				t.Fatalf("status=%d want=%d serviceCalls=%d want=%d body=%s", response.Code, test.want, calls[test.call], before, response.Body.String())
			}
		})
	}
}

func TestTenantMembershipRoleClientControllers_Handle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	cfg.JwtSecret = "s1"
	admin := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{
		"sub": "platform-operator", "scope": platformTenantAdminScope, "tid": "home",
		"role": string(domain.RoleAdmin), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})

	tenantSvc := &fakeTenantService{}
	memberSvc := &fakeMembershipService{}
	roleSvc := &fakeRoleService{}
	clientSvc := &fakeClientService{}

	tenantCtrl := NewTenantController(tenantSvc, cfg)
	memberCtrl := NewMembershipController(memberSvc, cfg)
	roleCtrl := NewRoleController(roleSvc, cfg)
	clientCtrl := NewClientController(clientSvc, cfg)

	r := gin.New()
	r.PUT("/tenants/:tenantId", tenantCtrl.CreateWithID)
	r.GET("/tenants", tenantCtrl.List)
	r.GET("/tenants/:tenantId", tenantCtrl.Get)
	r.GET("/tenants/:tenantId/users", memberCtrl.List)
	r.POST("/tenants/:tenantId/users", memberCtrl.Create)
	r.POST("/tenants/:tenantId/users/remove", memberCtrl.Remove)
	r.PUT("/tenants/:tenantId/roles/:roleName", roleCtrl.Put)
	r.GET("/tenants/:tenantId/roles", roleCtrl.ListAdmin)
	r.POST("/tenants/:tenantId/clients", clientCtrl.Create)
	r.GET("/tenants/:tenantId/clients/:clientId", clientCtrl.Get)
	r.GET("/tenants/:tenantId/clients", clientCtrl.List)

	rec := performJSON(t, r, http.MethodPut, "/tenants/t1", nil, admin)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("tenant create missing media type: expected 415, got %d", rec.Code)
	}
	tenantSvc.createWithIDFn = func(ctx context.Context, tenantID string, req domain.TenantCreateReq) (*domain.TenantResp, bool, error) {
		return nil, false, domain.ErrInvalidArgument
	}
	rec = performJSON(t, r, http.MethodPut, "/tenants/t1", domain.TenantCreateReq{Name: "n", Slug: "s"}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tenant create err: expected 400, got %d", rec.Code)
	}
	tenantSvc.createWithIDFn = func(ctx context.Context, tenantID string, req domain.TenantCreateReq) (*domain.TenantResp, bool, error) {
		return &domain.TenantResp{Id: tenantID}, true, nil
	}
	rec = performJSON(t, r, http.MethodPut, "/tenants/t1", domain.TenantCreateReq{Name: "n", Slug: "s"}, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("tenant create ok: expected 201, got %d", rec.Code)
	}

	rec = performJSON(t, r, http.MethodGet, "/tenants?pageSize=0", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tenant list invalid page size: expected 400, got %d", rec.Code)
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants?pageToken=invalid", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tenant list invalid page token: expected 400, got %d", rec.Code)
	}
	tenantSvc.listFn = func(_ context.Context, offset uint64, pageSize int64) (*domain.TenantsPage, error) {
		if offset != 7 || pageSize != 20 {
			t.Fatalf("unexpected tenant list request: offset=%d pageSize=%d", offset, pageSize)
		}
		return &domain.TenantsPage{Tenants: []domain.TenantResp{{Id: "t1", Status: domain.TenantStatusActive}}}, nil
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants?pageSize=20&pageToken=7", nil, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant list: expected 200, got %d", rec.Code)
	}

	memberSvc.listFn = func(_ context.Context, tenantID string, cursor uint64, pageSize int64) (*domain.TenantUsersPage, error) {
		if tenantID != "t1" || cursor != 7 || pageSize != 20 {
			t.Fatalf("unexpected membership list request: tenant=%s cursor=%d pageSize=%d", tenantID, cursor, pageSize)
		}
		return &domain.TenantUsersPage{Users: []domain.TenantUserResp{{Id: "u1", Email: "u@example.com"}}}, nil
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1/users?pageSize=20&pageToken=7", nil, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("membership list: expected 200, got %d", rec.Code)
	}

	tenantSvc.getFn = func(ctx context.Context, tenantID string) (*domain.TenantResp, error) { return nil, domain.ErrNotFound }
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1", nil, admin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("tenant get not found: expected 404, got %d", rec.Code)
	}
	tenantSvc.getFn = func(ctx context.Context, tenantID string) (*domain.TenantResp, error) {
		return nil, domain.ErrInvalidArgument
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tenant get bad req: expected 400, got %d", rec.Code)
	}
	tenantSvc.getFn = func(ctx context.Context, tenantID string) (*domain.TenantResp, error) {
		return nil, errors.New("tenant-get-fail")
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tenant get default err: expected 400, got %d", rec.Code)
	}
	tenantSvc.getFn = func(ctx context.Context, tenantID string) (*domain.TenantResp, error) {
		return &domain.TenantResp{Id: tenantID}, nil
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1", nil, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant get ok: expected 200, got %d", rec.Code)
	}

	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/users", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("membership create bad req: expected 400, got %d", rec.Code)
	}
	memberSvc.createFn = func(ctx context.Context, tenantID string, req domain.MembershipCreateReq) (*domain.MembershipResp, error) {
		return nil, domain.ErrInvalidTenant
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/users", domain.MembershipCreateReq{Email: "u@x.com"}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("membership create err: expected 400, got %d", rec.Code)
	}
	memberSvc.createFn = func(ctx context.Context, tenantID string, req domain.MembershipCreateReq) (*domain.MembershipResp, error) {
		return nil, domain.ErrNotFound
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/users", domain.MembershipCreateReq{Email: "u@x.com"}, admin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("membership create not found: expected 404, got %d", rec.Code)
	}
	memberSvc.createFn = func(ctx context.Context, tenantID string, req domain.MembershipCreateReq) (*domain.MembershipResp, error) {
		return &domain.MembershipResp{TenantId: tenantID, Email: req.Email}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/users", domain.MembershipCreateReq{Email: "u@x.com"}, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("membership create ok: expected 200, got %d", rec.Code)
	}

	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/users/remove", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("membership remove bad req: expected 400, got %d", rec.Code)
	}
	memberSvc.removeFn = func(ctx context.Context, tenantID string, req domain.MembershipRemoveReq) (*domain.MembershipRemoveResp, error) {
		return nil, domain.ErrInvalidArgument
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/users/remove", domain.MembershipRemoveReq{Email: "u@x.com"}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("membership remove err: expected 400, got %d", rec.Code)
	}
	memberSvc.removeFn = func(ctx context.Context, tenantID string, req domain.MembershipRemoveReq) (*domain.MembershipRemoveResp, error) {
		return nil, domain.ErrNotFound
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/users/remove", domain.MembershipRemoveReq{Email: "u@x.com"}, admin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("membership remove not found: expected 404, got %d", rec.Code)
	}
	memberSvc.removeFn = func(ctx context.Context, tenantID string, req domain.MembershipRemoveReq) (*domain.MembershipRemoveResp, error) {
		return &domain.MembershipRemoveResp{TenantId: tenantID, Email: req.Email}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/users/remove", domain.MembershipRemoveReq{Email: "u@x.com"}, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("membership remove ok: expected 200, got %d", rec.Code)
	}

	rec = performJSON(t, r, http.MethodPut, "/tenants/t1/roles/R1", nil, admin)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("role create missing media type: expected 415, got %d", rec.Code)
	}
	roleSvc.createWithNameFn = func(ctx context.Context, tenantID, roleName string, req domain.RolePutReq) (*domain.RoleResp, bool, error) {
		return nil, false, domain.ErrInvalidTenant
	}
	rec = performJSON(t, r, http.MethodPut, "/tenants/t1/roles/R1", domain.RolePutReq{Permissions: []string{}}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("role create err: expected 400, got %d", rec.Code)
	}
	roleSvc.createWithNameFn = func(ctx context.Context, tenantID, roleName string, req domain.RolePutReq) (*domain.RoleResp, bool, error) {
		return &domain.RoleResp{Name: roleName}, true, nil
	}
	rec = performJSON(t, r, http.MethodPut, "/tenants/t1/roles/R1", domain.RolePutReq{Permissions: []string{}}, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("role create ok: expected 201, got %d", rec.Code)
	}

	roleSvc.listCanonicalFn = func(ctx context.Context, tenantID string) ([]*domain.RoleResp, error) {
		return nil, domain.ErrInvalidTenant
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1/roles", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("role list err: expected 400, got %d", rec.Code)
	}
	roleSvc.listCanonicalFn = func(ctx context.Context, tenantID string) ([]*domain.RoleResp, error) {
		return nil, errors.New("role-list-fail")
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1/roles", nil, admin)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("role list default err: expected 500, got %d", rec.Code)
	}
	roleSvc.listCanonicalFn = func(ctx context.Context, tenantID string) ([]*domain.RoleResp, error) {
		return []*domain.RoleResp{{Name: "R1"}}, nil
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1/roles", nil, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("role list ok: expected 200, got %d", rec.Code)
	}

	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/clients", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("client create bad req: expected 400, got %d", rec.Code)
	}
	clientSvc.createFn = func(ctx context.Context, tenantID string, req domain.ClientCreateReq) (*domain.ClientResp, error) {
		return nil, domain.ErrInvalidTenant
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/clients", domain.ClientCreateReq{ClientId: "c1"}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("client create bad tenant: expected 400, got %d", rec.Code)
	}
	clientSvc.createFn = func(ctx context.Context, tenantID string, req domain.ClientCreateReq) (*domain.ClientResp, error) {
		return nil, domain.ErrNotFound
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/clients", domain.ClientCreateReq{ClientId: "c1"}, admin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("client create not found: expected 404, got %d", rec.Code)
	}
	clientSvc.createFn = func(ctx context.Context, tenantID string, req domain.ClientCreateReq) (*domain.ClientResp, error) {
		return &domain.ClientResp{ClientId: req.ClientId}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/clients", domain.ClientCreateReq{ClientId: "c1"}, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("client create ok: expected 201, got %d", rec.Code)
	}

	clientSvc.getFn = func(ctx context.Context, tenantID string, clientID string) (*domain.ClientResp, error) {
		return nil, domain.ErrInvalidArgument
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1/clients/c1", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("client get bad req: expected 400, got %d", rec.Code)
	}
	clientSvc.getFn = func(ctx context.Context, tenantID string, clientID string) (*domain.ClientResp, error) {
		return nil, domain.ErrNotFound
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1/clients/c1", nil, admin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("client get not found: expected 404, got %d", rec.Code)
	}
	clientSvc.getFn = func(ctx context.Context, tenantID string, clientID string) (*domain.ClientResp, error) {
		return &domain.ClientResp{ClientId: clientID}, nil
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1/clients/c1", nil, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("client get ok: expected 200, got %d", rec.Code)
	}

	clientSvc.listFn = func(ctx context.Context, tenantID string) ([]*domain.ClientResp, error) {
		return nil, domain.ErrInvalidTenant
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1/clients", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("client list bad req: expected 400, got %d", rec.Code)
	}
	clientSvc.listFn = func(ctx context.Context, tenantID string) ([]*domain.ClientResp, error) {
		return nil, errors.New("client-list-fail")
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1/clients", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("client list default err: expected 400, got %d", rec.Code)
	}
	clientSvc.listFn = func(ctx context.Context, tenantID string) ([]*domain.ClientResp, error) {
		return []*domain.ClientResp{{ClientId: "c1"}}, nil
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1/clients", nil, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("client list ok: expected 200, got %d", rec.Code)
	}
}
