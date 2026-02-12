package controllers

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestUserAdminController_Handle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JwtSecret: "s1"}
	svc := &fakeUserService{}
	ctrl := NewUserAdminController(svc, cfg)
	r := gin.New()
	r.POST("/status", ctrl.SetStatus)
	r.POST("/revoke", ctrl.Revoke)

	admin := "Bearer " + adminToken(t, cfg.JwtSecret, "ADMIN")

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

func TestUserAdminController_Revoke_ForwardsTenantAndScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JwtSecret: "s1"}
	svc := &fakeUserService{}
	ctrl := NewUserAdminController(svc, cfg)
	r := gin.New()
	r.POST("/revoke", ctrl.Revoke)

	admin := "Bearer " + adminToken(t, cfg.JwtSecret, "ADMIN")

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

	rec := performJSON(t, r, http.MethodPost, "/revoke", map[string]any{
		"email":    "u@x.com",
		"tenantId": "tenant-1",
		"scope":    "tenant",
	}, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if captured.email != "u@x.com" || captured.tenantID != "tenant-1" || captured.scope != "tenant" {
		t.Fatalf("revoke payload forwarding mismatch: %+v", captured)
	}
}

func TestTenantMembershipRoleClientControllers_Handle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JwtSecret: "s1"}
	admin := "Bearer " + adminToken(t, cfg.JwtSecret, "ADMIN")

	tenantSvc := &fakeTenantService{}
	memberSvc := &fakeMembershipService{}
	roleSvc := &fakeRoleService{}
	clientSvc := &fakeClientService{}

	tenantCtrl := NewTenantController(tenantSvc, cfg)
	memberCtrl := NewMembershipController(memberSvc, cfg)
	roleCtrl := NewRoleController(roleSvc, cfg)
	clientCtrl := NewClientController(clientSvc, cfg)

	r := gin.New()
	r.POST("/tenants", tenantCtrl.Create)
	r.GET("/tenants/id/:id", tenantCtrl.Get)
	r.POST("/tenants/:tenantId/users", memberCtrl.Create)
	r.POST("/tenants/:tenantId/users/remove", memberCtrl.Remove)
	r.POST("/tenants/:tenantId/roles", roleCtrl.Create)
	r.GET("/tenants/:tenantId/roles", roleCtrl.List)
	r.POST("/tenants/:tenantId/clients", clientCtrl.Create)
	r.GET("/tenants/:tenantId/clients/:clientId", clientCtrl.Get)
	r.GET("/tenants/:tenantId/clients", clientCtrl.List)

	rec := performJSON(t, r, http.MethodPost, "/tenants", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tenant create bad req: expected 400, got %d", rec.Code)
	}
	tenantSvc.createFn = func(ctx context.Context, req domain.TenantCreateReq) (*domain.TenantResp, error) {
		return nil, domain.ErrInvalidArgument
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants", domain.TenantCreateReq{Name: "n", Slug: "s"}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tenant create err: expected 400, got %d", rec.Code)
	}
	tenantSvc.createFn = func(ctx context.Context, req domain.TenantCreateReq) (*domain.TenantResp, error) {
		return &domain.TenantResp{Id: "t1"}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants", domain.TenantCreateReq{Name: "n", Slug: "s"}, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant create ok: expected 200, got %d", rec.Code)
	}

	tenantSvc.getFn = func(ctx context.Context, tenantID string) (*domain.TenantResp, error) { return nil, domain.ErrNotFound }
	rec = performJSON(t, r, http.MethodGet, "/tenants/id/t1", nil, admin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("tenant get not found: expected 404, got %d", rec.Code)
	}
	tenantSvc.getFn = func(ctx context.Context, tenantID string) (*domain.TenantResp, error) {
		return nil, domain.ErrInvalidArgument
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/id/t1", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tenant get bad req: expected 400, got %d", rec.Code)
	}
	tenantSvc.getFn = func(ctx context.Context, tenantID string) (*domain.TenantResp, error) {
		return nil, errors.New("tenant-get-fail")
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/id/t1", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tenant get default err: expected 400, got %d", rec.Code)
	}
	tenantSvc.getFn = func(ctx context.Context, tenantID string) (*domain.TenantResp, error) {
		return &domain.TenantResp{Id: tenantID}, nil
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/id/t1", nil, admin)
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

	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/roles", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("role create bad req: expected 400, got %d", rec.Code)
	}
	roleSvc.createFn = func(ctx context.Context, tenantID string, req domain.RoleCreateReq) (*domain.RoleResp, error) {
		return nil, domain.ErrInvalidTenant
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/roles", domain.RoleCreateReq{Name: "R1"}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("role create err: expected 400, got %d", rec.Code)
	}
	roleSvc.createFn = func(ctx context.Context, tenantID string, req domain.RoleCreateReq) (*domain.RoleResp, error) {
		return &domain.RoleResp{Name: req.Name}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/roles", domain.RoleCreateReq{Name: "R1"}, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("role create ok: expected 200, got %d", rec.Code)
	}

	roleSvc.listFn = func(ctx context.Context, tenantID string) ([]*domain.RoleResp, error) {
		return nil, domain.ErrInvalidTenant
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1/roles", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("role list err: expected 400, got %d", rec.Code)
	}
	roleSvc.listFn = func(ctx context.Context, tenantID string) ([]*domain.RoleResp, error) {
		return nil, errors.New("role-list-fail")
	}
	rec = performJSON(t, r, http.MethodGet, "/tenants/t1/roles", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("role list default err: expected 400, got %d", rec.Code)
	}
	roleSvc.listFn = func(ctx context.Context, tenantID string) ([]*domain.RoleResp, error) {
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
	if rec.Code != http.StatusOK {
		t.Fatalf("client create ok: expected 200, got %d", rec.Code)
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
