package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeUserService struct {
	signUpFn              func(context.Context, domain.SignUpReq) (*domain.SignUpResp, error)
	signInFn              func(context.Context, domain.SignInReq) (*domain.SignInResp, error)
	signInWithOobCodeFn   func(context.Context, domain.SignInWithOobCodeReq) (*domain.SignInResp, error)
	lookupFn              func(context.Context, domain.LookupReq) (*domain.LookupResp, error)
	tokenExchangeFn       func(context.Context, domain.TokenExchangeReq) (*domain.TokenExchangeResp, error)
	jwksFn                func(context.Context) (map[string]any, error)
	validateIDTokenFn     func(context.Context, string, string, string) (jwt.MapClaims, error)
	validateAccessTokenFn func(context.Context, string, string, string) (jwt.MapClaims, error)
	setStatusFn           func(context.Context, string, string) (*domain.StatusResp, error)
	revokeTokensFn        func(context.Context, string, string, string) (*domain.RevokeResp, error)
	updateUserFn          func(context.Context, domain.UpdateReq) (*domain.UpdateResp, error)
	deleteUserFn          func(context.Context, domain.DeleteReq) error
	sendOobFn             func(context.Context, domain.SendOobReq) (*domain.SendOobResp, error)
	sendOobForTenantFn    func(context.Context, string, domain.SendOobReq) (*domain.SendOobTenantResp, error)
	resetPasswordFn       func(context.Context, domain.ResetPwdReq) error
	getAllUsersFn         func(context.Context) ([]*domain.User, error)
}

func (f *fakeUserService) SignUp(ctx context.Context, req domain.SignUpReq) (*domain.SignUpResp, error) {
	if f.signUpFn != nil {
		return f.signUpFn(ctx, req)
	}
	return nil, nil
}

func (f *fakeUserService) SignIn(ctx context.Context, req domain.SignInReq) (*domain.SignInResp, error) {
	if f.signInFn != nil {
		return f.signInFn(ctx, req)
	}
	return nil, nil
}

func (f *fakeUserService) SignInWithOobCode(ctx context.Context, req domain.SignInWithOobCodeReq) (*domain.SignInResp, error) {
	if f.signInWithOobCodeFn != nil {
		return f.signInWithOobCodeFn(ctx, req)
	}
	return nil, nil
}

func (f *fakeUserService) Lookup(ctx context.Context, req domain.LookupReq) (*domain.LookupResp, error) {
	if f.lookupFn != nil {
		return f.lookupFn(ctx, req)
	}
	return nil, nil
}

func (f *fakeUserService) TokenExchange(ctx context.Context, req domain.TokenExchangeReq) (*domain.TokenExchangeResp, error) {
	if f.tokenExchangeFn != nil {
		return f.tokenExchangeFn(ctx, req)
	}
	return nil, nil
}

func (f *fakeUserService) JWKS(ctx context.Context) (map[string]any, error) {
	if f.jwksFn != nil {
		return f.jwksFn(ctx)
	}
	return nil, nil
}

func (f *fakeUserService) ValidateIDToken(ctx context.Context, tokenString string, issuer string, audience string) (jwt.MapClaims, error) {
	if f.validateIDTokenFn != nil {
		return f.validateIDTokenFn(ctx, tokenString, issuer, audience)
	}
	return nil, nil
}

func (f *fakeUserService) ValidateAccessToken(ctx context.Context, tokenString string, issuer string, audience string) (jwt.MapClaims, error) {
	if f.validateAccessTokenFn != nil {
		return f.validateAccessTokenFn(ctx, tokenString, issuer, audience)
	}
	return nil, nil
}

func (f *fakeUserService) SetStatus(ctx context.Context, email string, status string) (*domain.StatusResp, error) {
	if f.setStatusFn != nil {
		return f.setStatusFn(ctx, email, status)
	}
	return nil, nil
}

func (f *fakeUserService) RevokeTokens(ctx context.Context, email string, tenantID string, scope string) (*domain.RevokeResp, error) {
	if f.revokeTokensFn != nil {
		return f.revokeTokensFn(ctx, email, tenantID, scope)
	}
	return nil, nil
}

func (f *fakeUserService) UpdateUser(ctx context.Context, req domain.UpdateReq) (*domain.UpdateResp, error) {
	if f.updateUserFn != nil {
		return f.updateUserFn(ctx, req)
	}
	return nil, nil
}

func (f *fakeUserService) DeleteUser(ctx context.Context, req domain.DeleteReq) error {
	if f.deleteUserFn != nil {
		return f.deleteUserFn(ctx, req)
	}
	return nil
}

func (f *fakeUserService) SendOob(ctx context.Context, req domain.SendOobReq) (*domain.SendOobResp, error) {
	if f.sendOobFn != nil {
		return f.sendOobFn(ctx, req)
	}
	return nil, nil
}

func (f *fakeUserService) SendOobForTenant(ctx context.Context, tenantID string, req domain.SendOobReq) (*domain.SendOobTenantResp, error) {
	if f.sendOobForTenantFn != nil {
		return f.sendOobForTenantFn(ctx, tenantID, req)
	}
	return nil, nil
}

func (f *fakeUserService) ResetPassword(ctx context.Context, req domain.ResetPwdReq) error {
	if f.resetPasswordFn != nil {
		return f.resetPasswordFn(ctx, req)
	}
	return nil
}

func (f *fakeUserService) GetAllUsers(ctx context.Context) ([]*domain.User, error) {
	if f.getAllUsersFn != nil {
		return f.getAllUsersFn(ctx)
	}
	return nil, nil
}

type fakeTenantService struct {
	createFn        func(context.Context, domain.TenantCreateReq) (*domain.TenantResp, error)
	createWithIDFn  func(context.Context, string, domain.TenantCreateReq) (*domain.TenantResp, bool, error)
	getFn           func(context.Context, string) (*domain.TenantResp, error)
	listFn          func(context.Context, uint64, int64) (*domain.TenantsPage, error)
	ensureDefaultFn func(context.Context) (*domain.TenantResp, error)
}

func (f *fakeTenantService) Create(ctx context.Context, req domain.TenantCreateReq) (*domain.TenantResp, error) {
	if f.createFn != nil {
		return f.createFn(ctx, req)
	}
	return nil, nil
}

func (f *fakeTenantService) CreateWithID(
	ctx context.Context,
	tenantID string,
	req domain.TenantCreateReq,
) (*domain.TenantResp, bool, error) {
	if f.createWithIDFn != nil {
		return f.createWithIDFn(ctx, tenantID, req)
	}
	return nil, false, nil
}

func (f *fakeTenantService) Get(ctx context.Context, tenantID string) (*domain.TenantResp, error) {
	if f.getFn != nil {
		return f.getFn(ctx, tenantID)
	}
	return nil, nil
}

func (f *fakeTenantService) List(ctx context.Context, offset uint64, pageSize int64) (*domain.TenantsPage, error) {
	if f.listFn != nil {
		return f.listFn(ctx, offset, pageSize)
	}
	return &domain.TenantsPage{Tenants: []domain.TenantResp{}}, nil
}

func (f *fakeTenantService) EnsureDefault(ctx context.Context) (*domain.TenantResp, error) {
	if f.ensureDefaultFn != nil {
		return f.ensureDefaultFn(ctx)
	}
	return nil, nil
}

type fakeMembershipService struct {
	createFn            func(context.Context, string, domain.MembershipCreateReq) (*domain.MembershipResp, error)
	removeFn            func(context.Context, string, domain.MembershipRemoveReq) (*domain.MembershipRemoveResp, error)
	listFn              func(context.Context, string, uint64, int64) (*domain.TenantUsersPage, error)
	listTenantIDsByUser func(context.Context, string) ([]string, error)
}

func (f *fakeMembershipService) Create(ctx context.Context, tenantID string, req domain.MembershipCreateReq) (*domain.MembershipResp, error) {
	if f.createFn != nil {
		return f.createFn(ctx, tenantID, req)
	}
	return nil, nil
}

func (f *fakeMembershipService) Remove(ctx context.Context, tenantID string, req domain.MembershipRemoveReq) (*domain.MembershipRemoveResp, error) {
	if f.removeFn != nil {
		return f.removeFn(ctx, tenantID, req)
	}
	return nil, nil
}

func (f *fakeMembershipService) List(ctx context.Context, tenantID string, cursor uint64, pageSize int64) (*domain.TenantUsersPage, error) {
	if f.listFn != nil {
		return f.listFn(ctx, tenantID, cursor, pageSize)
	}
	return &domain.TenantUsersPage{Users: []domain.TenantUserResp{}}, nil
}

func (f *fakeMembershipService) ListTenantIDsByUser(ctx context.Context, userID string) ([]string, error) {
	if f.listTenantIDsByUser != nil {
		return f.listTenantIDsByUser(ctx, userID)
	}
	return nil, nil
}

type fakeRoleService struct {
	createFn             func(context.Context, string, domain.RoleCreateReq) (*domain.RoleResp, error)
	createWithNameFn     func(context.Context, string, string, domain.RolePutReq) (*domain.RoleResp, bool, error)
	getByNameFn          func(context.Context, string, string) (*domain.RoleResp, error)
	listCanonicalFn      func(context.Context, string) ([]*domain.RoleResp, error)
	listFn               func(context.Context, string) ([]*domain.RoleResp, error)
	resolvePermissionsFn func(context.Context, string, []string) ([]string, error)
}

func (f *fakeRoleService) Create(ctx context.Context, tenantID string, req domain.RoleCreateReq) (*domain.RoleResp, error) {
	if f.createFn != nil {
		return f.createFn(ctx, tenantID, req)
	}
	return nil, nil
}
func (f *fakeRoleService) CreateWithName(ctx context.Context, tenantID, name string, req domain.RolePutReq) (*domain.RoleResp, bool, error) {
	if f.createWithNameFn == nil {
		return nil, false, nil
	}
	return f.createWithNameFn(ctx, tenantID, name, req)
}
func (f *fakeRoleService) GetByName(ctx context.Context, tenantID, name string) (*domain.RoleResp, error) {
	if f.getByNameFn != nil {
		return f.getByNameFn(ctx, tenantID, name)
	}
	return nil, nil
}
func (f *fakeRoleService) ListCanonical(ctx context.Context, tenantID string) ([]*domain.RoleResp, error) {
	if f.listCanonicalFn != nil {
		return f.listCanonicalFn(ctx, tenantID)
	}
	return []*domain.RoleResp{}, nil
}
func (f *fakeRoleService) List(ctx context.Context, tenantID string) ([]*domain.RoleResp, error) {
	if f.listFn != nil {
		return f.listFn(ctx, tenantID)
	}
	return nil, nil
}

func (f *fakeRoleService) ResolvePermissions(ctx context.Context, tenantID string, roles []string) ([]string, error) {
	if f.resolvePermissionsFn != nil {
		return f.resolvePermissionsFn(ctx, tenantID, roles)
	}
	return nil, nil
}

type fakeClientService struct {
	createFn    func(context.Context, string, domain.ClientCreateReq) (*domain.ClientResp, error)
	getFn       func(context.Context, string, string) (*domain.ClientResp, error)
	listFn      func(context.Context, string) ([]*domain.ClientResp, error)
	getClientFn func(context.Context, string, string) (*domain.Client, error)
}

func (f *fakeClientService) Create(ctx context.Context, tenantID string, req domain.ClientCreateReq) (*domain.ClientResp, error) {
	if f.createFn != nil {
		return f.createFn(ctx, tenantID, req)
	}
	return nil, nil
}

func (f *fakeClientService) Get(ctx context.Context, tenantID string, clientID string) (*domain.ClientResp, error) {
	if f.getFn != nil {
		return f.getFn(ctx, tenantID, clientID)
	}
	return nil, nil
}

func (f *fakeClientService) List(ctx context.Context, tenantID string) ([]*domain.ClientResp, error) {
	if f.listFn != nil {
		return f.listFn(ctx, tenantID)
	}
	return nil, nil
}

func (f *fakeClientService) GetClient(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
	if f.getClientFn != nil {
		return f.getClientFn(ctx, tenantID, clientID)
	}
	return nil, nil
}

func performJSON(t *testing.T, h http.Handler, method string, path string, body any, auth string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeJSONBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode json response: %v body=%q", err, rec.Body.String())
	}
	return out
}

func adminToken(t *testing.T, secret string, role string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"role": role,
		"exp":  time.Now().Add(time.Hour).Unix(),
		"iat":  time.Now().Unix(),
	})
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}
