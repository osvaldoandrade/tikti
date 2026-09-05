package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type mockUserRepo struct {
	createUserFn            func(context.Context, *domain.User) error
	findByEmailFn           func(context.Context, string) (*domain.User, error)
	updateUserFn            func(context.Context, *domain.User) error
	deleteByEmailFn         func(context.Context, string) error
	setStatusFn             func(context.Context, string, domain.UserStatus) (*domain.User, error)
	incrementTokenVersionFn func(context.Context, string) (int, *domain.User, error)
	saveOobCodeFn           func(context.Context, string, string, string) error
	consumeOobCodeFn        func(context.Context, string, string) (string, error)
	getAllUsersFn           func(context.Context) ([]*domain.User, error)
	upsertFromSAMLFn        func(context.Context, string, string, string, string, []string, domain.MergeStrategy) (domain.User, bool, error)
}

func (m *mockUserRepo) CreateUser(ctx context.Context, user *domain.User) error {
	if m.createUserFn != nil {
		return m.createUserFn(ctx, user)
	}
	return nil
}
func (m *mockUserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	if m.findByEmailFn != nil {
		return m.findByEmailFn(ctx, email)
	}
	return nil, nil
}
func (m *mockUserRepo) UpdateUser(ctx context.Context, user *domain.User) error {
	if m.updateUserFn != nil {
		return m.updateUserFn(ctx, user)
	}
	return nil
}
func (m *mockUserRepo) DeleteByEmail(ctx context.Context, email string) error {
	if m.deleteByEmailFn != nil {
		return m.deleteByEmailFn(ctx, email)
	}
	return nil
}
func (m *mockUserRepo) SetStatus(ctx context.Context, email string, status domain.UserStatus) (*domain.User, error) {
	if m.setStatusFn != nil {
		return m.setStatusFn(ctx, email, status)
	}
	return nil, nil
}
func (m *mockUserRepo) IncrementTokenVersion(ctx context.Context, email string) (int, *domain.User, error) {
	if m.incrementTokenVersionFn != nil {
		return m.incrementTokenVersionFn(ctx, email)
	}
	return 0, nil, nil
}
func (m *mockUserRepo) SaveOobCode(ctx context.Context, code, email, reqType string) error {
	if m.saveOobCodeFn != nil {
		return m.saveOobCodeFn(ctx, code, email, reqType)
	}
	return nil
}
func (m *mockUserRepo) ConsumeOobCode(ctx context.Context, code string, expectedReqType string) (string, error) {
	if m.consumeOobCodeFn != nil {
		return m.consumeOobCodeFn(ctx, code, expectedReqType)
	}
	return "", nil
}
func (m *mockUserRepo) GetAllUsers(ctx context.Context) ([]*domain.User, error) {
	if m.getAllUsersFn != nil {
		return m.getAllUsersFn(ctx)
	}
	return nil, nil
}
func (m *mockUserRepo) UpsertFromSAML(ctx context.Context, tid, externalSubject, email, name string, roles []string, mergeStrategy domain.MergeStrategy) (domain.User, bool, error) {
	if m.upsertFromSAMLFn != nil {
		return m.upsertFromSAMLFn(ctx, tid, externalSubject, email, name, roles, mergeStrategy)
	}
	return domain.User{}, false, nil
}

type mockMembershipRepo struct {
	createFn            func(context.Context, *domain.Membership) error
	getFn               func(context.Context, string, string) (*domain.Membership, error)
	getExactFn          func(context.Context, string, string) (*domain.Membership, error)
	listByTenantFn      func(context.Context, string, uint64, int64) ([]*domain.Membership, uint64, error)
	listTenantIDsByUser func(context.Context, string) ([]string, error)
	listExactFn         func(context.Context, string) ([]string, error)
	deleteFn            func(context.Context, string, string) error
}

func (m *mockMembershipRepo) Create(ctx context.Context, membership *domain.Membership) error {
	if m.createFn != nil {
		return m.createFn(ctx, membership)
	}
	return nil
}
func (m *mockMembershipRepo) Get(ctx context.Context, tenantID string, userID string) (*domain.Membership, error) {
	if m.getFn != nil {
		return m.getFn(ctx, tenantID, userID)
	}
	return nil, nil
}
func (m *mockMembershipRepo) GetExact(ctx context.Context, tenantID string, userID string) (*domain.Membership, error) {
	if m.getExactFn != nil {
		return m.getExactFn(ctx, tenantID, userID)
	}
	return nil, nil
}
func (m *mockMembershipRepo) ListByTenant(ctx context.Context, tenantID string, cursor uint64, count int64) ([]*domain.Membership, uint64, error) {
	if m.listByTenantFn != nil {
		return m.listByTenantFn(ctx, tenantID, cursor, count)
	}
	return nil, 0, nil
}
func (m *mockMembershipRepo) ListTenantIDsByUser(ctx context.Context, userID string) ([]string, error) {
	if m.listTenantIDsByUser != nil {
		return m.listTenantIDsByUser(ctx, userID)
	}
	return nil, nil
}
func (m *mockMembershipRepo) ListTenantIDsByUserExact(ctx context.Context, userID string) ([]string, error) {
	if m.listExactFn != nil {
		return m.listExactFn(ctx, userID)
	}
	return nil, nil
}
func (m *mockMembershipRepo) ListTenantIDsByUserExactBounded(ctx context.Context, userID string, maximum int) ([]string, bool, error) {
	values, err := m.ListTenantIDsByUserExact(ctx, userID)
	if err != nil {
		return nil, false, err
	}
	if len(values) > maximum {
		return nil, true, nil
	}
	return values, false, nil
}
func (m *mockMembershipRepo) Delete(ctx context.Context, tenantID string, userID string) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, tenantID, userID)
	}
	return nil
}

type mockRoleService struct {
	resolvePermissionsFn func(context.Context, string, []string) ([]string, error)
	getByNameFn          func(context.Context, string, string) (*domain.RoleResp, error)
}

func (m *mockRoleService) Create(context.Context, string, domain.RoleCreateReq) (*domain.RoleResp, error) {
	return nil, nil
}
func (m *mockRoleService) CreateWithName(context.Context, string, string, domain.RolePutReq) (*domain.RoleResp, bool, error) {
	return nil, false, nil
}

func (m *mockRoleService) GetByName(ctx context.Context, tenantID, roleName string) (*domain.RoleResp, error) {
	if m.getByNameFn != nil {
		return m.getByNameFn(ctx, tenantID, roleName)
	}
	return nil, nil
}
func (m *mockRoleService) ListCanonical(context.Context, string) ([]*domain.RoleResp, error) {
	return nil, nil
}
func (m *mockRoleService) List(context.Context, string) ([]*domain.RoleResp, error) { return nil, nil }
func (m *mockRoleService) ResolvePermissions(ctx context.Context, tenantID string, roles []string) ([]string, error) {
	if m.resolvePermissionsFn != nil {
		return m.resolvePermissionsFn(ctx, tenantID, roles)
	}
	return nil, nil
}

type mockClientService struct {
	getClientFn func(context.Context, string, string) (*domain.Client, error)
}

func (m *mockClientService) Create(context.Context, string, domain.ClientCreateReq) (*domain.ClientResp, error) {
	return nil, nil
}
func (m *mockClientService) EnsureCodeAdminAudience(context.Context, string, domain.ManagedAudienceClientEnsureReq) (*domain.ManagedAudienceClientResp, bool, error) {
	return nil, false, nil
}
func (m *mockClientService) Get(context.Context, string, string) (*domain.ClientResp, error) {
	return nil, nil
}
func (m *mockClientService) List(context.Context, string) ([]*domain.ClientResp, error) {
	return nil, nil
}
func (m *mockClientService) GetClient(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
	if m.getClientFn != nil {
		return m.getClientFn(ctx, tenantID, clientID)
	}
	return nil, nil
}

func makePEMKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

func signIDToken(t *testing.T, secret string, email string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   email,
		"email": email,
		"role":  string(domain.RoleCompanyEmployee),
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return signed
}

func bcryptHash(t *testing.T, raw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

func TestUserService_SignUpAndSignIn(t *testing.T) {
	repo := &mockUserRepo{}
	membership := &mockMembershipRepo{}
	svc := NewUserService(repo, membership, nil, nil, "secret", "http://issuer", "tikti", makePEMKey(t), "kid").(*userService)

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email}, nil
	}
	if _, err := svc.SignUp(context.Background(), domain.SignUpReq{Email: "a@x.com", Password: "p"}); err != domain.ErrEmailExists {
		t.Fatalf("expected ErrEmailExists, got %v", err)
	}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) { return nil, nil }
	createErr := errors.New("create-fail")
	repo.createUserFn = func(ctx context.Context, user *domain.User) error { return createErr }
	if _, err := svc.SignUp(context.Background(), domain.SignUpReq{Email: "a@x.com", Password: "p"}); !errors.Is(err, createErr) {
		t.Fatalf("expected create error, got %v", err)
	}

	membershipCreated := false
	repo.createUserFn = func(ctx context.Context, user *domain.User) error { return nil }
	membership.createFn = func(ctx context.Context, m *domain.Membership) error {
		membershipCreated = true
		return nil
	}
	resp, err := svc.SignUp(context.Background(), domain.SignUpReq{Email: "a@x.com", Password: "p", Role: string(domain.RoleCompanyAdmin)})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !membershipCreated || resp.Email != "a@x.com" {
		t.Fatalf("unexpected signup response: %+v", resp)
	}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) { return nil, errors.New("x") }
	if _, err := svc.SignIn(context.Background(), domain.SignInReq{Email: "a@x.com", Password: "p"}); err != domain.ErrInvalidCreds {
		t.Fatalf("expected ErrInvalidCreds, got %v", err)
	}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, Password: bcryptHash(t, "p"), Status: domain.UserStatusSuspended}, nil
	}
	if _, err := svc.SignIn(context.Background(), domain.SignInReq{Email: "a@x.com", Password: "p"}); err != domain.ErrInvalidCreds {
		t.Fatalf("expected ErrInvalidCreds, got %v", err)
	}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, Password: bcryptHash(t, "other"), Status: domain.UserStatusActive}, nil
	}
	if _, err := svc.SignIn(context.Background(), domain.SignInReq{Email: "a@x.com", Password: "p"}); err != domain.ErrInvalidCreds {
		t.Fatalf("expected ErrInvalidCreds, got %v", err)
	}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, Password: bcryptHash(t, "p"), Status: domain.UserStatusActive, Role: domain.RoleCompanyEmployee}, nil
	}
	signInResp, err := svc.SignIn(context.Background(), domain.SignInReq{Email: "a@x.com", Password: "p"})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if signInResp.IdToken == "" || signInResp.ExpiresIn != 3600 {
		t.Fatalf("unexpected signin response: %+v", signInResp)
	}
	claims, err := utils.ParseToken(signInResp.IdToken, "secret")
	if err != nil {
		t.Fatalf("expected parseable id token, got %v", err)
	}
	if claims["email"] != "a@x.com" {
		t.Fatalf("unexpected email claim: %v", claims["email"])
	}
	if claims["sub"] != "u1" {
		t.Fatalf("expected sub=u1, got %v", claims["sub"])
	}
}

func TestUserService_LookupAndUserMutations(t *testing.T) {
	repo := &mockUserRepo{}
	svc := NewUserService(repo, nil, nil, nil, "secret", "http://issuer", "tikti", makePEMKey(t), "kid").(*userService)

	if _, err := svc.Lookup(context.Background(), domain.LookupReq{IdToken: "bad"}); err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}

	tok := signIDToken(t, "secret", "u@x.com")
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) { return nil, nil }
	if _, err := svc.Lookup(context.Background(), domain.LookupReq{IdToken: tok}); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	tenant := "tenant-1"
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, CompanyId: &tenant}, nil
	}
	lr, err := svc.Lookup(context.Background(), domain.LookupReq{IdToken: tok})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(lr.Users) != 1 || lr.Users[0].Tenant != "tenant-1" {
		t.Fatalf("unexpected lookup response: %+v", lr)
	}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: "u@x.com", Password: "old"}, nil
	}
	repo.updateUserFn = func(ctx context.Context, user *domain.User) error { return errors.New("update-fail") }
	if _, err := svc.UpdateUser(context.Background(), domain.UpdateReq{IdToken: tok, Email: "new@x.com"}); err == nil {
		t.Fatalf("expected update error")
	}

	repo.updateUserFn = func(ctx context.Context, user *domain.User) error { return nil }
	ur, err := svc.UpdateUser(context.Background(), domain.UpdateReq{IdToken: tok, Email: "new@x.com", Password: "np"})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if ur.Email != "new@x.com" {
		t.Fatalf("unexpected update response: %+v", ur)
	}

	if err := svc.DeleteUser(context.Background(), domain.DeleteReq{IdToken: "bad-token"}); err == nil {
		t.Fatalf("expected invalid token error")
	}

	repo.deleteByEmailFn = func(ctx context.Context, email string) error { return errors.New("delete-fail") }
	if err := svc.DeleteUser(context.Background(), domain.DeleteReq{IdToken: tok}); err == nil {
		t.Fatalf("expected delete error")
	}
	repo.deleteByEmailFn = func(ctx context.Context, email string) error { return nil }
	if err := svc.DeleteUser(context.Background(), domain.DeleteReq{IdToken: tok}); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestUserService_TokenExchangeAndAccessValidation(t *testing.T) {
	repo := &mockUserRepo{}
	membership := &mockMembershipRepo{}
	roleSvc := &mockRoleService{}
	clientSvc := &mockClientService{}
	tenant := "t1"
	svc := NewUserService(repo, membership, roleSvc, clientSvc, "secret", "https://issuer", "tikti", makePEMKey(t), "kid-1").(*userService)

	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{Audience: "a"}); err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: "x"}); err != domain.ErrInvalidAudience {
		t.Fatalf("expected ErrInvalidAudience, got %v", err)
	}
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: "bad", Audience: "a"}); err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}

	noEmailToken := signIDToken(t, "secret", "")
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: noEmailToken, Audience: "a"}); err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}

	idTok := signIDToken(t, "secret", "u@x.com")
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) { return nil, nil }
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: idTok, Audience: "a"}); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, Status: domain.UserStatusSuspended}, nil
	}
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: idTok, Audience: "a"}); err != domain.ErrInvalidCreds {
		t.Fatalf("expected ErrInvalidCreds, got %v", err)
	}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, Status: domain.UserStatusActive}, nil
	}
	membership.listTenantIDsByUser = func(ctx context.Context, userID string) ([]string, error) { return nil, nil }
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: idTok, Audience: "a"}); err != domain.ErrInvalidTenant {
		t.Fatalf("expected ErrInvalidTenant, got %v", err)
	}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, Status: domain.UserStatusActive, CompanyId: &tenant, Role: domain.RoleCompanyEmployee}, nil
	}
	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		return nil, errors.New("client-fail")
	}
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: idTok, Audience: "a", TenantID: "t1"}); err == nil {
		t.Fatalf("expected client error")
	}

	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) { return nil, nil }
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: idTok, Audience: "a", TenantID: "t1"}); err != domain.ErrInvalidAudience {
		t.Fatalf("expected ErrInvalidAudience, got %v", err)
	}

	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		return &domain.Client{Id: clientID, Status: "INACTIVE"}, nil
	}
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: idTok, Audience: "a", TenantID: "t1"}); err != domain.ErrInvalidAudience {
		t.Fatalf("expected ErrInvalidAudience, got %v", err)
	}

	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		return &domain.Client{Id: clientID, Status: "ACTIVE", DefaultScopes: []string{"s1"}}, nil
	}
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken: idTok, Audience: "a", TenantID: "t1", Scopes: []string{"s2"},
	}); err != domain.ErrUnauthorizedScope {
		t.Fatalf("expected ErrUnauthorizedScope, got %v", err)
	}

	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		return &domain.Client{Id: clientID, Status: "ACTIVE", DefaultScopes: []string{"codeq:claim"}}, nil
	}
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken: idTok, Audience: "a", TenantID: "t1", Scopes: []string{"codeq:result"},
	}); err != domain.ErrUnauthorizedScope {
		t.Fatalf("expected ErrUnauthorizedScope, got %v", err)
	}

	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken: idTok, Audience: "codeq-worker", TenantID: "t1", Scopes: []string{"codeq:claim"},
	}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, Status: domain.UserStatusActive, CompanyId: &tenant, Role: domain.RoleAdmin}, nil
	}
	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		return &domain.Client{Id: clientID, Status: "ACTIVE", DefaultScopes: []string{"code-admin:secrets:read"}}, nil
	}
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken: idTok, Audience: "legacy-client", TenantID: "t1",
	}); err != nil {
		t.Fatalf("expected runtime-backed stored scope to be issued, got %v", err)
	}
	if _, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken: idTok, Audience: "legacy-client", TenantID: "t1", Scopes: []string{"code-admin:secrets:read"},
	}); err != nil {
		t.Fatalf("expected runtime-backed requested scope to be issued, got %v", err)
	}
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, Status: domain.UserStatusActive, CompanyId: &tenant, Role: domain.RoleCompanyEmployee}, nil
	}
	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		return &domain.Client{Id: clientID, Status: "ACTIVE", DefaultScopes: []string{"codeq:claim"}}, nil
	}

	badKeySvc := NewUserService(repo, membership, roleSvc, clientSvc, "secret", "https://issuer", "tikti", "bad-pem", "kid").(*userService)
	if _, err := badKeySvc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken: idTok, Audience: "a", TenantID: "t1", Scopes: []string{"codeq:claim"},
	}); err == nil {
		t.Fatalf("expected pem parse error")
	}

	teResp, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken: idTok, Audience: "a", TenantID: "t1", Scopes: []string{"codeq:claim"}, TTLSeconds: 90000, Subject: "",
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if teResp.AccessToken == "" || teResp.ExpiresIn != 86400 {
		t.Fatalf("unexpected token exchange response: %+v", teResp)
	}

	claims, err := svc.ValidateAccessToken(context.Background(), teResp.AccessToken, "https://issuer", "a")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if claims["tid"] != "t1" {
		t.Fatalf("unexpected tid: %v", claims["tid"])
	}
}

func TestUserService_ValidateJWKSAndHelpers(t *testing.T) {
	repo := &mockUserRepo{}
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, TokenVersion: 1, Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive}, nil
	}
	membership := &mockMembershipRepo{
		getFn: func(ctx context.Context, tenantID string, userID string) (*domain.Membership, error) {
			return &domain.Membership{TenantId: tenantID, UserId: userID, Roles: []string{"CUSTOM"}}, nil
		},
		listTenantIDsByUser: func(ctx context.Context, userID string) ([]string, error) {
			return []string{"t2", "t1"}, nil
		},
	}
	roleSvc := &mockRoleService{
		resolvePermissionsFn: func(ctx context.Context, tenantID string, roles []string) ([]string, error) {
			return []string{"custom:perm"}, nil
		},
	}
	svc := NewUserService(repo, membership, roleSvc, nil, "secret", "https://issuer", "tikti", makePEMKey(t), "kid").(*userService)

	// Build a valid RS256 token first.
	key, err := svc.getRSAPrivateKey()
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	priv := key.(*rsa.PrivateKey)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://issuer",
		"aud": "tikti",
		"sub": "u@x.com",
		"ver": 1,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := svc.ValidateAccessToken(context.Background(), "bad", "https://issuer", "tikti"); err == nil {
		t.Fatalf("expected invalid token error")
	}

	// invalid key type branch.
	svc2 := &userService{repo: repo}
	svc2.rsaOnce.Do(func() { svc2.rsaKey = "bad-type" })
	if _, err := svc2.ValidateAccessToken(context.Background(), signed, "https://issuer", "tikti"); err == nil {
		t.Fatalf("expected invalid rsa key type")
	}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) { return nil, nil }
	if _, err := svc.ValidateAccessToken(context.Background(), signed, "https://issuer", "tikti"); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, TokenVersion: 2, Status: domain.UserStatusActive}, nil
	}
	if _, err := svc.ValidateAccessToken(context.Background(), signed, "https://issuer", "tikti"); err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, TokenVersion: 1, Status: domain.UserStatusActive}, nil
	}
	if _, err := svc.ValidateAccessToken(context.Background(), signed, "https://issuer", "tikti"); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	tokenWithEmailFallback := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   "https://issuer",
		"aud":   "tikti",
		"email": "u@x.com",
		"ver":   1,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})
	emailFallbackSigned, err := tokenWithEmailFallback.SignedString(priv)
	if err != nil {
		t.Fatalf("sign email fallback token: %v", err)
	}
	if _, err := svc.ValidateAccessToken(context.Background(), emailFallbackSigned, "https://issuer", "tikti"); err != nil {
		t.Fatalf("expected email-claim fallback to validate, got %v", err)
	}
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, TokenVersion: 1, Status: domain.UserStatusSuspended}, nil
	}
	if _, err := svc.ValidateAccessToken(context.Background(), signed, "https://issuer", "tikti"); err != domain.ErrInvalidCreds {
		t.Fatalf("expected suspended account rejection, got %v", err)
	}

	tokenWithoutSubject := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://issuer",
		"aud": "tikti",
		"ver": 1,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	noSubjectSigned, err := tokenWithoutSubject.SignedString(priv)
	if err != nil {
		t.Fatalf("sign no-sub token: %v", err)
	}
	if _, err := svc.ValidateAccessToken(context.Background(), noSubjectSigned, "https://issuer", "tikti"); err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}

	jwksOut, err := svc.JWKS(context.Background())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if _, ok := jwksOut["keys"]; !ok {
		t.Fatalf("expected keys in jwks output")
	}

	badKeySvc := NewUserService(repo, membership, roleSvc, nil, "secret", "https://issuer", "tikti", "bad-pem", "kid").(*userService)
	if _, err := badKeySvc.JWKS(context.Background()); err == nil {
		t.Fatalf("expected jwks parse-key error")
	}
	invalidTypeSvc := &userService{}
	invalidTypeSvc.rsaOnce.Do(func() { invalidTypeSvc.rsaKey = "bad-type" })
	if _, err := invalidTypeSvc.JWKS(context.Background()); err == nil {
		t.Fatalf("expected invalid rsa key type")
	}

	if ok := svc.scopesAllowed(context.Background(), "t1", nil, []string{"x"}); ok {
		t.Fatalf("nil user should not be allowed")
	}
	adminUser := &domain.User{Role: domain.RoleAdmin}
	if ok := svc.scopesAllowed(context.Background(), "t1", adminUser, []string{"x"}); !ok {
		t.Fatalf("admin should be allowed")
	}
	if ok := svc.scopesAllowed(context.Background(), "t1", adminUser, []string{"code-admin:secrets:read"}); !ok {
		t.Fatalf("admin did not receive a runtime-backed tenant scope")
	}
	if ok := svc.scopesAllowed(context.Background(), "t1", adminUser, []string{"code-admin:invented:read"}); ok {
		t.Fatalf("admin received an unknown reserved scope")
	}
	companyAdmin := &domain.User{Role: domain.RoleCompanyAdmin}
	if ok := svc.scopesAllowed(context.Background(), "t1", companyAdmin, []string{domain.PlatformTenantAdminScope}); ok {
		t.Fatalf("company admin received a global tenant administration scope")
	}
	if ok := svc.scopesAllowed(context.Background(), "t1", companyAdmin, []string{"legacy:company-admin"}); !ok {
		t.Fatalf("unrelated legacy company-admin scope should remain compatible")
	}
	if ok := svc.scopesAllowed(context.Background(), "t1", companyAdmin, []string{"code-admin:secrets:write"}); !ok {
		t.Fatalf("company admin did not receive a runtime-backed tenant scope")
	}
	emp := &domain.User{Id: "u1", Role: domain.RoleCompanyEmployee}
	if ok := svc.scopesAllowed(context.Background(), "t1", emp, []string{"codeq:claim"}); !ok {
		t.Fatalf("employee should have codeq defaults")
	}
	if ok := svc.scopesAllowed(context.Background(), "t1", emp, []string{"custom:perm"}); !ok {
		t.Fatalf("employee should include resolved custom perms")
	}
	if ok := svc.scopesAllowed(context.Background(), "t1", emp, []string{"missing"}); ok {
		t.Fatalf("missing scope should be denied")
	}

	if got := normalizeList([]string{" a ", "", "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("unexpected normalizeList: %v", got)
	}
	ids := svc.listTenantIDs(context.Background(), "u1")
	if !reflect.DeepEqual(ids, []string{"t1", "t2"}) {
		t.Fatalf("unexpected listTenantIDs: %v", ids)
	}
	if got := svc.resolveTenantID(context.Background(), nil); got != "" {
		t.Fatalf("expected empty tenant for nil user, got %s", got)
	}
	tenant := "company-1"
	if got := svc.resolveTenantID(context.Background(), &domain.User{Id: "u1", CompanyId: &tenant}); got != "t1" {
		t.Fatalf("expected membership tenant precedence, got %s", got)
	}
	if !containsString([]string{"a", "b"}, "a") || containsString([]string{"a"}, "x") {
		t.Fatalf("containsString failed")
	}
	if !subset(nil, []string{"a"}) {
		t.Fatalf("empty items should be subset")
	}
	if !subset([]string{"a", "", "b"}, []string{"a", "b"}) || subset([]string{"a", "c"}, []string{"a", "b"}) {
		t.Fatalf("subset failed")
	}
	if derefString(nil) != "" || derefString(&tenant) != "company-1" {
		t.Fatalf("derefString failed")
	}
}

func TestUserService_StatusRevokeOobAndReset(t *testing.T) {
	repo := &mockUserRepo{}
	membership := &mockMembershipRepo{}
	svc := NewUserService(repo, membership, nil, nil, "secret", "https://issuer", "tikti", makePEMKey(t), "kid").(*userService)

	if _, err := svc.SetStatus(context.Background(), "", "ACTIVE"); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if _, err := svc.SetStatus(context.Background(), "u@x.com", "BAD"); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	repo.setStatusFn = func(ctx context.Context, email string, status domain.UserStatus) (*domain.User, error) {
		return nil, errors.New("set-fail")
	}
	if _, err := svc.SetStatus(context.Background(), "u@x.com", "ACTIVE"); err == nil {
		t.Fatalf("expected set status error")
	}
	repo.setStatusFn = func(ctx context.Context, email string, status domain.UserStatus) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, Status: status}, nil
	}
	st, err := svc.SetStatus(context.Background(), "u@x.com", "ACTIVE")
	if err != nil || st.Status != "ACTIVE" {
		t.Fatalf("unexpected status response: %+v err=%v", st, err)
	}
	st, err = svc.SetStatus(context.Background(), "u@x.com", "inactive")
	if err != nil || st.Status != "INACTIVE" {
		t.Fatalf("unexpected inactive response: %+v err=%v", st, err)
	}
	st, err = svc.SetStatus(context.Background(), "u@x.com", "SUSPENDED")
	if err != nil || st.Status != "SUSPENDED" {
		t.Fatalf("unexpected suspended response: %+v err=%v", st, err)
	}

	if _, err := svc.RevokeTokens(context.Background(), " ", "", ""); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	repo.incrementTokenVersionFn = func(ctx context.Context, email string) (int, *domain.User, error) {
		return 0, nil, errors.New("revoke-fail")
	}
	if _, err := svc.RevokeTokens(context.Background(), "u@x.com", "", ""); err == nil {
		t.Fatalf("expected revoke error")
	}
	repo.incrementTokenVersionFn = func(ctx context.Context, email string) (int, *domain.User, error) {
		return 3, &domain.User{Id: "u1", Email: email}, nil
	}
	rev, err := svc.RevokeTokens(context.Background(), "u@x.com", "", "global")
	if err != nil || rev.TokenVersion != 3 {
		t.Fatalf("unexpected revoke response: %+v err=%v", rev, err)
	}

	if _, err := svc.SendOob(context.Background(), domain.SendOobReq{RequestType: "BAD", Email: "u@x.com"}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if _, err := svc.SendOob(context.Background(), domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: " "}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) { return nil, nil }
	sendResp, err := svc.SendOob(context.Background(), domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"})
	if err != nil || sendResp.OobCode == "" {
		t.Fatalf("unexpected EMAIL_SIGNIN anti-enum response: %+v err=%v", sendResp, err)
	}
	if _, err := svc.SendOob(context.Background(), domain.SendOobReq{RequestType: "PASSWORD_RESET", Email: "u@x.com"}); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, Status: domain.UserStatusActive}, nil
	}
	repo.saveOobCodeFn = func(ctx context.Context, code, email, reqType string) error { return errors.New("save-fail") }
	if _, err := svc.SendOob(context.Background(), domain.SendOobReq{RequestType: "PASSWORD_RESET", Email: "u@x.com"}); err == nil {
		t.Fatalf("expected save error")
	}
	repo.saveOobCodeFn = func(ctx context.Context, code, email, reqType string) error { return nil }
	if _, err := svc.SendOob(context.Background(), domain.SendOobReq{RequestType: "PASSWORD_RESET", Email: "u@x.com"}); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if _, err := svc.SendOobForTenant(context.Background(), " ", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"}); err != domain.ErrInvalidTenant {
		t.Fatalf("expected ErrInvalidTenant, got %v", err)
	}
	if _, err := svc.SendOobForTenant(context.Background(), "t1", domain.SendOobReq{RequestType: "BAD", Email: "u@x.com"}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if _, err := svc.SendOobForTenant(context.Background(), "t1", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: ""}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) { return nil, errors.New("find-fail") }
	if _, err := svc.SendOobForTenant(context.Background(), "t1", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"}); err == nil {
		t.Fatalf("expected find error")
	}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) { return nil, nil }
	if _, err := svc.SendOobForTenant(context.Background(), "t1", domain.SendOobReq{RequestType: "PASSWORD_RESET", Email: "u@x.com"}); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	createErr := errors.New("create-fail")
	repo.createUserFn = func(ctx context.Context, user *domain.User) error { return createErr }
	if _, err := svc.SendOobForTenant(context.Background(), "t1", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "new@x.com"}); !errors.Is(err, createErr) {
		t.Fatalf("expected create error, got %v", err)
	}

	repo.createUserFn = func(ctx context.Context, user *domain.User) error { return nil }
	repo.saveOobCodeFn = func(ctx context.Context, code, email, reqType string) error { return nil }
	resp, err := svc.SendOobForTenant(context.Background(), "t1", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "new@x.com"})
	if err != nil || resp.OobCode == "" {
		t.Fatalf("unexpected send oob tenant response: %+v err=%v", resp, err)
	}

	otherTenant := "t2"
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email, Status: domain.UserStatusActive, CompanyId: &otherTenant}, nil
	}
	membership.getFn = func(ctx context.Context, tenantID string, userID string) (*domain.Membership, error) { return nil, nil }
	if _, err := svc.SendOobForTenant(context.Background(), "t1", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"}); err != domain.ErrInvalidTenant {
		t.Fatalf("expected ErrInvalidTenant, got %v", err)
	}

	svcNoMembership := NewUserService(repo, nil, nil, nil, "secret", "https://issuer", "tikti", makePEMKey(t), "kid").(*userService)
	if _, err := svcNoMembership.SendOobForTenant(context.Background(), "t1", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"}); err != domain.ErrInvalidTenant {
		t.Fatalf("expected ErrInvalidTenant, got %v", err)
	}

	repo.consumeOobCodeFn = func(ctx context.Context, code string, expectedReqType string) (string, error) {
		return "", errors.New("consume-fail")
	}
	if err := svc.ResetPassword(context.Background(), domain.ResetPwdReq{OobCode: "c", NewPassword: "p"}); err != domain.ErrInvalidOob {
		t.Fatalf("expected ErrInvalidOob, got %v", err)
	}
	repo.consumeOobCodeFn = func(ctx context.Context, code string, expectedReqType string) (string, error) {
		return "u@x.com", nil
	}
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) { return nil, nil }
	if err := svc.ResetPassword(context.Background(), domain.ResetPwdReq{OobCode: "c", NewPassword: "p"}); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "u1", Email: email}, nil
	}
	repo.updateUserFn = func(ctx context.Context, user *domain.User) error { return errors.New("update-fail") }
	if err := svc.ResetPassword(context.Background(), domain.ResetPwdReq{OobCode: "c", NewPassword: "p"}); err == nil {
		t.Fatalf("expected update error")
	}
	repo.updateUserFn = func(ctx context.Context, user *domain.User) error { return nil }
	if err := svc.ResetPassword(context.Background(), domain.ResetPwdReq{OobCode: "c", NewPassword: "p"}); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	repo.getAllUsersFn = func(ctx context.Context) ([]*domain.User, error) { return nil, errors.New("list-fail") }
	if _, err := svc.GetAllUsers(context.Background()); err == nil {
		t.Fatalf("expected list error")
	}
	repo.getAllUsersFn = func(ctx context.Context) ([]*domain.User, error) { return []*domain.User{{Id: "u1"}}, nil }
	if users, err := svc.GetAllUsers(context.Background()); err != nil || len(users) != 1 {
		t.Fatalf("unexpected users: %+v err=%v", users, err)
	}
}

func TestSendOobForTenantRejectsForeignPasswordResetBeforeSavingCode(t *testing.T) {
	foreignTenant := "foreign-tenant"
	saveCalls := 0
	repo := &mockUserRepo{
		findByEmailFn: func(context.Context, string) (*domain.User, error) {
			return &domain.User{
				Id:        "foreign-user",
				Email:     "foreign@example.com",
				Status:    domain.UserStatusActive,
				CompanyId: &foreignTenant,
			}, nil
		},
		saveOobCodeFn: func(context.Context, string, string, string) error {
			saveCalls++
			return nil
		},
	}
	memberships := &mockMembershipRepo{
		getFn: func(context.Context, string, string) (*domain.Membership, error) {
			return nil, nil
		},
	}
	service := NewUserService(repo, memberships, nil, nil, "secret", "https://issuer", "tikti", makePEMKey(t), "kid").(*userService)

	_, err := service.SendOobForTenant(context.Background(), "requested-tenant", domain.SendOobReq{
		RequestType: "PASSWORD_RESET",
		Email:       "foreign@example.com",
	})
	if err != domain.ErrInvalidTenant {
		t.Fatalf("expected ErrInvalidTenant, got %v", err)
	}
	if saveCalls != 0 {
		t.Fatalf("SaveOobCode calls=%d, want 0", saveCalls)
	}
}

func TestUserService_IssueIDTokenAndGetRSAPrivateKey(t *testing.T) {
	repo := &mockUserRepo{}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://issuer", "tikti", makePEMKey(t), "kid").(*userService)

	if _, _, err := svc.issueIDToken(nil, nil); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	tok, exp, err := svc.issueIDToken(&domain.User{Id: "u1", Email: "u@x.com", Role: domain.RoleCompanyEmployee}, nil)
	if err != nil || tok == "" || exp != 3600 {
		t.Fatalf("unexpected token response: tok=%q exp=%d err=%v", tok, exp, err)
	}
	claims, err := utils.ParseToken(tok, "secret")
	if err != nil || claims["email"] != "u@x.com" {
		t.Fatalf("unexpected parsed claims: %+v err=%v", claims, err)
	}
	if claims["sub"] != "u1" {
		t.Fatalf("expected sub=u1, got %v", claims["sub"])
	}
	if claims["aud"] != "tikti" {
		t.Fatalf("expected aud=tikti, got %v", claims["aud"])
	}
	if claims["iss"] != "https://issuer" {
		t.Fatalf("expected iss=https://issuer, got %v", claims["iss"])
	}
	if claims["role"] != string(domain.RoleCompanyEmployee) {
		t.Fatalf("expected role=%s, got %v", domain.RoleCompanyEmployee, claims["role"])
	}
	if _, ok := claims["tid"]; ok {
		t.Fatalf("tid should be omitted when company id is empty")
	}

	tenantID := "tenant-1"
	tokWithTenant, _, err := svc.issueIDToken(&domain.User{
		Id:        "u2",
		Email:     "u2@x.com",
		Role:      domain.RoleCompanyEmployee,
		CompanyId: &tenantID,
	}, nil)
	if err != nil {
		t.Fatalf("issue id token with tenant: %v", err)
	}
	claimsWithTenant, err := utils.ParseToken(tokWithTenant, "secret")
	if err != nil {
		t.Fatalf("parse token with tenant: %v", err)
	}
	if claimsWithTenant["sub"] != "u2" {
		t.Fatalf("expected sub=u2, got %v", claimsWithTenant["sub"])
	}
	if claimsWithTenant["tid"] != "tenant-1" {
		t.Fatalf("expected tid=tenant-1, got %v", claimsWithTenant["tid"])
	}

	// getRSAPrivateKey caches errors
	bad := &userService{jwksPrivateKey: "bad-pem"}
	if _, err := bad.getRSAPrivateKey(); err == nil {
		t.Fatalf("expected parse error")
	}
	if _, err := bad.getRSAPrivateKey(); err == nil {
		t.Fatalf("expected cached parse error")
	}

	missing := &userService{}
	missing.rsaOnce.Do(func() { missing.rsaKey = nil })
	if _, err := missing.getRSAPrivateKey(); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected missing key error, got %v", err)
	}
}

func TestIDToken_AMR_Password(t *testing.T) {
	svc := NewUserService(&mockUserRepo{}, nil, nil, nil, "secret", "https://issuer", "tikti", makePEMKey(t), "kid").(*userService)

	// Password path: nil amr → token must not contain amr.
	tok, exp, err := svc.issueIDToken(&domain.User{Id: "u-pwd", Email: "pwd@example.com", Role: domain.RoleCompanyEmployee}, nil)
	if err != nil || tok == "" || exp != 3600 {
		t.Fatalf("unexpected: tok=%q exp=%d err=%v", tok, exp, err)
	}
	claims, err := utils.ParseToken(tok, "secret")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := claims["amr"]; ok {
		t.Fatalf("password path must not include amr claim, got %v", claims["amr"])
	}
	if claims["email"] != "pwd@example.com" {
		t.Fatalf("expected email=pwd@example.com, got %v", claims["email"])
	}
}

func TestIDToken_AMR_SAML(t *testing.T) {
	svc := NewUserService(&mockUserRepo{}, nil, nil, nil, "secret", "https://issuer", "tikti", makePEMKey(t), "kid").(*userService)

	// SAML path: amr=["saml"] → token must include that claim.
	tok, exp, err := svc.issueIDToken(&domain.User{Id: "u-saml", Email: "saml@example.com", Role: domain.RoleCompanyEmployee}, []string{"saml"})
	if err != nil || tok == "" || exp != 3600 {
		t.Fatalf("unexpected: tok=%q exp=%d err=%v", tok, exp, err)
	}
	claims, err := utils.ParseToken(tok, "secret")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	amrRaw, ok := claims["amr"]
	if !ok {
		t.Fatalf("expected amr claim to be present")
	}
	amrSlice, ok := amrRaw.([]interface{})
	if !ok {
		t.Fatalf("expected amr to be a slice, got %T", amrRaw)
	}
	if len(amrSlice) != 1 || amrSlice[0] != "saml" {
		t.Fatalf("expected amr=[saml], got %v", amrSlice)
	}
	if claims["email"] != "saml@example.com" {
		t.Fatalf("expected email=saml@example.com, got %v", claims["email"])
	}
}
