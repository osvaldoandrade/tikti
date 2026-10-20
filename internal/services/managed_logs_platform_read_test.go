package services

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const logsPlatformReadTestScope = "code-admin:logs:platform:read"

func TestManagedLogsPlatformReadCannotBeDelegatedByTenantRole(t *testing.T) {
	if _, ok := scopepolicy.CanonicalAudienceScopes([]string{logsPlatformReadTestScope}); !ok || !scopepolicy.RequiresHomeAuthority(logsPlatformReadTestScope) {
		t.Fatal("platform Logs scope is not registered as home authority")
	}
	if _, ok := scopepolicy.CanonicalPermissions([]string{logsPlatformReadTestScope}); ok || scopepolicy.TenantRoleAssignable(logsPlatformReadTestScope) {
		t.Fatal("tenant role can delegate platform Logs")
	}
}

func TestManagedLogsPlatformReadRejectsLegacyRoleExpansion(t *testing.T) {
	home := "conveste"
	u := &domain.User{Id: "tenant-reader", Email: "reader@example.test", Status: domain.UserStatusActive, Role: domain.RoleCompanyEmployee, CompanyId: &home, AuthSource: domain.AuthSourcePassword}
	s := NewUserService(&mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return u, nil }}, nil, &mockRoleService{resolvePermissionsFn: func(context.Context, string, []string) ([]string, error) {
		return []string{logsPlatformReadTestScope}, nil
	}}, &mockClientService{getClientFn: func(context.Context, string, string) (*domain.Client, error) {
		return &domain.Client{Id: domain.CodeAdminAudienceClientID, TenantId: home, Status: domain.ClientStatusActive, DefaultScopes: []string{logsPlatformReadTestScope}}, nil
	}}, "session-secret", "https://issuer", "tikti", makePEMKey(t), "kid")
	if token, err := s.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: signIDToken(t, "session-secret", u.Email), Audience: domain.CodeAdminAudienceClientID, TenantID: home, Scopes: []string{logsPlatformReadTestScope}}); err == nil || token != nil {
		t.Fatal("legacy role expansion promoted platform Logs scope")
	}
}

func TestManagedLogsPlatformAuthorityRequiresCurrentMasterSAMLAllowlist(t *testing.T) {
	home := domain.MasterTenantID
	u := &domain.User{Id: "ops", Email: "ops@example.test", CompanyId: &home, AuthSource: domain.AuthSourceSAML, ExternalSubject: "retained-idp-subject", Role: domain.RoleAdmin, Status: domain.UserStatusActive, TokenVersion: 3}
	key := currentPlatformAdministratorKey(home, u.Email)
	s := &userService{platformAuthorityConfigured: true, platformAdministrators: map[string]struct{}{key: {}}}
	claims := jwt.MapClaims{"tid": home, "role": "ADMIN", "ver": float64(3), domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin}
	if !s.managedLogsPlatformAuthority(context.Background(), u, claims) {
		t.Fatal("current MASTER SAML platform authority denied")
	}
	delete(s.platformAdministrators, key)
	if s.managedLogsPlatformAuthority(context.Background(), u, claims) {
		t.Fatal("removed SAML allowlist authority remained valid")
	}
	s.platformAdministrators[key] = struct{}{}
	home = "conveste"
	claims["tid"] = home
	s.platformAdministrators[currentPlatformAdministratorKey(home, u.Email)] = struct{}{}
	if s.managedLogsPlatformAuthority(context.Background(), u, claims) {
		t.Fatal("workload tenant SAML role promoted to platform reader")
	}
}

func TestManagedLogsPlatformReadRequiresExplicitScopeAndCurrentDirectMasterAuthority(t *testing.T) {
	ctx := context.Background()
	server := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })
	directory := repository.NewIdentityDirectoryRepository(redisClient)
	home := "conveste"
	u := &domain.User{Id: "platform-reader", Email: "reader@example.test", Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, Role: domain.RoleAdmin, CompanyId: &home}
	u.Password = "existing-test-password-hash"
	if err := repository.NewRedisRepo(redisClient).CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, _, err := directory.PutAccessAssignment(ctx, home, domain.AccessPrincipalUser, u.Id, []string{"reader"}, ""); err != nil {
		t.Fatal(err)
	}
	users := &mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return u, nil }}
	clients := &mockClientService{getClientFn: func(_ context.Context, tenant, audience string) (*domain.Client, error) {
		return &domain.Client{Id: audience, TenantId: tenant, Status: domain.ClientStatusActive, DefaultScopes: []string{logsPlatformReadTestScope}}, nil
	}}
	s := NewUserService(users, nil, nil, clients, "session-secret", "https://issuer", "tikti", makePEMKey(t), "kid", WithIdentityDirectoryAccess(directory)).(*userService)
	request := domain.TokenExchangeReq{IdToken: signIDToken(t, "session-secret", u.Email), Audience: domain.CodeAdminAudienceClientID, TenantID: home, Scopes: []string{logsPlatformReadTestScope}}
	if _, err := s.TokenExchange(ctx, request); err == nil {
		t.Fatal("ADMIN role alone granted platform Logs")
	}
	if _, _, err := directory.PutAccessAssignment(ctx, domain.MasterTenantID, domain.AccessPrincipalUser, u.Id, []string{"ADMIN"}, ""); err != nil {
		t.Fatal(err)
	}
	// The platform assignment authorizes an explicitly requested and bounded
	// scope; it does not add the scope to a caller's request implicitly.
	issued, err := s.TokenExchange(ctx, request)
	if err != nil {
		t.Fatalf("explicit platform reader refused: %v", err)
	}
	request.Scopes = nil
	if _, err := s.TokenExchange(ctx, request); err == nil {
		t.Fatal("client defaults implicitly granted platform Logs")
	}
	request.Scopes = []string{logsPlatformReadTestScope}
	u.Role = domain.RoleCompanyAdmin
	if _, err := s.TokenExchange(ctx, request); err == nil {
		t.Fatal("tenant company-admin inherited platform Logs")
	}
	u.Role = domain.RoleAdmin
	assignment, err := directory.GetAccessAssignment(ctx, domain.MasterTenantID, domain.AccessPrincipalUser, u.Id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = directory.DeleteAccessAssignment(ctx, domain.MasterTenantID, domain.AccessPrincipalUser, u.Id, repository.IdentityETag(assignment.Version)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.TokenExchange(ctx, request); err == nil {
		t.Fatal("removed platform assignment still authorized issuance")
	}
	if _, err = s.ValidateAccessToken(ctx, issued.AccessToken, "https://issuer", domain.CodeAdminAudienceClientID); err == nil {
		t.Fatal("removed platform authority still accepted bearer")
	}
}
