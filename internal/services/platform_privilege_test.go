package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestPlatformPrivilegeIssuanceRequiresStoredAdmin(t *testing.T) {
	tenantID := "home"
	user := &domain.User{
		Id: "user-1", Email: "operator@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleCompanyAdmin, CompanyId: &tenantID,
	}
	users := &mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) {
		return user, nil
	}}
	memberships := &mockMembershipRepo{listTenantIDsByUser: func(context.Context, string) ([]string, error) {
		return []string{tenantID}, nil
	}}
	service := NewUserService(users, memberships, nil, nil, "secret", "https://issuer", "tikti", makePEMKey(t), "kid").(*userService)
	request := domain.TokenExchangeReq{
		IdToken: signIDToken(t, "secret", user.Email), Audience: "code-admin", TenantID: tenantID,
		Scopes: []string{domain.PlatformTenantAdminScope},
	}
	if response, err := service.TokenExchange(context.Background(), request); response != nil || !errors.Is(err, domain.ErrUnauthorizedScope) {
		t.Fatalf("company admin global exchange = %+v, %v", response, err)
	}

	user.Role = domain.RoleAdmin
	user.AuthSource = domain.AuthSourceSAML
	if response, err := service.TokenExchange(context.Background(), request); response != nil || !errors.Is(err, domain.ErrUnauthorizedScope) {
		t.Fatalf("tenant SAML ADMIN global exchange = %+v, %v", response, err)
	}

	trustedIDToken, _, err := service.IssueIDTokenWithAMR(user, []string{"saml"}, domain.PlatformPrivilegeAdmin)
	if err != nil {
		t.Fatalf("issue trusted SAML platform administrator id token: %v", err)
	}
	request.IdToken = trustedIDToken
	response, err := service.TokenExchange(context.Background(), request)
	if err != nil {
		t.Fatalf("trusted SAML platform administrator exchange: %v", err)
	}
	key, err := service.getRSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	claims, err := utils.ValidateRS256(response.AccessToken, &key.(*rsa.PrivateKey).PublicKey, "https://issuer", "code-admin")
	if err != nil || claims["role"] != string(domain.RoleAdmin) || claims["scope"] != domain.PlatformTenantAdminScope ||
		claims[domain.PlatformPrivilegeClaim] != domain.PlatformPrivilegeAdmin {
		t.Fatalf("trusted SAML platform privilege claims = %v, %v", claims, err)
	}

	user.AuthSource = domain.AuthSourcePassword
	request.IdToken = signIDToken(t, "secret", user.Email)
	response, err = service.TokenExchange(context.Background(), request)
	if err != nil {
		t.Fatalf("platform admin exchange: %v", err)
	}
	claims, err = utils.ValidateRS256(response.AccessToken, &key.(*rsa.PrivateKey).PublicKey, "https://issuer", "code-admin")
	if err != nil || claims["role"] != string(domain.RoleAdmin) || claims["scope"] != domain.PlatformTenantAdminScope ||
		claims[domain.PlatformPrivilegeClaim] != domain.PlatformPrivilegeAdmin {
		t.Fatalf("platform privilege claims = %v, %v", claims, err)
	}
}

func TestTenantSAMLAdminCannotReuseStalePlatformRoleInDiscovery(t *testing.T) {
	tenantID := "home"
	user := &domain.User{
		Id: "saml-user", Email: "saml@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleAdmin, AuthSource: domain.AuthSourceSAML, CompanyId: &tenantID,
	}
	if validSignedHome(user, tenantID, string(domain.RoleAdmin)) {
		t.Fatal("stale tenant SAML ADMIN token retained platform home authority")
	}
	if !validSignedHome(user, tenantID, string(domain.RoleCompanyAdmin)) {
		t.Fatal("effective tenant SAML role was not accepted")
	}
	if !validSignedHome(user, tenantID, string(domain.RoleAdmin), domain.PlatformPrivilegeAdmin) {
		t.Fatal("trusted SAML platform administrator provenance was not accepted")
	}
	authority := homeAuthority(user, string(domain.RoleCompanyAdmin), []string{
		domain.PlatformTenantAdminScope, "code-admin:identity:write",
	})
	if len(authority) != 1 || authority[0] != "code-admin:identity:write" {
		t.Fatalf("tenant SAML authority escaped home boundary: %v", authority)
	}
	platformAuthority := homeAuthority(user, string(domain.RoleAdmin), []string{
		domain.PlatformTenantAdminScope, "code-admin:identity:write",
	}, domain.PlatformPrivilegeAdmin)
	if len(platformAuthority) != 2 {
		t.Fatalf("trusted SAML platform authority = %v", platformAuthority)
	}
}

func TestPlatformAdministratorAllowlistRemovalRevokesExistingTokens(t *testing.T) {
	tenantID := domain.MasterTenantID
	user := &domain.User{
		Id: "platform-user", Email: "owner@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleAdmin, AuthSource: domain.AuthSourceSAML, CompanyId: &tenantID, TokenVersion: 4,
	}
	users := &mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) {
		copy := *user
		return &copy, nil
	}}
	memberships := &mockMembershipRepo{listTenantIDsByUser: func(context.Context, string) ([]string, error) {
		return []string{tenantID}, nil
	}}
	privateKey := makePEMKey(t)
	configured := []config.SAMLPlatformAdministrator{{TenantID: tenantID, Email: user.Email}}
	service := NewUserService(
		users, memberships, nil, nil, "secret", "https://issuer", "tikti", privateKey, "kid",
		WithCurrentPlatformAdministrators(configured),
	).(*userService)
	idToken, _, err := service.IssueIDTokenWithAMR(user, []string{"saml"}, domain.PlatformPrivilegeAdmin)
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := service.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken: idToken, Audience: "code-admin", TenantID: tenantID,
		Scopes: []string{domain.PlatformTenantAdminScope},
	})
	if err != nil || exchange == nil {
		t.Fatalf("allowlisted exchange=%#v err=%v", exchange, err)
	}
	if _, err := service.ValidateAccessToken(context.Background(), exchange.AccessToken, "https://issuer", "code-admin"); err != nil {
		t.Fatalf("allowlisted access token rejected: %v", err)
	}

	revoked := NewUserService(
		users, memberships, nil, nil, "secret", "https://issuer", "tikti", privateKey, "kid",
		WithCurrentPlatformAdministrators(nil),
	).(*userService)
	if _, err := revoked.ValidateIDToken(context.Background(), idToken, "https://issuer", "tikti"); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("removed administrator ID token remained valid: %v", err)
	}
	if result, err := revoked.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken: idToken, Audience: "code-admin", TenantID: tenantID,
		Scopes: []string{domain.PlatformTenantAdminScope},
	}); result != nil || !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("removed administrator exchanged token: result=%#v err=%v", result, err)
	}
	if _, err := revoked.ValidateAccessToken(context.Background(), exchange.AccessToken, "https://issuer", "code-admin"); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("removed administrator access token remained valid: %v", err)
	}
}
