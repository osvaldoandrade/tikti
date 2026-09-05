package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/osvaldoandrade/tikti/internal/utils"
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

	user.AuthSource = domain.AuthSourcePassword
	response, err := service.TokenExchange(context.Background(), request)
	if err != nil {
		t.Fatalf("platform admin exchange: %v", err)
	}
	key, err := service.getRSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	claims, err := utils.ValidateRS256(response.AccessToken, &key.(*rsa.PrivateKey).PublicKey, "https://issuer", "code-admin")
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
	authority := homeAuthority(user, string(domain.RoleCompanyAdmin), []string{
		domain.PlatformTenantAdminScope, "code-admin:identity:write",
	})
	if len(authority) != 1 || authority[0] != "code-admin:identity:write" {
		t.Fatalf("tenant SAML authority escaped home boundary: %v", authority)
	}
}
