package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"slices"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestPasswordAdministratorDirectMasterAssignmentProvidesRevocablePlatformAuthority(t *testing.T) {
	ctx := context.Background()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	users := repository.NewRedisRepo(client)
	tenants := repository.NewTenantRepo(client)
	roles := repository.NewRoleRepo(client)
	clients := repository.NewClientRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	home := "conveste"
	user := &domain.User{
		Id: "existing-admin", Email: "admin@example.com", Password: "stored-password-hash",
		Role: domain.RoleAdmin, Status: domain.UserStatusActive, CompanyId: &home,
		AuthSource: domain.AuthSourcePassword, TokenVersion: 3,
	}
	if err := users.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	for _, tenantID := range []string{home, domain.MasterTenantID} {
		if err := tenants.Create(ctx, &domain.Tenant{
			Id: tenantID, Slug: tenantID, Name: tenantID, Status: domain.TenantStatusActive,
		}); err != nil {
			t.Fatal(err)
		}
	}
	roleScopes, valid := scopepolicy.CanonicalPermissions([]string{
		"code-admin:services:read", "code-admin:workloads:read",
	})
	if !valid {
		t.Fatal("MASTER role fixture is invalid")
	}
	if err := roles.Create(ctx, domain.MasterTenantID, &domain.Role{
		Name: "ADMIN", Scope: domain.RoleScopeTenant, TenantId: domain.MasterTenantID,
		Permissions: roleScopes,
	}); err != nil {
		t.Fatal(err)
	}
	assignment, _, err := directory.PutAccessAssignment(
		ctx, domain.MasterTenantID, domain.AccessPrincipalUser, user.Id, []string{"ADMIN"}, "",
	)
	if err != nil {
		t.Fatal(err)
	}
	audienceScopes, valid := scopepolicy.CanonicalAudienceScopes([]string{
		"code-admin:clusters:read", "code-admin:identity:read", "code-admin:services:read",
		domain.PlatformTenantAdminScope, "code-admin:workloads:read",
	})
	if !valid {
		t.Fatal("MASTER audience fixture is invalid")
	}
	if _, _, err = clients.EnsureManagedAudience(ctx, domain.MasterTenantID, &domain.Client{
		Id: domain.CodeAdminAudienceClientID, TenantId: domain.MasterTenantID,
		Type: domain.ClientTypeService, Status: domain.ClientStatusActive,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     audienceScopes, ManagedBy: domain.CodeAdminAudienceClientManager,
	}); err != nil {
		t.Fatal(err)
	}
	homeAudienceScopes, valid := scopepolicy.CanonicalAudienceScopes([]string{
		"code-admin:clusters:read", "code-admin:services:read", "code-admin:workloads:read",
	})
	if !valid {
		t.Fatal("workload audience fixture is invalid")
	}
	if _, _, err = clients.EnsureManagedAudience(ctx, home, &domain.Client{
		Id: domain.CodeAdminAudienceClientID, TenantId: home,
		Type: domain.ClientTypeService, Status: domain.ClientStatusActive,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     homeAudienceScopes, ManagedBy: domain.CodeAdminAudienceClientManager,
	}); err != nil {
		t.Fatal(err)
	}

	service := NewUserService(
		users, nil, NewRoleService(roles), NewClientService(clients),
		"jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithIdentityDirectoryAccess(directory),
		WithTenantTargetDiscoveryV2(true, []string{domain.MasterTenantID}, tenants),
	).(*userService)
	idToken := signTenantHomeTokenForTenant(t, "jwt-secret", user, domain.RoleAdmin, home)
	exchange, err := service.TokenExchange(ctx, domain.TokenExchangeReq{
		IdToken: idToken, Audience: domain.CodeAdminAudienceClientID,
		TenantID: domain.MasterTenantID, DiscoverTenantTargetsV2: true,
		ScopeCeilingV1: audienceScopes, TTLSeconds: 300,
	})
	if err != nil {
		t.Fatalf("MASTER exchange: %v", err)
	}
	if exchange.PrincipalTenantID != domain.MasterTenantID ||
		!slices.Equal(exchange.AuthorizedTenants, []string{home, domain.MasterTenantID}) ||
		!slices.Contains(exchange.Scopes, domain.PlatformTenantAdminScope) {
		t.Fatalf("unexpected MASTER authority: principal=%q tenants=%v scopes=%v",
			exchange.PrincipalTenantID, exchange.AuthorizedTenants, exchange.Scopes)
	}
	key, err := service.getRSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	claims, err := utils.ValidateRS256(
		exchange.AccessToken, &key.(*rsa.PrivateKey).PublicKey,
		"https://issuer", domain.CodeAdminAudienceClientID,
	)
	if err != nil || claims["tid"] != domain.MasterTenantID ||
		claims["principal_tid"] != domain.MasterTenantID || claims["role"] != string(domain.RoleAdmin) ||
		claims[domain.PlatformPrivilegeClaim] != domain.PlatformPrivilegeAdmin ||
		!slices.Equal(claims["roles"].([]interface{}), []interface{}{"ADMIN"}) {
		t.Fatalf("unexpected MASTER claims=%v err=%v", claims, err)
	}
	if _, err = service.ValidateAccessToken(
		ctx, exchange.AccessToken, "https://issuer", domain.CodeAdminAudienceClientID,
	); err != nil {
		t.Fatalf("current MASTER token rejected: %v", err)
	}
	homeExchange, err := service.TokenExchange(ctx, domain.TokenExchangeReq{
		IdToken: idToken, Audience: domain.CodeAdminAudienceClientID,
		TenantID: home, DiscoverTenantTargetsV2: true,
		ScopeCeilingV1: audienceScopes, TTLSeconds: 300,
	})
	if err != nil {
		t.Fatalf("workload-home exchange: %v", err)
	}
	if homeExchange.PrincipalTenantID != domain.MasterTenantID ||
		!slices.Equal(homeExchange.Scopes, homeAudienceScopes) {
		t.Fatalf("workload-home exchange lost MASTER identity principal: principal=%q scopes=%v",
			homeExchange.PrincipalTenantID, homeExchange.Scopes)
	}

	group, err := directory.CreateGroup(ctx, "master-admins", "inherited role must not elevate")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = directory.PutGroupMember(ctx, group.ID, user.Id, repository.IdentityETag(group.Version)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = directory.PutAccessAssignment(
		ctx, domain.MasterTenantID, domain.AccessPrincipalGroup, group.ID, []string{"ADMIN"}, "",
	); err != nil {
		t.Fatal(err)
	}
	deleted, err := directory.DeleteAccessAssignment(
		ctx, domain.MasterTenantID, domain.AccessPrincipalUser, user.Id,
		repository.IdentityETag(assignment.Version),
	)
	if err != nil || !deleted {
		t.Fatalf("remove MASTER assignment: deleted=%t err=%v", deleted, err)
	}
	if _, err = service.ValidateAccessToken(
		ctx, exchange.AccessToken, "https://issuer", domain.CodeAdminAudienceClientID,
	); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("revoked MASTER authority remained valid: %v", err)
	}
	inherited, err := service.TokenExchange(ctx, domain.TokenExchangeReq{
		IdToken: idToken, Audience: domain.CodeAdminAudienceClientID,
		TenantID: domain.MasterTenantID, DiscoverTenantTargetsV2: true,
		ScopeCeilingV1: audienceScopes, TTLSeconds: 300,
	})
	if err != nil {
		t.Fatalf("inherited MASTER exchange: %v", err)
	}
	if inherited.PrincipalTenantID != home {
		t.Fatalf("inherited ADMIN became platform principal: %q", inherited.PrincipalTenantID)
	}
	inheritedClaims, err := utils.ValidateRS256(
		inherited.AccessToken, &key.(*rsa.PrivateKey).PublicKey,
		"https://issuer", domain.CodeAdminAudienceClientID,
	)
	if err != nil || inheritedClaims["role"] != nil || inheritedClaims[domain.PlatformPrivilegeClaim] != nil {
		t.Fatalf("inherited ADMIN gained platform claims: role=%v privilege=%v err=%v",
			inheritedClaims["role"], inheritedClaims[domain.PlatformPrivilegeClaim], err)
	}
}
