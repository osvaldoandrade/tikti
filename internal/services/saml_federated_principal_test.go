package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestTenantLocalSAMLPrincipalCannotHijackGlobalEmailAndCompletesHomeExchange(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	users := repository.NewRedisRepo(client)
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password-1234"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	home := "bereia"
	global := &domain.User{
		Id: "global-victim", Email: "victim@example.com", Password: string(passwordHash),
		Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive,
		AuthSource: domain.AuthSourcePassword, CompanyId: &home, CreatedAt: time.Now().UTC(),
	}
	if err := users.CreateUser(ctx, global); err != nil {
		t.Fatal(err)
	}
	federated, created, err := users.UpsertFromSAML(
		ctx, home, "idp-controlled-subject", global.Email, "Victim", []string{"COMPANY_ADMIN"}, domain.MergeStrategyEmail,
	)
	if err != nil || !created || federated.Id == global.Id {
		t.Fatalf("federated principal=%#v created=%t err=%v", federated, created, err)
	}
	canonical, err := users.FindByEmail(ctx, global.Email)
	if err != nil || canonical == nil || canonical.Id != global.Id || canonical.AuthSource != domain.AuthSourcePassword {
		t.Fatalf("global identity was changed: user=%#v err=%v", canonical, err)
	}

	tenants := repository.NewTenantRepo(client)
	if err := tenants.Create(ctx, &domain.Tenant{Id: home, Slug: home, Name: "Bereia", Status: domain.TenantStatusActive}); err != nil {
		t.Fatal(err)
	}
	tokens := NewUserService(
		users, nil, nil, discoveryClientService(t, false),
		"jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithTenantTargetDiscoveryV2(true, []string{domain.MasterTenantID}, tenants),
	).(*userService)
	idToken, _, err := tokens.IssueIDTokenWithAMR(&federated, []string{"saml"}, "")
	if err != nil {
		t.Fatal(err)
	}
	request := domain.TokenExchangeReq{
		IdToken: idToken, Audience: domain.CodeAdminAudienceClientID, TenantID: home,
		DiscoverTenantTargetsV2: true, ScopeCeilingV1: append([]string(nil), managedAudienceScopes...),
		Scopes: []string{"code-admin:workloads:read"}, TTLSeconds: 300,
	}
	exchange, err := tokens.TokenExchange(ctx, request)
	if err != nil || exchange == nil || exchange.PrincipalTenantID != home {
		t.Fatalf("home exchange=%#v err=%v", exchange, err)
	}
	key, err := tokens.getRSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	claims, err := tokens.ValidateAccessToken(ctx, exchange.AccessToken, "https://issuer", domain.CodeAdminAudienceClientID)
	if err != nil || claims["sub"] != federated.Id || claims["principal_tid"] != home {
		t.Fatalf("federated access claims=%v err=%v", claims, err)
	}
	if _, err := utils.ValidateRS256(exchange.AccessToken, &key.(*rsa.PrivateKey).PublicKey, "https://issuer", domain.CodeAdminAudienceClientID); err != nil {
		t.Fatal(err)
	}
	if err := tenants.Create(ctx, &domain.Tenant{Id: home, Slug: home, Name: "Bereia", Status: domain.TenantStatusDisabled}); err != nil {
		t.Fatal(err)
	}
	if claims, validateErr := tokens.ValidateIDToken(ctx, idToken, "https://issuer", "tikti"); !errors.Is(validateErr, domain.ErrInvalidToken) || claims != nil {
		t.Fatalf("SAML browser session remained valid after tenant disable: claims=%v err=%v", claims, validateErr)
	}
	if err := tenants.Create(ctx, &domain.Tenant{Id: home, Slug: home, Name: "Bereia", Status: domain.TenantStatusActive}); err != nil {
		t.Fatal(err)
	}

	request.TenantID = "storifly"
	if result, crossErr := tokens.TokenExchange(ctx, request); !errors.Is(crossErr, domain.ErrInvalidTenant) || result != nil {
		t.Fatalf("cross-home exchange=%#v err=%v", result, crossErr)
	}
	if err := tokens.DeleteUser(ctx, domain.DeleteReq{IdToken: idToken}); !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("federated self-delete=%v", err)
	}
	canonical, err = users.FindByEmail(ctx, global.Email)
	if err != nil || canonical == nil || canonical.Id != global.Id {
		t.Fatalf("self-delete affected global identity: user=%#v err=%v", canonical, err)
	}
	downgraded, wasCreated, err := users.UpsertFromSAML(
		ctx, home, federated.ExternalSubject, federated.Email, "Victim", []string{"COMPANY_EMPLOYEE"}, domain.MergeStrategyExternalSubject,
	)
	if err != nil || wasCreated || downgraded.Role != domain.RoleCompanyEmployee || downgraded.TokenVersion != federated.TokenVersion+1 {
		t.Fatalf("SAML role downgrade=%#v created=%t err=%v", downgraded, wasCreated, err)
	}
	if _, err := tokens.ValidateAccessToken(ctx, exchange.AccessToken, "https://issuer", domain.CodeAdminAudienceClientID); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("pre-downgrade access token remained valid: %v", err)
	}
	if err := tokens.RevokeIDTokenSubject(ctx, federated.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.ValidateAccessToken(ctx, exchange.AccessToken, "https://issuer", domain.CodeAdminAudienceClientID); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("revoked federated access token remained valid: %v", err)
	}
}

func TestMasterSAMLPlatformAdministratorDiscoversWorkloadsOnlyWithProvenance(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	users := repository.NewRedisRepo(client)
	tenants := repository.NewTenantRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	for _, tenant := range []*domain.Tenant{
		{Id: domain.MasterTenantID, Slug: domain.MasterTenantID, Name: domain.MasterTenantName, Status: domain.TenantStatusActive},
		{Id: "bereia", Slug: "bereia", Name: "Bereia", Status: domain.TenantStatusActive},
	} {
		if err := tenants.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	principal, _, err := users.UpsertFromSAML(
		ctx, domain.MasterTenantID, "master-idp-subject", "owner@example.com", "Owner", []string{"ADMIN"}, domain.MergeStrategyExternalSubject,
	)
	if err != nil {
		t.Fatal(err)
	}
	principal.Role = domain.RoleAdmin
	if err := users.UpdateUser(ctx, &principal); err != nil {
		t.Fatalf("persist platform role: %v", err)
	}

	tokens := NewUserService(
		users, nil, nil, discoveryClientService(t, false),
		"jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithTenantTargetDiscoveryV2(true, []string{domain.MasterTenantID}, tenants),
		WithCurrentPlatformAdministrators([]config.SAMLPlatformAdministrator{{
			TenantID: domain.MasterTenantID, Email: principal.Email,
		}}),
		WithIdentityDirectoryAccess(directory),
	).(*userService)
	request := domain.TokenExchangeReq{
		Audience: domain.CodeAdminAudienceClientID, TenantID: "bereia", DiscoverTenantTargetsV2: true,
		ScopeCeilingV1: append([]string(nil), managedAudienceScopes...),
		Scopes:         []string{"code-admin:workloads:read"}, TTLSeconds: 300,
	}

	request.IdToken, _, err = tokens.IssueIDTokenWithAMR(&principal, []string{"saml"}, domain.PlatformPrivilegeAdmin)
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := tokens.TokenExchange(ctx, request)
	if err != nil || exchange == nil || exchange.PrincipalTenantID != domain.MasterTenantID ||
		!slices.Equal(exchange.AuthorizedTenants, []string{"bereia", domain.MasterTenantID}) {
		t.Fatalf("provenance-bound platform exchange=%#v err=%v", exchange, err)
	}
	key, keyErr := tokens.getRSAPrivateKey()
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	rawClaims, rawErr := utils.ValidateRS256(exchange.AccessToken, &key.(*rsa.PrivateKey).PublicKey, "https://issuer", domain.CodeAdminAudienceClientID)
	if rawErr != nil {
		t.Fatal(rawErr)
	}
	claims, err := tokens.ValidateAccessToken(ctx, exchange.AccessToken, "https://issuer", domain.CodeAdminAudienceClientID)
	if err != nil || claims[domain.PlatformPrivilegeClaim] != nil || claims["tid"] != "bereia" || claims["principal_tid"] != domain.MasterTenantID {
		t.Fatalf("platform access claims=%v raw=%v err=%v", claims, rawClaims, err)
	}

	request.IdToken, _, err = tokens.IssueIDTokenWithAMR(&principal, []string{"saml"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if ordinary, ordinaryErr := tokens.TokenExchange(ctx, request); !errors.Is(ordinaryErr, domain.ErrInvalidTenant) || ordinary != nil {
		t.Fatalf("unprovenanced SAML principal crossed tenant: response=%#v err=%v", ordinary, ordinaryErr)
	}
}
