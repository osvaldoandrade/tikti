package services

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestManagedLogsPlatformReadDiscoveryV2(t *testing.T) {
	for _, scenario := range []string{
		"current SAML platform administrator", "tenant SAML administrator",
		"MASTER SAML without provenance", "ceiling excludes platform logs",
		"client excludes platform logs", "other tenant selected", "explicit unauthorized scope",
	} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			server := miniredis.RunT(t)
			redisClient := redis.NewClient(&redis.Options{Addr: server.Addr()})
			t.Cleanup(func() { _ = redisClient.Close() })
			users := repository.NewRedisRepo(redisClient)
			tenants := repository.NewTenantRepo(redisClient)
			for _, tenantID := range []string{domain.MasterTenantID, "conveste"} {
				if err := tenants.Create(ctx, &domain.Tenant{Id: tenantID, Slug: tenantID, Name: tenantID, Status: domain.TenantStatusActive}); err != nil {
					t.Fatal(err)
				}
			}
			home, role, privilege := domain.MasterTenantID, domain.RoleAdmin, domain.PlatformPrivilegeAdmin
			if scenario == "tenant SAML administrator" || scenario == "explicit unauthorized scope" {
				home, role, privilege = "conveste", domain.RoleCompanyAdmin, ""
			} else if scenario == "MASTER SAML without provenance" {
				privilege = ""
			}
			user, _, err := users.UpsertFromSAML(ctx, home, "logs-reader", "reader@example.test", "Reader", []string{string(role)}, domain.MergeStrategyExternalSubject)
			if err != nil {
				t.Fatal(err)
			}
			user.Role = role
			if err = users.UpdateUser(ctx, &user); err != nil {
				t.Fatal(err)
			}
			// The Console discovers scopes with an empty Scopes field and a full
			// ceiling, including its existing platform-administration capability.
			audienceScopes, valid := scopepolicy.CanonicalAudienceScopes(append(
				append([]string(nil), productionBootstrapHomeScopes...), logsPlatformReadTestScope,
			))
			if !valid {
				t.Fatal("invalid scope fixture")
			}
			clientScopes := append([]string(nil), audienceScopes...)
			if scenario == "client excludes platform logs" {
				clientScopes = slices.DeleteFunc(clientScopes, func(scope string) bool { return scope == logsPlatformReadTestScope })
			}
			clients := &mockClientService{getClientFn: func(_ context.Context, tenant, audience string) (*domain.Client, error) {
				return &domain.Client{Id: audience, TenantId: tenant, Type: domain.ClientTypeService, Status: domain.ClientStatusActive,
					AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)}, ManagedBy: domain.CodeAdminAudienceClientManager,
					DefaultScopes: append([]string(nil), clientScopes...)}, nil
			}}
			service := NewUserService(users, nil, nil, clients, "session-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
				WithTenantTargetDiscoveryV2(true, []string{domain.MasterTenantID}, tenants),
				WithIdentityDirectoryAccess(repository.NewIdentityDirectoryRepository(redisClient)),
				WithCurrentPlatformAdministrators([]config.SAMLPlatformAdministrator{{TenantID: domain.MasterTenantID, Email: user.Email}}),
			).(*userService)
			idToken, _, err := service.IssueIDTokenWithAMR(&user, []string{"saml"}, privilege)
			if err != nil {
				t.Fatal(err)
			}
			request := domain.TokenExchangeReq{IdToken: idToken, Audience: domain.CodeAdminAudienceClientID,
				TenantID: home, DiscoverTenantTargetsV2: true, ScopeCeilingV1: append([]string(nil), audienceScopes...), TTLSeconds: 300}
			if scenario == "ceiling excludes platform logs" {
				request.ScopeCeilingV1 = slices.DeleteFunc(request.ScopeCeilingV1, func(scope string) bool { return scope == logsPlatformReadTestScope })
			} else if scenario == "other tenant selected" {
				request.TenantID = "conveste"
			} else if scenario == "explicit unauthorized scope" {
				request.Scopes = []string{logsPlatformReadTestScope}
			}
			response, err := service.TokenExchange(ctx, request)
			if scenario == "explicit unauthorized scope" {
				if !errors.Is(err, domain.ErrUnauthorizedScope) || response != nil {
					t.Fatalf("explicit unauthorized scope: response present=%t err=%v", response != nil, err)
				}
				return
			}
			if err != nil || response == nil {
				t.Fatalf("discovery login failed: %v", err)
			}
			wantPlatform := scenario == "current SAML platform administrator"
			if slices.Contains(response.Scopes, logsPlatformReadTestScope) != wantPlatform || !slices.Contains(response.Scopes, "code-admin:logs:read") {
				t.Fatalf("unexpected discovery scopes: %v", response.Scopes)
			}
			claims, err := service.ValidateAccessToken(ctx, response.AccessToken, "https://issuer", domain.CodeAdminAudienceClientID)
			if err != nil || slices.Contains(strings.Fields(claimStringValue(claims, "scope")), logsPlatformReadTestScope) != wantPlatform {
				t.Fatalf("discovered token failed current-authority validation: %v", err)
			}
			if wantPlatform {
				if response.PrincipalTenantID != domain.MasterTenantID || claims["tid"] != domain.MasterTenantID || claims["principal_tid"] != domain.MasterTenantID {
					t.Fatal("platform discovery escaped its principal tenant")
				}
				delete(service.platformAdministrators, currentPlatformAdministratorKey(home, user.Email))
				if denied, err := service.TokenExchange(ctx, request); !errors.Is(err, domain.ErrInvalidToken) || denied != nil {
					t.Fatalf("revoked SAML authority still issued a token: %v", err)
				}
				if _, err = service.ValidateAccessToken(ctx, response.AccessToken, "https://issuer", domain.CodeAdminAudienceClientID); !errors.Is(err, domain.ErrInvalidToken) {
					t.Fatalf("revoked SAML authority retained the issued token: %v", err)
				}
			}
		})
	}
}
