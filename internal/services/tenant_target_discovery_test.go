package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

var managedAudienceScopes = []string{
	"code-admin:clusters:read",
	"code-admin:services:read",
	"code-admin:services:write",
	"code-admin:workloads:read",
	"code-admin:workloads:write",
	"console:clusters:read",
}

// productionBootstrapHomeScopes mirrors the existing values-prod bootstrap
// order, which is intentionally not canonical storage order.
var productionBootstrapHomeScopes = []string{
	"code-admin:services:read", "code-admin:services:write",
	"code-admin:workloads:read", "code-admin:workloads:write",
	"code-admin:queues:read", "code-admin:queues:write",
	"code-admin:repositories:read", "code-admin:repositories:write", "code-admin:repositories:admin",
	"code-admin:storage:read", "code-admin:storage:write",
	"code-admin:secrets:read", "code-admin:secrets:write",
	"code-admin:clusters:read", "code-admin:clusters:admin",
	"code-admin:platform:read", "code-admin:platform:admin",
	"code-admin:tenants:read", "code-admin:tenants:admin",
	"code-admin:subscriptions:read", "code-admin:subscriptions:admin",
	"code-admin:environments:read", "code-admin:environments:admin",
	"code-admin:bindings:read", "code-admin:bindings:write",
	"code-admin:quotas:read", "code-admin:quotas:write",
	"code-admin:policies:read", "code-admin:policies:write",
	"code-admin:operations:read", "code-admin:operations:write",
	"code-admin:deployments:read", "code-admin:deployments:write",
	"code-admin:deployments:approve", "code-admin:deployments:rollback",
	"code-admin:explorer:read",
	"code-admin:yaml:read", "code-admin:yaml:write",
	"code-admin:logs:read", "code-admin:metrics:read",
	"code-admin:observability:read", "code-admin:observability:write",
	"code-admin:identity:read", "code-admin:identity:write",
	"code-admin:audit:read", "code-admin:audit:write",
	"code-admin:features:read", "code-admin:features:write",
}

func TestTenantTargetDiscovery_RequiresExactBereiaMembership(t *testing.T) {
	service, idToken := newTenantTargetDiscoveryService(t, "", nil, domain.RoleAdmin)
	response, err := service.TokenExchange(context.Background(), tenantTargetRequest(idToken, "bereia"))
	if !errors.Is(err, domain.ErrInvalidTenant) || response != nil {
		t.Fatalf("membership-free exchange response=%+v err=%v", response, err)
	}
}

func TestTenantTargetDiscovery_RequiresCurrentTokenVersionBeforeDiscovery(t *testing.T) {
	service, _ := newTenantTargetDiscoveryService(
		t, "bereia-read", []string{"code-admin:workloads:read"}, domain.RoleAdmin,
	)
	service.exactMembershipRepo = &mockMembershipRepo{listExactFn: func(context.Context, string) ([]string, error) {
		t.Fatal("invalid token version reached tenant discovery")
		return nil, nil
	}}
	user := &domain.User{Id: "user-1", Email: "user@example.com", TokenVersion: 3}
	for name, version := range map[string]any{
		"stale": float64(2), "missing": nil, "malformed": "3",
	} {
		t.Run(name, func(t *testing.T) {
			idToken := signTenantHomeTokenVersion(t, "secret", user, domain.RoleAdmin, version)
			response, err := service.TokenExchange(context.Background(), tenantTargetRequest(idToken, "bereia"))
			if !errors.Is(err, domain.ErrInvalidToken) || response != nil {
				t.Fatalf("invalid version response=%+v err=%v", response, err)
			}
		})
	}
}

func TestTenantTargetDiscovery_RoleProfilesPreserveHomeGlobalScopes(t *testing.T) {
	profiles := []struct {
		role        string
		permissions []string
		wantScopes  []string
	}{
		{
			role: "bereia-read", permissions: []string{"code-admin:workloads:read"},
			wantScopes: []string{"code-admin:clusters:read", "code-admin:workloads:read", "console:clusters:read"},
		},
		{
			role: "bereia-write", permissions: []string{"code-admin:workloads:read", "code-admin:workloads:write"},
			wantScopes: []string{"code-admin:clusters:read", "code-admin:workloads:read", "code-admin:workloads:write", "console:clusters:read"},
		},
		{
			role: "bereia-admin",
			permissions: []string{
				"code-admin:services:read", "code-admin:services:write",
				"code-admin:workloads:read", "code-admin:workloads:write",
			},
			wantScopes: append([]string(nil), managedAudienceScopes...),
		},
	}
	for _, profile := range profiles {
		t.Run(profile.role, func(t *testing.T) {
			service, idToken := newTenantTargetDiscoveryService(t, profile.role, profile.permissions, domain.RoleAdmin)
			response, err := service.TokenExchange(context.Background(), tenantTargetRequest(idToken, "bereia"))
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			if response.PrincipalTenantID != "local-tenant" ||
				!slices.Equal(response.AuthorizedTenants, []string{"bereia", "local-tenant"}) ||
				!slices.Equal(response.Scopes, profile.wantScopes) {
				t.Fatalf("unexpected response: %+v", response)
			}
			key, _ := service.getRSAPrivateKey()
			claims, err := utils.ValidateRS256(
				response.AccessToken, &key.(*rsa.PrivateKey).PublicKey, "https://issuer", domain.CodeAdminAudienceClientID,
			)
			if err != nil || claims["tid"] != "bereia" || claims["role"] != nil ||
				!reflect.DeepEqual(claims["roles"], []interface{}{profile.role}) ||
				claims["scope"] != strings.Join(profile.wantScopes, " ") {
				t.Fatalf("unexpected claims=%v err=%v", claims, err)
			}
		})
	}
}

func TestTenantTargetDiscovery_CanReturnToSignedHomeTenant(t *testing.T) {
	service, idToken := newTenantTargetDiscoveryService(
		t, "bereia-read", []string{"code-admin:workloads:read"}, domain.RoleAdmin,
	)
	service.clientSvc = discoveryClientService(t, true)
	if bereia, exchangeErr := service.TokenExchange(context.Background(), tenantTargetRequest(idToken, "bereia")); exchangeErr != nil || bereia == nil {
		t.Fatalf("outbound Bereia exchange response=%+v err=%v", bereia, exchangeErr)
	}
	homeScopes, valid := scopepolicy.CanonicalAudienceScopes(productionBootstrapHomeScopes)
	if !valid || slices.Equal(homeScopes, productionBootstrapHomeScopes) {
		t.Fatal("production bootstrap fixture must be valid, unique, and non-canonical")
	}
	homeRequest := tenantTargetRequest(idToken, "local-tenant")
	homeRequest.ScopeCeilingV1 = append([]string(nil), homeScopes...)
	response, err := service.TokenExchange(context.Background(), homeRequest)
	if err != nil {
		t.Fatalf("home exchange: %v", err)
	}
	if response.PrincipalTenantID != "local-tenant" ||
		!slices.Equal(response.AuthorizedTenants, []string{"bereia", "local-tenant"}) ||
		!slices.Equal(response.Scopes, homeScopes) {
		t.Fatalf("unexpected response: %+v", response)
	}
	key, _ := service.getRSAPrivateKey()
	claims, err := utils.ValidateRS256(
		response.AccessToken, &key.(*rsa.PrivateKey).PublicKey, "https://issuer", domain.CodeAdminAudienceClientID,
	)
	if err != nil || claims["tid"] != "local-tenant" || claims["role"] != string(domain.RoleAdmin) || claims["roles"] != nil ||
		claims["scope"] != strings.Join(homeScopes, " ") {
		t.Fatalf("unexpected home claims=%v err=%v", claims, err)
	}
	service.clientSvc = discoveryClientService(t, false)
	if managed, exchangeErr := service.TokenExchange(context.Background(), homeRequest); exchangeErr != nil || managed == nil {
		t.Fatalf("managed home response=%+v err=%v", managed, exchangeErr)
	}
	service.clientSvc = &mockClientService{getClientFn: func(context.Context, string, string) (*domain.Client, error) {
		return &domain.Client{Id: domain.CodeAdminAudienceClientID, TenantId: "local-tenant", Type: domain.ClientTypePublic,
			AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
			DefaultScopes:     []string{"code-admin:workloads:read", "code-admin:workloads:read"},
			Status:            domain.ClientStatusActive}, nil
	}}
	if invalid, exchangeErr := service.TokenExchange(context.Background(), homeRequest); !errors.Is(exchangeErr, domain.ErrInvalidAudience) || invalid != nil {
		t.Fatalf("invalid home client response=%+v err=%v", invalid, exchangeErr)
	}
}

func TestTenantTargetDiscovery_GlobalScopeNeedsSignedHomeAuthority(t *testing.T) {
	service, idToken := newTenantTargetDiscoveryService(
		t, "bereia-read", []string{"code-admin:workloads:read", "console:clusters:read"}, domain.RoleCompanyEmployee,
	)
	response, err := service.TokenExchange(context.Background(), tenantTargetRequest(idToken, "bereia"))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if !slices.Equal(response.Scopes, []string{"code-admin:workloads:read"}) ||
		slices.Contains(response.Scopes, "code-admin:clusters:read") {
		t.Fatalf("global scope escaped home authority: %v", response.Scopes)
	}

	forged := signTenantHomeToken(t, "secret", &domain.User{
		Id: "user-1", Email: "user@example.com", Role: domain.RoleCompanyEmployee, TokenVersion: 3,
	}, domain.RoleAdmin)
	if response, err := service.TokenExchange(context.Background(), tenantTargetRequest(forged, "bereia")); !errors.Is(err, domain.ErrInvalidTenant) || response != nil {
		t.Fatalf("mismatched signed role response=%+v err=%v", response, err)
	}
	malformed, malformedToken := newTenantTargetDiscoveryService(
		t, "bereia-read", []string{"code-admin:clusters:read", "code-admin:workloads:read"}, domain.RoleCompanyEmployee,
	)
	if response, err := malformed.TokenExchange(context.Background(), tenantTargetRequest(malformedToken, "bereia")); !errors.Is(err, domain.ErrUnauthorizedScope) || response != nil {
		t.Fatalf("global tenant-role scope response=%+v err=%v", response, err)
	}
}

func TestTenantTargetDiscovery_RejectsUnsupportedContractInputs(t *testing.T) {
	service, idToken := newTenantTargetDiscoveryService(
		t, "bereia-read", []string{"code-admin:workloads:read"}, domain.RoleAdmin,
	)
	for name, mutate := range map[string]func(*domain.TokenExchangeReq){
		"missing target": func(request *domain.TokenExchangeReq) { request.TenantID = "" },
		"target alias":   func(request *domain.TokenExchangeReq) { request.TenantID = " Bereia " },
		"wrong audience": func(request *domain.TokenExchangeReq) { request.Audience = "other-api" },
		"empty ceiling":  func(request *domain.TokenExchangeReq) { request.ScopeCeilingV1 = nil },
		"invented scope": func(request *domain.TokenExchangeReq) {
			request.ScopeCeilingV1 = []string{"code-admin:invented:read"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := tenantTargetRequest(idToken, "bereia")
			mutate(&request)
			if response, err := service.TokenExchange(context.Background(), request); err == nil || response != nil {
				t.Fatalf("invalid exchange response=%+v err=%v", response, err)
			}
		})
	}
	request := tenantTargetRequest(idToken, "bereia")
	request.DiscoverTenantTargetsV1 = false
	if response, err := service.TokenExchange(context.Background(), request); !errors.Is(err, domain.ErrInvalidArgument) || response != nil {
		t.Fatalf("orphan ceiling response=%+v err=%v", response, err)
	}
	service.clientSvc = &mockClientService{getClientFn: func(context.Context, string, string) (*domain.Client, error) {
		return &domain.Client{Id: domain.CodeAdminAudienceClientID, TenantId: "bereia", Type: domain.ClientTypeService,
			AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)}, DefaultScopes: managedAudienceScopes,
			Status: domain.ClientStatusActive}, nil
	}}
	request = tenantTargetRequest(idToken, "bereia")
	if response, err := service.TokenExchange(context.Background(), request); !errors.Is(err, domain.ErrInvalidAudience) || response != nil {
		t.Fatalf("legacy target client response=%+v err=%v", response, err)
	}
	service.clientSvc = &mockClientService{getClientFn: func(context.Context, string, string) (*domain.Client, error) {
		return &domain.Client{Id: domain.CodeAdminAudienceClientID, TenantId: "bereia", Type: domain.ClientTypeService,
			AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
			DefaultScopes:     []string{"code-admin:workloads:read", "code-admin:clusters:read"},
			Status:            domain.ClientStatusActive, ManagedBy: domain.CodeAdminAudienceClientManager}, nil
	}}
	if response, err := service.TokenExchange(context.Background(), request); !errors.Is(err, domain.ErrInvalidAudience) || response != nil {
		t.Fatalf("noncanonical managed target response=%+v err=%v", response, err)
	}
	service.tenantScopedTokenClaimsV1 = false
	request = tenantTargetRequest(idToken, "bereia")
	if response, err := service.TokenExchange(context.Background(), request); !errors.Is(err, domain.ErrInvalidArgument) || response != nil {
		t.Fatalf("disabled discovery response=%+v err=%v", response, err)
	}
}

func newTenantTargetDiscoveryService(
	t *testing.T,
	roleName string,
	permissions []string,
	userRole domain.UserRole,
) (*userService, string) {
	t.Helper()
	home := "local-tenant"
	user := &domain.User{
		Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive,
		Role: userRole, CompanyId: &home, TokenVersion: 3,
	}
	users := &mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return user, nil }}
	memberships := &mockMembershipRepo{
		listExactFn: func(context.Context, string) ([]string, error) {
			if roleName == "" {
				return nil, nil
			}
			return []string{"bereia"}, nil
		},
		getExactFn: func(_ context.Context, tenantID, userID string) (*domain.Membership, error) {
			return &domain.Membership{TenantId: tenantID, UserId: userID, Roles: []string{roleName}}, nil
		},
	}
	tenants := &fakeTenantRepo{getFn: func(_ context.Context, tenantID string) (*domain.Tenant, error) {
		return &domain.Tenant{Id: tenantID, Status: domain.TenantStatusActive}, nil
	}}
	roles := &mockRoleService{getByNameFn: func(_ context.Context, tenantID, requestedRole string) (*domain.RoleResp, error) {
		if tenantID != "bereia" || requestedRole != roleName {
			t.Fatalf("unexpected role read: tenant=%s role=%s", tenantID, requestedRole)
		}
		return &domain.RoleResp{Name: roleName, Permissions: append([]string(nil), permissions...)}, nil
	}}
	clients := discoveryClientService(t, false)
	service := NewUserService(
		users, memberships, roles, clients, "secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithTenantScopedTokenClaimsV1(true, []string{"bereia"}, tenants),
	).(*userService)
	return service, signTenantHomeToken(t, "secret", user, user.Role)
}

func discoveryClientService(t *testing.T, legacyHome bool) *mockClientService {
	t.Helper()
	return &mockClientService{getClientFn: func(_ context.Context, tenantID, clientID string) (*domain.Client, error) {
		if clientID != domain.CodeAdminAudienceClientID {
			t.Fatalf("unexpected client id: %s", clientID)
		}
		client := &domain.Client{
			Id: clientID, TenantId: tenantID, Type: domain.ClientTypeService,
			AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
			DefaultScopes:     append([]string(nil), managedAudienceScopes...), Status: domain.ClientStatusActive,
			ManagedBy: domain.CodeAdminAudienceClientManager,
		}
		if legacyHome && tenantID == "local-tenant" {
			client.Type, client.ManagedBy = domain.ClientTypePublic, ""
			client.DefaultScopes = append([]string(nil), productionBootstrapHomeScopes...)
		}
		return client, nil
	}}
}

func signTenantHomeToken(t *testing.T, secret string, user *domain.User, signedRole domain.UserRole) string {
	t.Helper()
	return signTenantHomeTokenVersion(t, secret, user, signedRole, user.TokenVersion)
}

func signTenantHomeTokenVersion(t *testing.T, secret string, user *domain.User, signedRole domain.UserRole, version any) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": user.Id, "email": user.Email, "role": string(signedRole),
		"tid": "local-tenant", "iss": "https://issuer", "aud": "tikti",
	}
	if version != nil {
		claims["ver"] = version
	}
	return signIDTokenWithClaims(t, secret, claims)
}

func tenantTargetRequest(idToken, tenantID string) domain.TokenExchangeReq {
	return domain.TokenExchangeReq{
		IdToken: idToken, Audience: domain.CodeAdminAudienceClientID, TenantID: tenantID,
		DiscoverTenantTargetsV1: true, ScopeCeilingV1: append([]string(nil), managedAudienceScopes...), TTLSeconds: 300,
	}
}
