package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

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

func TestTenantTargetDiscoveryV2_DiscoversNewExactMembershipForCanaryPrincipal(t *testing.T) {
	home := "local-tenant"
	user := &domain.User{
		Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleAdmin, CompanyId: &home, TokenVersion: 3,
	}
	users := &mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return user, nil }}
	memberships := &mockMembershipRepo{
		listExactFn: func(context.Context, string) ([]string, error) {
			return []string{"bereia", "new-tenant"}, nil
		},
		getExactFn: func(_ context.Context, tenantID, userID string) (*domain.Membership, error) {
			return &domain.Membership{TenantId: tenantID, UserId: userID, Roles: []string{tenantID + "-read"}}, nil
		},
	}
	tenants := &fakeTenantRepo{getFn: func(_ context.Context, tenantID string) (*domain.Tenant, error) {
		return &domain.Tenant{Id: tenantID, Status: domain.TenantStatusActive}, nil
	}}
	roles := &mockRoleService{getByNameFn: func(_ context.Context, tenantID, roleName string) (*domain.RoleResp, error) {
		if roleName != tenantID+"-read" {
			t.Fatalf("unexpected role read: tenant=%s role=%s", tenantID, roleName)
		}
		return &domain.RoleResp{Name: roleName, Permissions: []string{"code-admin:workloads:read"}}, nil
	}}
	service := NewUserService(
		users, memberships, roles, discoveryClientService(t, false),
		"secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithTenantScopedTokenClaimsV1(true, []string{"bereia"}, tenants),
		WithTenantTargetDiscoveryV2(true, []string{"local-tenant"}, tenants),
	).(*userService)
	idToken := signTenantHomeToken(t, "secret", user, user.Role)
	request := tenantTargetRequest(idToken, "new-tenant")
	request.DiscoverTenantTargetsV1 = false
	request.DiscoverTenantTargetsV2 = true

	response, err := service.TokenExchange(context.Background(), request)
	if err != nil {
		t.Fatalf("dynamic discovery exchange: %v", err)
	}
	if response.PrincipalTenantID != home ||
		!slices.Equal(response.AuthorizedTenants, []string{"bereia", "local-tenant", "new-tenant"}) ||
		!slices.Equal(response.Scopes, []string{
			"code-admin:clusters:read", "code-admin:workloads:read", "console:clusters:read",
		}) {
		t.Fatalf("unexpected dynamic authority: %+v", response)
	}

	legacy := tenantTargetRequest(idToken, "new-tenant")
	if legacyResponse, legacyErr := service.TokenExchange(context.Background(), legacy); !errors.Is(legacyErr, domain.ErrInvalidTenant) || legacyResponse != nil {
		t.Fatalf("v1 accepted a non-allowlisted target response=%+v err=%v", legacyResponse, legacyErr)
	}
}

func TestTenantTargetDiscoveryV2_DiscoversForAnyProvenanceBoundAdminHome(t *testing.T) {
	home := "bereia"
	user := &domain.User{
		Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleAdmin, CompanyId: &home, TokenVersion: 3,
	}
	tenants := &fakeTenantRepo{getFn: func(_ context.Context, tenantID string) (*domain.Tenant, error) {
		return &domain.Tenant{Id: tenantID, Status: domain.TenantStatusActive}, nil
	}}
	service := NewUserService(
		&mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return user, nil }},
		&mockMembershipRepo{
			listExactFn: func(context.Context, string) ([]string, error) {
				return []string{"new-tenant"}, nil
			},
			getExactFn: func(_ context.Context, tenantID, userID string) (*domain.Membership, error) {
				return &domain.Membership{TenantId: tenantID, UserId: userID, Roles: []string{tenantID + "-read"}}, nil
			},
		},
		&mockRoleService{getByNameFn: func(_ context.Context, tenantID, roleName string) (*domain.RoleResp, error) {
			if roleName != tenantID+"-read" {
				t.Fatalf("unexpected role read: tenant=%s role=%s", tenantID, roleName)
			}
			return &domain.RoleResp{Name: roleName, Permissions: []string{"code-admin:workloads:read"}}, nil
		}}, discoveryClientService(t, false),
		"secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithTenantScopedTokenClaimsV1(true, []string{"bereia", "local-tenant"}, tenants),
		WithTenantTargetDiscoveryV2(true, []string{"local-tenant"}, tenants),
	).(*userService)
	registry := prometheus.NewRegistry()
	service.tenantDiscoveryMetrics = NewTenantDiscoveryMetrics(registry)
	request := tenantTargetRequest(signTenantHomeTokenForTenant(t, "secret", user, user.Role, home), home)
	request.DiscoverTenantTargetsV1 = false
	request.DiscoverTenantTargetsV2 = true

	response, err := service.TokenExchange(context.Background(), request)
	if err != nil {
		t.Fatalf("dynamic discovery outside the former principal cohort: %v", err)
	}
	if response.PrincipalTenantID != home ||
		!slices.Equal(response.AuthorizedTenants, []string{"bereia", "new-tenant"}) ||
		!slices.Equal(response.Scopes, managedAudienceScopes) {
		t.Fatalf("unexpected dynamic authority: %+v", response)
	}
	if value := tenantDiscoveryCounterValue(t, service.tenantDiscoveryMetrics.requests, "v2", "success", "allowed"); value != 1 {
		t.Fatalf("v2 request metric=%v", value)
	}
}

func TestTenantTargetDiscoveryV2_EnforcesRoleLimitWithoutHomeAllowlist(t *testing.T) {
	home := "bereia"
	target := "local-tenant"
	user := &domain.User{
		Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleAdmin, CompanyId: &home, TokenVersion: 3,
	}
	roleNames := make([]string, 101)
	for index := range roleNames {
		roleNames[index] = fmt.Sprintf("role-%03d", index)
	}
	roleReads := 0
	tenants := &fakeTenantRepo{getFn: func(_ context.Context, tenantID string) (*domain.Tenant, error) {
		return &domain.Tenant{Id: tenantID, Status: domain.TenantStatusActive}, nil
	}}
	service := NewUserService(
		&mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return user, nil }},
		&mockMembershipRepo{
			listExactFn: func(context.Context, string) ([]string, error) { return []string{target}, nil },
			getExactFn: func(_ context.Context, tenantID, userID string) (*domain.Membership, error) {
				return &domain.Membership{TenantId: tenantID, UserId: userID, Roles: append([]string(nil), roleNames...)}, nil
			},
		},
		&mockRoleService{getByNameFn: func(_ context.Context, _ string, roleName string) (*domain.RoleResp, error) {
			roleReads++
			return &domain.RoleResp{Name: roleName, Permissions: []string{"code-admin:workloads:read"}}, nil
		}},
		discoveryClientService(t, false), "secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithTenantScopedTokenClaimsV1(true, []string{home, target}, tenants),
		WithTenantTargetDiscoveryV2(true, []string{"canary-home"}, tenants),
	).(*userService)
	request := tenantTargetRequest(signTenantHomeTokenForTenant(t, "secret", user, user.Role, home), target)
	request.DiscoverTenantTargetsV1 = false
	request.DiscoverTenantTargetsV2 = true

	response, err := service.TokenExchange(context.Background(), request)
	if !errors.Is(err, domain.ErrInvalidTenant) || response != nil || roleReads != 0 {
		t.Fatalf("dynamic role-limit response=%+v reads=%d err=%v", response, roleReads, err)
	}
}

func TestTenantTargetDiscoveryV2_ExcludesMemberWithoutManagedAudience(t *testing.T) {
	home := "local-tenant"
	user := &domain.User{
		Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleAdmin, CompanyId: &home, TokenVersion: 3,
	}
	tenants := &fakeTenantRepo{getFn: func(_ context.Context, tenantID string) (*domain.Tenant, error) {
		return &domain.Tenant{Id: tenantID, Status: domain.TenantStatusActive}, nil
	}}
	clients := discoveryClientService(t, false)
	validClient := clients.getClientFn
	clients.getClientFn = func(ctx context.Context, tenantID, clientID string) (*domain.Client, error) {
		if tenantID == "new-tenant" {
			return nil, nil
		}
		return validClient(ctx, tenantID, clientID)
	}
	service := NewUserService(
		&mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return user, nil }},
		&mockMembershipRepo{
			listExactFn: func(context.Context, string) ([]string, error) { return []string{"new-tenant"}, nil },
			getExactFn: func(_ context.Context, tenantID, userID string) (*domain.Membership, error) {
				return &domain.Membership{TenantId: tenantID, UserId: userID, Roles: []string{"reader"}}, nil
			},
		},
		&mockRoleService{}, clients,
		"secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithTenantScopedTokenClaimsV1(true, []string{"bereia", "local-tenant"}, tenants),
		WithTenantTargetDiscoveryV2(true, []string{"local-tenant"}, tenants),
	).(*userService)
	request := tenantTargetRequest(signTenantHomeToken(t, "secret", user, user.Role), home)
	request.DiscoverTenantTargetsV1 = false
	request.DiscoverTenantTargetsV2 = true

	response, err := service.TokenExchange(context.Background(), request)
	if err != nil {
		t.Fatalf("dynamic home exchange: %v", err)
	}
	if !slices.Equal(response.AuthorizedTenants, []string{"local-tenant"}) {
		t.Fatalf("client-incomplete tenant became eligible: %+v", response)
	}
}

func TestTenantTargetDiscoveryV2_ExcludesMemberWithUnresolvableRole(t *testing.T) {
	home := "local-tenant"
	user := &domain.User{
		Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleAdmin, CompanyId: &home, TokenVersion: 3,
	}
	tenants := &fakeTenantRepo{getFn: func(_ context.Context, tenantID string) (*domain.Tenant, error) {
		return &domain.Tenant{Id: tenantID, Status: domain.TenantStatusActive}, nil
	}}
	service := NewUserService(
		&mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return user, nil }},
		&mockMembershipRepo{
			listExactFn: func(context.Context, string) ([]string, error) { return []string{"new-tenant"}, nil },
			getExactFn: func(_ context.Context, tenantID, userID string) (*domain.Membership, error) {
				return &domain.Membership{TenantId: tenantID, UserId: userID, Roles: []string{"missing-reader"}}, nil
			},
		},
		&mockRoleService{getByNameFn: func(context.Context, string, string) (*domain.RoleResp, error) {
			return nil, domain.ErrNotFound
		}},
		discoveryClientService(t, false),
		"secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithTenantScopedTokenClaimsV1(true, []string{"bereia", "local-tenant"}, tenants),
		WithTenantTargetDiscoveryV2(true, []string{"local-tenant"}, tenants),
	).(*userService)
	registry := prometheus.NewRegistry()
	service.tenantDiscoveryMetrics = NewTenantDiscoveryMetrics(registry)
	request := tenantTargetRequest(signTenantHomeToken(t, "secret", user, user.Role), home)
	request.DiscoverTenantTargetsV1 = false
	request.DiscoverTenantTargetsV2 = true

	response, err := service.TokenExchange(context.Background(), request)
	if err != nil {
		t.Fatalf("dynamic home exchange: %v", err)
	}
	if !slices.Equal(response.AuthorizedTenants, []string{"local-tenant"}) {
		t.Fatalf("tenant with unresolvable role became eligible: %+v", response)
	}
	if value := tenantDiscoveryCounterValue(t, service.tenantDiscoveryMetrics.omissions, "v2", "role_unresolvable"); value != 1 {
		t.Fatalf("role omission metric=%v", value)
	}
}

func TestTenantDiscoveryMetricsCollapseUnknownLabelValues(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewTenantDiscoveryMetrics(registry)
	metrics.observeRequest("tenant-secret", nil, 3)
	metrics.observeOmission("tenant-secret", "role-secret")
	if value := tenantDiscoveryCounterValue(t, metrics.requests, "internal", "success", "allowed"); value != 1 {
		t.Fatalf("closed request metric=%v", value)
	}
	if value := tenantDiscoveryCounterValue(t, metrics.omissions, "internal", "internal"); value != 1 {
		t.Fatalf("closed omission metric=%v", value)
	}
}

func tenantDiscoveryCounterValue(t *testing.T, counter *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	metric := &dto.Metric{}
	if err := counter.WithLabelValues(labels...).Write(metric); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return metric.GetCounter().GetValue()
}

func TestTenantTargetDiscoveryV2_BoundsAuthorizedTargetsForAPIContract(t *testing.T) {
	for _, test := range []struct {
		members int
		want    int
		wantErr error
	}{
		{members: 99, want: 100},
		{members: 100, wantErr: domain.ErrInvalidTenant},
	} {
		t.Run(fmt.Sprintf("members-%d", test.members), func(t *testing.T) {
			tenantIDs := make([]string, test.members)
			for index := range tenantIDs {
				tenantIDs[index] = fmt.Sprintf("tenant-%03d", index)
			}
			user := &domain.User{Id: "user-1", Status: domain.UserStatusActive}
			service := &userService{
				exactMembershipRepo: &mockMembershipRepo{
					listExactFn: func(context.Context, string) ([]string, error) {
						return append([]string(nil), tenantIDs...), nil
					},
					getExactFn: func(_ context.Context, tenantID, userID string) (*domain.Membership, error) {
						return &domain.Membership{TenantId: tenantID, UserId: userID, Roles: []string{"reader"}}, nil
					},
				},
				tenantRepo: &fakeTenantRepo{getFn: func(_ context.Context, tenantID string) (*domain.Tenant, error) {
					return &domain.Tenant{Id: tenantID, Status: domain.TenantStatusActive}, nil
				}},
				roleSvc: &mockRoleService{getByNameFn: func(_ context.Context, _ string, roleName string) (*domain.RoleResp, error) {
					return &domain.RoleResp{Name: roleName, Permissions: []string{"code-admin:workloads:read"}}, nil
				}},
				clientSvc: discoveryClientService(t, false),
			}
			targets, err := service.authorizedTenantTargets(context.Background(), user, "local-tenant", true)
			if !errors.Is(err, test.wantErr) || len(targets) != test.want {
				t.Fatalf("members=%d targets=%d err=%v", test.members, len(targets), err)
			}
		})
	}
}

func TestTenantTargetDiscoveryV2_BoundsRoleResolutionWork(t *testing.T) {
	tenantIDs := []string{"tenant-1", "tenant-2", "tenant-3", "tenant-4", "tenant-5", "tenant-6"}
	roles := make([]string, 100)
	for index := range roles {
		roles[index] = fmt.Sprintf("role-%03d", index)
	}
	roleReads := 0
	service := &userService{
		exactMembershipRepo: &mockMembershipRepo{
			listExactFn: func(context.Context, string) ([]string, error) {
				return append([]string(nil), tenantIDs...), nil
			},
			getExactFn: func(_ context.Context, tenantID, userID string) (*domain.Membership, error) {
				return &domain.Membership{TenantId: tenantID, UserId: userID, Roles: append([]string(nil), roles...)}, nil
			},
		},
		tenantRepo: &fakeTenantRepo{getFn: func(_ context.Context, tenantID string) (*domain.Tenant, error) {
			return &domain.Tenant{Id: tenantID, Status: domain.TenantStatusActive}, nil
		}},
		roleSvc: &mockRoleService{getByNameFn: func(_ context.Context, _ string, roleName string) (*domain.RoleResp, error) {
			roleReads++
			return &domain.RoleResp{Name: roleName, Permissions: []string{"code-admin:workloads:read"}}, nil
		}},
		clientSvc: discoveryClientService(t, false),
	}
	targets, err := service.authorizedTenantTargets(
		context.Background(), &domain.User{Id: "user-1", Status: domain.UserStatusActive}, "local-tenant", true,
	)
	if !errors.Is(err, domain.ErrInvalidTenant) || targets != nil || roleReads != 500 {
		t.Fatalf("role-resolution budget targets=%v reads=%d err=%v", targets, roleReads, err)
	}
}

func TestTenantTargetDiscoveryV2_TokenExchangeSharesRoleLookupBudget(t *testing.T) {
	home := "local-tenant"
	user := &domain.User{
		Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleAdmin, CompanyId: &home, TokenVersion: 3,
	}
	tenantIDs := []string{"tenant-1", "tenant-2", "tenant-3", "tenant-4", "tenant-5"}
	roles := make([]string, maximumDynamicMembershipRoles)
	for index := range roles {
		roles[index] = fmt.Sprintf("role-%03d", index)
	}
	roleReads := 0
	service := NewUserService(
		&mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return user, nil }},
		&mockMembershipRepo{
			listExactFn: func(context.Context, string) ([]string, error) {
				return append([]string(nil), tenantIDs...), nil
			},
			getExactFn: func(_ context.Context, tenantID, userID string) (*domain.Membership, error) {
				return &domain.Membership{
					TenantId: tenantID, UserId: userID, Roles: append([]string(nil), roles...),
				}, nil
			},
		},
		&mockRoleService{getByNameFn: func(_ context.Context, _ string, roleName string) (*domain.RoleResp, error) {
			roleReads++
			return &domain.RoleResp{Name: roleName, Permissions: []string{"code-admin:workloads:read"}}, nil
		}},
		discoveryClientService(t, false), "secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithTenantScopedTokenClaimsV1(true, tenantIDs, &fakeTenantRepo{getFn: func(_ context.Context, tenantID string) (*domain.Tenant, error) {
			return &domain.Tenant{Id: tenantID, Status: domain.TenantStatusActive}, nil
		}}),
		WithTenantTargetDiscoveryV2(true, []string{home}, &fakeTenantRepo{getFn: func(_ context.Context, tenantID string) (*domain.Tenant, error) {
			return &domain.Tenant{Id: tenantID, Status: domain.TenantStatusActive}, nil
		}}),
	).(*userService)
	request := tenantTargetRequest(signTenantHomeToken(t, "secret", user, user.Role), "tenant-5")
	request.DiscoverTenantTargetsV1 = false
	request.DiscoverTenantTargetsV2 = true

	response, err := service.TokenExchange(context.Background(), request)
	if err != nil || response == nil {
		t.Fatalf("exchange response=%+v err=%v", response, err)
	}
	if roleReads != maximumDiscoveryRoleLookups {
		t.Fatalf("role definitions were resolved more than once: reads=%d budget=%d", roleReads, maximumDiscoveryRoleLookups)
	}
}

func TestTenantTargetDiscoveryV2_FailsClosedOutsidePrincipalCohort(t *testing.T) {
	home := "other-home"
	user := &domain.User{
		Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleAdmin, CompanyId: &home, TokenVersion: 3,
	}
	service := NewUserService(
		&mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return user, nil }},
		&mockMembershipRepo{
			listExactFn: func(context.Context, string) ([]string, error) { return []string{"new-tenant"}, nil },
			getExactFn: func(_ context.Context, tenantID, userID string) (*domain.Membership, error) {
				return &domain.Membership{TenantId: tenantID, UserId: userID, Roles: []string{"new-tenant-read"}}, nil
			},
		},
		&mockRoleService{}, discoveryClientService(t, false),
		"secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithTenantTargetDiscoveryV2(true, []string{"local-tenant"}, &fakeTenantRepo{getFn: func(_ context.Context, tenantID string) (*domain.Tenant, error) {
			return &domain.Tenant{Id: tenantID, Status: domain.TenantStatusActive}, nil
		}}),
	).(*userService)
	request := tenantTargetRequest(signTenantHomeTokenForTenant(t, "secret", user, user.Role, home), "new-tenant")
	request.DiscoverTenantTargetsV1 = false
	request.DiscoverTenantTargetsV2 = true

	response, err := service.TokenExchange(context.Background(), request)
	if !errors.Is(err, domain.ErrInvalidTenant) || response != nil {
		t.Fatalf("non-canary principal response=%+v err=%v", response, err)
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

func TestTenantTargetDiscovery_BuiltInAdministratorsCanElevateFeatureWritesForMemberTenant(t *testing.T) {
	featureScopes, valid := scopepolicy.CanonicalAudienceScopes(append(
		append([]string(nil), managedAudienceScopes...),
		"code-admin:features:read", "code-admin:features:write",
	))
	if !valid {
		t.Fatal("feature scope fixture must be canonicalizable")
	}

	for _, profile := range []struct {
		name      string
		userRole  domain.UserRole
		wantWrite bool
	}{
		{name: "admin", userRole: domain.RoleAdmin, wantWrite: true},
		{name: "company admin", userRole: domain.RoleCompanyAdmin, wantWrite: true},
		{name: "employee", userRole: domain.RoleCompanyEmployee, wantWrite: false},
	} {
		t.Run(profile.name, func(t *testing.T) {
			service, idToken := newTenantTargetDiscoveryService(
				t, "bereia-admin", []string{"code-admin:features:read"}, profile.userRole,
			)
			service.clientSvc = &mockClientService{getClientFn: func(_ context.Context, tenantID, clientID string) (*domain.Client, error) {
				return &domain.Client{
					Id: clientID, TenantId: tenantID, Type: domain.ClientTypeService,
					AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
					DefaultScopes:     append([]string(nil), featureScopes...), Status: domain.ClientStatusActive,
					ManagedBy: domain.CodeAdminAudienceClientManager,
				}, nil
			}}
			request := tenantTargetRequest(idToken, "bereia")
			request.ScopeCeilingV1 = append([]string(nil), featureScopes...)

			response, err := service.TokenExchange(context.Background(), request)
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			if got := slices.Contains(response.Scopes, "code-admin:features:write"); got != profile.wantWrite {
				t.Fatalf("feature write=%t want=%t scopes=%v", got, profile.wantWrite, response.Scopes)
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

func signTenantHomeTokenForTenant(t *testing.T, secret string, user *domain.User, signedRole domain.UserRole, tenantID string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": user.Id, "email": user.Email, "role": string(signedRole),
		"tid": tenantID, "iss": "https://issuer", "aud": "tikti", "ver": user.TokenVersion,
	}
	return signIDTokenWithClaims(t, secret, claims)
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
