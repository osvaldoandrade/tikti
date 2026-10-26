package services

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type aiIdentityStores struct {
	tenants repository.TenantRepository
	roles   repository.RoleRepository
	clients repository.ClientRepository
	service AIGatewayIdentityService
}

func newAIIdentityStores(t *testing.T, tenantIDs ...string) aiIdentityStores {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	s := aiIdentityStores{tenants: repository.NewTenantRepo(client), roles: repository.NewRoleRepo(client), clients: repository.NewClientRepo(client)}
	for _, id := range tenantIDs {
		if _, _, err := s.tenants.CreateIfAbsent(context.Background(), &domain.Tenant{Id: id, Slug: id, Name: id, Status: domain.TenantStatusActive, CreatedAt: time.Now().Add(-time.Hour).UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	s.service = NewAIGatewayIdentityService(s.tenants, NewRoleService(s.roles), s.clients)
	return s
}

func TestAIGatewayIdentityEnsureCreatesClosedTenantRecordsAndReplays(t *testing.T) {
	s := newAIIdentityStores(t, "tenant-1", "tenant-2")
	got, created, err := s.service.Ensure(context.Background(), "tenant-1")
	if err != nil || !created || got == nil {
		t.Fatalf("ensure=%#v created=%v err=%v", got, created, err)
	}
	if got.TenantId != "tenant-1" || got.Client.ClientId != aigateway.Audience || got.Client.TenantId != "tenant-1" ||
		!slices.Equal(got.Client.DefaultScopes, []string{aigateway.InvokeScope, aigateway.ModelsScope, aigateway.UsageScope}) ||
		!slices.Equal(got.Client.AllowedGrantTypes, []string{"token_exchange"}) || got.Client.Type != domain.ClientTypeService {
		t.Fatalf("unexpected client projection: %#v", got.Client)
	}
	if len(got.Roles) != 2 || got.Roles[0].Name != "tenant-1-ai-admin" || got.Roles[1].Name != "tenant-1-ai-user" {
		t.Fatalf("unexpected roles: %#v", got.Roles)
	}
	stored, err := s.clients.Get(context.Background(), "tenant-1", aigateway.Audience)
	if err != nil || !domain.IsManagedAIGatewayAudience("tenant-1", stored) || stored.SecretHash != "" {
		t.Fatalf("stored client is not the managed credential-free audience: %#v %v", stored, err)
	}
	again, created, err := s.service.Ensure(context.Background(), "tenant-1")
	if err != nil || created || again.Client.ClientId != got.Client.ClientId || len(again.Roles) != 2 {
		t.Fatalf("replay=%#v created=%v err=%v", again, created, err)
	}
	// Exactly one tenant is affected.
	if other, err := s.clients.Get(context.Background(), "tenant-2", aigateway.Audience); err != nil || other != nil {
		t.Fatalf("cross-tenant client was provisioned: %#v %v", other, err)
	}
	if role, _ := s.roles.Get(context.Background(), "tenant-2", "tenant-1-ai-user"); role != nil {
		t.Fatal("cross-tenant role was provisioned")
	}
}

func TestAIGatewayIdentityRolesNeverCarryGlobalScopes(t *testing.T) {
	for _, role := range AIGatewayRoleDefinitions("tenant-1") {
		if slices.Contains(role.Permissions, "code-admin:ai:platform") || slices.Contains(role.Permissions, aigateway.RuntimeScope) || slices.Contains(role.Permissions, aigateway.UsageScope) {
			t.Fatalf("role %s carries a non-tenant AI scope", role.Name)
		}
		if !scopepolicy.ValidCanonicalPermissions(role.Permissions) {
			t.Fatalf("role %s is not canonical tenant-assignable", role.Name)
		}
	}
	for _, scope := range []string{"code-admin:ai:platform", aigateway.RuntimeScope} {
		if _, ok := scopepolicy.CanonicalPermissions([]string{scope}); ok {
			t.Fatalf("%s became tenant-assignable", scope)
		}
	}
}

func TestAIGatewayIdentityFailsClosedOnConflictsAndInvalidTenants(t *testing.T) {
	ctx := context.Background()
	t.Run("existing role is never broadened", func(t *testing.T) {
		s := newAIIdentityStores(t, "tenant-1")
		if _, _, err := NewRoleService(s.roles).CreateWithName(ctx, "tenant-1", "tenant-1-ai-user", domain.RolePutReq{Permissions: []string{aigateway.InvokeScope}}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.service.Ensure(ctx, "tenant-1"); !errors.Is(err, domain.ErrRoleConflict) {
			t.Fatalf("err=%v", err)
		}
		role, _ := s.roles.Get(ctx, "tenant-1", "tenant-1-ai-user")
		if role == nil || !slices.Equal(role.Permissions, []string{aigateway.InvokeScope}) {
			t.Fatalf("existing role changed: %#v", role)
		}
		if c, _ := s.clients.Get(ctx, "tenant-1", aigateway.Audience); c != nil {
			t.Fatal("client was activated despite a role conflict")
		}
	})
	t.Run("unmanaged look-alike client", func(t *testing.T) {
		s := newAIIdentityStores(t, "tenant-1")
		if err := s.clients.Create(ctx, "tenant-1", &domain.Client{Id: aigateway.Audience, TenantId: "tenant-1", SecretHash: "x", Type: domain.ClientTypeService, AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: []string{aigateway.InvokeScope}, Status: domain.ClientStatusActive}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.service.Ensure(ctx, "tenant-1"); !errors.Is(err, domain.ErrManagedClientConflict) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("invalid or inactive tenants", func(t *testing.T) {
		s := newAIIdentityStores(t, "tenant-1")
		disabled := &domain.Tenant{Id: "tenant-off", Slug: "tenant-off", Name: "off", Status: domain.TenantStatusDisabled, CreatedAt: time.Now().Add(-time.Hour).UTC()}
		if _, _, err := s.tenants.CreateIfAbsent(ctx, disabled); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"", "missing", "tenant-off", domain.RetiredDefaultTenantID, "Tenant-1", "tenant_1"} {
			if _, _, err := s.service.Ensure(ctx, id); !errors.Is(err, domain.ErrInvalidTenant) {
				t.Fatalf("tenant %q: err=%v", id, err)
			}
		}
	})
	t.Run("unconfigured", func(t *testing.T) {
		var nilService *aiGatewayIdentityService
		if _, _, err := nilService.Ensure(ctx, "tenant-1"); err == nil {
			t.Fatal("nil service succeeded")
		}
	})
}

func TestAIGatewayGenericClientCreationCannotClaimReservedAudience(t *testing.T) {
	s := newAIIdentityStores(t, "tenant-1")
	svc := NewClientService(s.clients)
	for _, id := range []string{aigateway.Audience, " CODE-LLM-SERVICE "} {
		if _, err := svc.Create(context.Background(), "tenant-1", domain.ClientCreateReq{ClientId: id, AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: []string{aigateway.InvokeScope}}); !errors.Is(err, domain.ErrInvalidArgument) {
			t.Fatalf("%q: err=%v", id, err)
		}
	}
}

// The user exchange gate opens only after Ensure plus an explicit assignment.
func TestAIGatewayIdentityEnablesExchangeOnlyThroughAssignedDedicatedRole(t *testing.T) {
	s, request, _, user, tenant := aiUserFixture(t)
	stores := newAIIdentityStores(t, tenant.Id)
	s.clientSvc = NewClientService(stores.clients)
	s.roleSvc = NewRoleService(stores.roles)
	assigned := []string{}
	members := &mockMembershipRepo{listExactFn: func(context.Context, string) ([]string, error) { return []string{tenant.Id}, nil }, getExactFn: func(context.Context, string, string) (*domain.Membership, error) {
		return &domain.Membership{TenantId: tenant.Id, UserId: user.Id, Roles: append([]string(nil), assigned...)}, nil
	}}
	s.membershipRepo, s.exactMembershipRepo = members, members
	if _, err := s.TokenExchange(context.Background(), request); err == nil {
		t.Fatal("exchange succeeded before the AI identity existed")
	}
	if _, _, err := stores.service.Ensure(context.Background(), tenant.Id); err != nil {
		t.Fatal(err)
	}
	assigned = []string{"unrelated"}
	if _, err := NewRoleService(stores.roles).Create(context.Background(), tenant.Id, domain.RoleCreateReq{Name: "unrelated", Permissions: []string{"code-admin:services:read"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TokenExchange(context.Background(), request); err == nil {
		t.Fatal("ensure implicitly granted AI to a principal without the dedicated role")
	}
	assigned = []string{tenant.Id + "-ai-user"}
	response, err := s.TokenExchange(context.Background(), request)
	if err != nil || response == nil || !slices.Equal(response.Scopes, []string{aigateway.InvokeScope, aigateway.ModelsScope}) {
		t.Fatalf("assigned user exchange=%#v err=%v", response, err)
	}
	if _, err := s.ValidateAIAccessToken(context.Background(), response.AccessToken); err != nil {
		t.Fatalf("issued token failed current validation: %v", err)
	}
}

func TestAIGatewayAudienceIdentifierIsOneProtocolContract(t *testing.T) {
	if domain.AIGatewayAudienceClientID != aigateway.Audience {
		t.Fatal("managed client ID diverged from the AI token audience")
	}
	lookAlike := &domain.Client{Id: aigateway.Audience, TenantId: "tenant-1", Type: domain.ClientTypeService, AllowedGrantTypes: []string{"token_exchange"}, Status: domain.ClientStatusActive, ManagedBy: domain.WorkloadAccountBFFClientManager}
	if domain.IsManagedWorkloadAccountAudience("tenant-1", lookAlike) || domain.IsManagedAIGatewayAudience("tenant-1", lookAlike) {
		t.Fatal("another manager can own the AI audience")
	}
	lookAlike.ManagedBy = domain.AIGatewayAudienceClientManager
	if !domain.IsManagedAIGatewayAudience("tenant-1", lookAlike) || domain.IsManagedAIGatewayAudience("tenant-2", lookAlike) {
		t.Fatal("managed AI audience is not tenant-bound")
	}
	lookAlike.SecretHash = "x"
	if domain.IsManagedAIGatewayAudience("tenant-1", lookAlike) {
		t.Fatal("secret-bearing AI audience accepted")
	}
}
