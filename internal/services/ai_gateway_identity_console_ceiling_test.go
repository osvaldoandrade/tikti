package services

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func (s aiIdentityStores) consoleCeiling(t *testing.T, tenantID string) *domain.Client {
	t.Helper()
	client, err := s.clients.Get(context.Background(), tenantID, domain.CodeAdminAudienceClientID)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// ADR-0024 Amendment 2: a workload tenant administrator enabling AI raises the
// tenant's managed Console ceiling additively with exactly the tenant AI
// scopes, so the dynamic Console session can carry <tenant>-ai-admin.
func TestAIGatewayIdentityEnsureRaisesManagedConsoleCeilingAdditively(t *testing.T) {
	ctx := context.Background()
	s := newAIIdentityStores(t, "workload-1", "workload-2")
	got, created, err := s.service.Ensure(ctx, "workload-1", s.admin)
	if err != nil || !created || got == nil {
		t.Fatalf("ensure=%#v created=%v err=%v", got, created, err)
	}
	ceiling := s.consoleCeiling(t, "workload-1")
	want := []string{"code-admin:ai:read", "code-admin:ai:write", "code-admin:audit:read", "code-admin:identity:write"}
	if !domain.IsManagedCodeAdminAudience("workload-1", ceiling) || !slices.Equal(ceiling.DefaultScopes, want) {
		t.Fatalf("ceiling was not raised additively: %#v", ceiling)
	}
	for _, scope := range []string{"code-admin:ai:platform", aigateway.RuntimeScope} {
		if slices.Contains(ceiling.DefaultScopes, scope) {
			t.Fatalf("global scope %s entered the tenant ceiling", scope)
		}
	}
	// Tenant isolation: another tenant's ceiling is untouched.
	if other := s.consoleCeiling(t, "workload-2"); !slices.Equal(other.DefaultScopes, consoleBaselineScopes) {
		t.Fatalf("another tenant's ceiling changed: %v", other.DefaultScopes)
	}

	// Exact replay: nothing is rewritten and the route reports 200.
	again, created, err := s.service.Ensure(ctx, "workload-1", s.admin)
	if err != nil || created || again == nil {
		t.Fatalf("replay=%#v created=%v err=%v", again, created, err)
	}
	if replayed := s.consoleCeiling(t, "workload-1"); !reflect.DeepEqual(replayed, ceiling) {
		t.Fatalf("replay rewrote the ceiling: %#v != %#v", replayed, ceiling)
	}
	// The response projection is unchanged: the strict API decoder sees only
	// the AI audience, roles and admin assignment.
	if again.Client.ClientId != aigateway.Audience || !slices.Equal(again.Client.DefaultScopes, AIGatewayClientScopes()) {
		t.Fatalf("response projection changed: %#v", again.Client)
	}
}

func TestAIGatewayIdentityEnsureNeverShrinksOrDuplicatesTheConsoleCeiling(t *testing.T) {
	ctx := context.Background()
	s := newAIIdentityStores(t, "workload-1")
	// A ceiling that already carries one AI scope and extra scopes keeps them
	// all and gains only the missing tenant AI scope.
	wide := []string{"code-admin:ai:read", "code-admin:audit:read", "code-admin:audit:write", "code-admin:identity:write", "custom:scope"}
	if _, _, err := s.clients.EnsureManagedAudience(ctx, "workload-1", managedConsoleClient("workload-1", wide)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.service.Ensure(ctx, "workload-1", s.admin); err != nil {
		t.Fatal(err)
	}
	want := []string{"code-admin:ai:read", "code-admin:ai:write", "code-admin:audit:read", "code-admin:audit:write", "code-admin:identity:write", "custom:scope"}
	if got := s.consoleCeiling(t, "workload-1"); !slices.Equal(got.DefaultScopes, want) {
		t.Fatalf("ceiling=%v want=%v", got.DefaultScopes, want)
	}

	// A ceiling already containing both AI scopes is a pure no-op for the
	// ceiling: with the rest of the identity in place the route replays.
	if _, created, err := s.service.Ensure(ctx, "workload-1", s.admin); err != nil || created {
		t.Fatalf("replay created=%v err=%v", created, err)
	}
}

func TestAIGatewayConsoleCeilingScopesAreTenantAssignableOnly(t *testing.T) {
	scopes := AIGatewayConsoleCeilingScopes()
	if !slices.Equal(scopes, []string{"code-admin:ai:read", "code-admin:ai:write"}) {
		t.Fatalf("unexpected ceiling scopes: %v", scopes)
	}
	for _, scope := range scopes {
		if !scopepolicy.TenantRoleAssignable(scope) {
			t.Fatalf("%s is not tenant-assignable", scope)
		}
	}
	for _, scope := range []string{"code-admin:ai:platform", aigateway.RuntimeScope} {
		if slices.Contains(scopes, scope) || scopepolicy.TenantRoleAssignable(scope) {
			t.Fatalf("global scope %s is reachable through the tenant ceiling", scope)
		}
	}
}

// A missing or unmanaged Console client fails closed before any write: no
// role, assignment or AI audience is created and the look-alike is untouched.
func TestAIGatewayIdentityEnsureConflictsOnMissingOrUnmanagedConsoleClient(t *testing.T) {
	ctx := context.Background()
	for name, lookAlike := range map[string]*domain.Client{
		"missing": nil,
		"unmanaged service look-alike": {
			Id: domain.CodeAdminAudienceClientID, TenantId: "workload-x", SecretHash: "x", Type: domain.ClientTypeService,
			AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: []string{"code-admin:audit:read"}, Status: domain.ClientStatusActive,
		},
		"unmanaged credential-free service": {
			Id: domain.CodeAdminAudienceClientID, TenantId: "workload-x", Type: domain.ClientTypeService,
			AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: []string{"code-admin:audit:read"}, Status: domain.ClientStatusActive,
		},
		// Generic client creation always stores a secret, so a secret-bearing
		// PUBLIC code-admin-api is never the bootstrap's legacy home audience.
		"secret-bearing public look-alike": {
			Id: domain.CodeAdminAudienceClientID, TenantId: "workload-x", SecretHash: "x", Type: domain.ClientTypePublic,
			AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: []string{"code-admin:audit:read"}, Status: domain.ClientStatusActive,
		},
		"credential-free public with extra grant": {
			Id: domain.CodeAdminAudienceClientID, TenantId: "workload-x", Type: domain.ClientTypePublic,
			AllowedGrantTypes: []string{"token_exchange", "client_credentials"}, DefaultScopes: []string{"code-admin:audit:read"}, Status: domain.ClientStatusActive,
		},
		"inactive credential-free public": {
			Id: domain.CodeAdminAudienceClientID, TenantId: "workload-x", Type: domain.ClientTypePublic,
			AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: []string{"code-admin:audit:read"}, Status: domain.ClientStatusInactive,
		},
		"credential-free public with non-canonical scopes": {
			Id: domain.CodeAdminAudienceClientID, TenantId: "workload-x", Type: domain.ClientTypePublic,
			AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: []string{"code-admin:identity:write", "code-admin:audit:read", "code-admin:audit:read"}, Status: domain.ClientStatusActive,
		},
		"credential-free public in another tenant record": {
			Id: domain.CodeAdminAudienceClientID, TenantId: "workload-other", Type: domain.ClientTypePublic,
			AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: []string{"code-admin:audit:read"}, Status: domain.ClientStatusActive,
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newAIIdentityStores(t)
			if _, _, err := s.tenants.CreateIfAbsent(ctx, &domain.Tenant{Id: "workload-x", Slug: "workload-x", Name: "workload-x", Status: domain.TenantStatusActive, CreatedAt: time.Now().Add(-time.Hour).UTC()}); err != nil {
				t.Fatal(err)
			}
			if lookAlike != nil {
				if err := s.clients.Create(ctx, "workload-x", lookAlike); err != nil {
					t.Fatal(err)
				}
			}
			before := s.consoleCeiling(t, "workload-x")
			if _, _, err := s.service.Ensure(ctx, "workload-x", s.admin); !errors.Is(err, domain.ErrManagedClientConflict) {
				t.Fatalf("err=%v", err)
			}
			if after := s.consoleCeiling(t, "workload-x"); !reflect.DeepEqual(after, before) {
				t.Fatalf("look-alike was modified: %#v -> %#v", before, after)
			}
			for _, role := range AIGatewayRoleDefinitions("workload-x") {
				if stored, _ := s.roles.Get(ctx, "workload-x", role.Name); stored != nil {
					t.Fatalf("role %s was created after the ceiling conflict", role.Name)
				}
			}
			if roles := s.directRoles(t, "workload-x", s.admin); roles != nil {
				t.Fatalf("administrator was assigned after the ceiling conflict: %v", roles)
			}
			if audience, err := s.clients.Get(ctx, "workload-x", aigateway.Audience); err != nil || audience != nil {
				t.Fatalf("AI audience was activated after the ceiling conflict: %#v %v", audience, err)
			}
		})
	}
}

// Deactivation never shrinks the ceiling; the AI scopes are inert without the
// roles and the ACTIVE AI audience. Re-enabling replays the ceiling.
func TestAIGatewayIdentityDeactivationLeavesConsoleCeiling(t *testing.T) {
	ctx := context.Background()
	s := newAIIdentityStores(t, "workload-1")
	if _, _, err := s.service.Ensure(ctx, "workload-1", s.admin); err != nil {
		t.Fatal(err)
	}
	raised := s.consoleCeiling(t, "workload-1")
	if _, changed, err := s.service.Deactivate(ctx, "workload-1"); err != nil || !changed {
		t.Fatalf("deactivate changed=%v err=%v", changed, err)
	}
	if after := s.consoleCeiling(t, "workload-1"); !reflect.DeepEqual(after, raised) {
		t.Fatalf("deactivation changed the ceiling: %#v -> %#v", raised, after)
	}
	if _, _, err := s.service.Ensure(ctx, "workload-1", s.admin); err != nil {
		t.Fatal(err)
	}
	if after := s.consoleCeiling(t, "workload-1"); !reflect.DeepEqual(after, raised) {
		t.Fatalf("re-enable rewrote the ceiling: %#v -> %#v", raised, after)
	}
}

func TestRaiseManagedCodeAdminAudienceScopesRejectsNonCanonicalInput(t *testing.T) {
	ctx := context.Background()
	s := newAIIdentityStores(t, "workload-1")
	raiser := s.clients.(repository.CodeAdminAudienceScopeRaiser)
	for name, scopes := range map[string][]string{
		"empty":         nil,
		"unsorted":      {"code-admin:ai:write", "code-admin:ai:read"},
		"duplicate":     {"code-admin:ai:read", "code-admin:ai:read"},
		"padded":        {" code-admin:ai:read"},
		"unknown":       {"code-admin:ai:unknown"},
		"invalid chars": {"code-admin:ai read"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := raiser.RaiseManagedCodeAdminAudienceScopes(ctx, "workload-1", scopes); !errors.Is(err, domain.ErrInvalidArgument) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if got := s.consoleCeiling(t, "workload-1"); !slices.Equal(got.DefaultScopes, consoleBaselineScopes) {
		t.Fatalf("rejected input changed the ceiling: %v", got.DefaultScopes)
	}
	if _, _, err := raiser.RaiseManagedCodeAdminAudienceScopes(ctx, "Workload-1", []string{"code-admin:ai:read"}); err == nil {
		t.Fatal("non-canonical tenant accepted")
	}
}

func bootstrapLegacyHomeAudience(tenantID string, scopes []string) *domain.Client {
	return &domain.Client{
		Id: domain.CodeAdminAudienceClientID, TenantId: tenantID, Type: domain.ClientTypePublic,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     append([]string(nil), scopes...), Status: domain.ClientStatusActive,
	}
}

// The MASTER home tenant holds the bootstrap's secret-free legacy PUBLIC
// code-admin-api audience, which is never adopted as managed. Activation
// raises it additively in place and keeps its legacy shape.
func TestAIGatewayIdentityEnsureRaisesBootstrapLegacyHomeAudience(t *testing.T) {
	ctx := context.Background()
	s := newAIIdentityStores(t, "workload-2")
	if _, _, err := s.tenants.CreateIfAbsent(ctx, &domain.Tenant{Id: domain.MasterTenantID, Slug: domain.MasterTenantID, Name: domain.MasterTenantName, Status: domain.TenantStatusActive, CreatedAt: time.Now().Add(-time.Hour).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := s.clients.UpsertBootstrap(ctx, domain.MasterTenantID, bootstrapLegacyHomeAudience(domain.MasterTenantID, consoleBaselineScopes)); err != nil {
		t.Fatal(err)
	}
	got, created, err := s.service.Ensure(ctx, domain.MasterTenantID, s.admin)
	if err != nil || !created || got == nil {
		t.Fatalf("ensure=%#v created=%v err=%v", got, created, err)
	}
	ceiling := s.consoleCeiling(t, domain.MasterTenantID)
	want := []string{"code-admin:ai:read", "code-admin:ai:write", "code-admin:audit:read", "code-admin:identity:write"}
	if !domain.IsBootstrapLegacyCodeAdminAudience(domain.MasterTenantID, ceiling) ||
		domain.IsManagedCodeAdminAudience(domain.MasterTenantID, ceiling) || !slices.Equal(ceiling.DefaultScopes, want) {
		t.Fatalf("legacy home audience was not raised in place: %#v", ceiling)
	}
	for _, scope := range []string{"code-admin:ai:platform", aigateway.RuntimeScope} {
		if slices.Contains(ceiling.DefaultScopes, scope) {
			t.Fatalf("global scope %s entered the home ceiling", scope)
		}
	}
	// No managed marker was written: the bootstrap can still upsert it.
	if err := s.clients.UpsertBootstrap(ctx, domain.MasterTenantID, bootstrapLegacyHomeAudience(domain.MasterTenantID, want)); err != nil {
		t.Fatalf("bootstrap can no longer maintain the legacy home audience: %v", err)
	}
	if other := s.consoleCeiling(t, "workload-2"); !domain.IsManagedCodeAdminAudience("workload-2", other) || !slices.Equal(other.DefaultScopes, consoleBaselineScopes) {
		t.Fatalf("another tenant's ceiling changed: %#v", other)
	}
	again, created, err := s.service.Ensure(ctx, domain.MasterTenantID, s.admin)
	if err != nil || created || again == nil {
		t.Fatalf("replay=%#v created=%v err=%v", again, created, err)
	}
	if replayed := s.consoleCeiling(t, domain.MasterTenantID); !reflect.DeepEqual(replayed, ceiling) {
		t.Fatalf("replay rewrote the legacy ceiling: %#v != %#v", replayed, ceiling)
	}
	if again.Client.ClientId != aigateway.Audience || !slices.Equal(again.Client.DefaultScopes, AIGatewayClientScopes()) {
		t.Fatalf("response projection changed: %#v", again.Client)
	}
	if _, changed, err := s.service.Deactivate(ctx, domain.MasterTenantID); err != nil || !changed {
		t.Fatalf("deactivate changed=%v err=%v", changed, err)
	}
	if after := s.consoleCeiling(t, domain.MasterTenantID); !reflect.DeepEqual(after, ceiling) {
		t.Fatalf("deactivation changed the legacy ceiling: %#v -> %#v", ceiling, after)
	}
}

// Secret-bearing or unowned look-alikes in the MASTER tenant still conflict.
func TestAIGatewayIdentityEnsureConflictsOnMasterLookAlikes(t *testing.T) {
	ctx := context.Background()
	for name, lookAlike := range map[string]*domain.Client{
		"secret-bearing public": {
			Id: domain.CodeAdminAudienceClientID, TenantId: domain.MasterTenantID, SecretHash: "stored-hash", Type: domain.ClientTypePublic,
			AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: consoleBaselineScopes, Status: domain.ClientStatusActive,
		},
		"secret-bearing service": {
			Id: domain.CodeAdminAudienceClientID, TenantId: domain.MasterTenantID, SecretHash: "stored-hash", Type: domain.ClientTypeService,
			AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: consoleBaselineScopes, Status: domain.ClientStatusActive,
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newAIIdentityStores(t, domain.MasterTenantID+"-peer")
			if _, _, err := s.tenants.CreateIfAbsent(ctx, &domain.Tenant{Id: domain.MasterTenantID, Slug: domain.MasterTenantID, Name: domain.MasterTenantName, Status: domain.TenantStatusActive, CreatedAt: time.Now().Add(-time.Hour).UTC()}); err != nil {
				t.Fatal(err)
			}
			if err := s.clients.Create(ctx, domain.MasterTenantID, lookAlike); err != nil {
				t.Fatal(err)
			}
			before := s.consoleCeiling(t, domain.MasterTenantID)
			if _, _, err := s.service.Ensure(ctx, domain.MasterTenantID, s.admin); !errors.Is(err, domain.ErrManagedClientConflict) {
				t.Fatalf("err=%v", err)
			}
			if after := s.consoleCeiling(t, domain.MasterTenantID); !reflect.DeepEqual(after, before) {
				t.Fatalf("look-alike was modified: %#v -> %#v", before, after)
			}
			if audience, err := s.clients.Get(ctx, domain.MasterTenantID, aigateway.Audience); err != nil || audience != nil {
				t.Fatalf("AI audience was activated after the conflict: %#v %v", audience, err)
			}
		})
	}
}
