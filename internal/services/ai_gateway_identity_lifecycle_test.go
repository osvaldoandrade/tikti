package services

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// ADR-0024 Amendment 2, decision 3: activation assigns <tenant>-ai-admin to
// the enabling administrator only, preserving that user's existing roles.
func TestAIGatewayIdentityEnsureAssignsAdminRoleOnlyToEnablingAdministrator(t *testing.T) {
	ctx := context.Background()
	s := newAIIdentityStores(t, "tenant-1", "tenant-2")
	if _, _, err := NewRoleService(s.roles).CreateWithName(ctx, "tenant-1", "reader", domain.RolePutReq{Permissions: []string{"code-admin:services:read"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.directory.PutAssignment(ctx, "tenant-1", domain.AccessPrincipalUser, s.admin, []string{"reader"}, ""); err != nil {
		t.Fatal(err)
	}
	before, err := s.directory.GetAssignment(ctx, "tenant-1", domain.AccessPrincipalUser, s.admin)
	if err != nil {
		t.Fatal(err)
	}
	got, created, err := s.service.Ensure(ctx, "tenant-1", s.admin)
	if err != nil || !created {
		t.Fatalf("ensure=%#v created=%v err=%v", got, created, err)
	}
	if got.AdminAssignment != (domain.AIGatewayAdminAssignmentResp{PrincipalId: s.admin, Role: "tenant-1-ai-admin"}) {
		t.Fatalf("unexpected admin assignment: %#v", got.AdminAssignment)
	}
	if roles := s.directRoles(t, "tenant-1", s.admin); !slices.Equal(roles, []string{"reader", "tenant-1-ai-admin"}) {
		t.Fatalf("existing roles were not preserved or the admin role is missing: %v", roles)
	}
	if roles := s.directRoles(t, "tenant-1", s.otherUser); roles != nil {
		t.Fatalf("another user received an assignment: %v", roles)
	}
	if roles := s.directRoles(t, "tenant-2", s.admin); roles != nil {
		t.Fatalf("the administrator received a cross-tenant assignment: %v", roles)
	}
	page, err := s.directory.ListAssignments(ctx, "tenant-1", "", 100)
	if err != nil || len(page.Assignments) != 1 {
		t.Fatalf("activation implied more than one assignment: %#v %v", page, err)
	}
	for _, assignment := range page.Assignments {
		if slices.Contains(assignment.Roles, "tenant-1-ai-user") {
			t.Fatal("activation assigned the tenant AI user role")
		}
	}
	admin, _ := s.roles.Get(ctx, "tenant-1", "tenant-1-ai-admin")
	if admin == nil || slices.Contains(admin.Permissions, "code-admin:ai:platform") || slices.Contains(admin.Permissions, aigateway.RuntimeScope) {
		t.Fatalf("assigned role carries a platform scope: %#v", admin)
	}
	// Replay changes nothing, including the assignment version.
	again, created, err := s.service.Ensure(ctx, "tenant-1", s.admin)
	if err != nil || created || again.AdminAssignment.PrincipalId != s.admin {
		t.Fatalf("replay=%#v created=%v err=%v", again, created, err)
	}
	after, err := s.directory.GetAssignment(ctx, "tenant-1", domain.AccessPrincipalUser, s.admin)
	if err != nil || after.Version != before.Version+1 {
		t.Fatalf("replay rewrote the assignment: before=%d after=%#v err=%v", before.Version, after, err)
	}
	// A second administrator enabling again receives the role; the first keeps it.
	if _, created, err := s.service.Ensure(ctx, "tenant-1", s.otherUser); err != nil || !created {
		t.Fatalf("second administrator: created=%v err=%v", created, err)
	}
	if roles := s.directRoles(t, "tenant-1", s.otherUser); !slices.Equal(roles, []string{"tenant-1-ai-admin"}) {
		t.Fatalf("second administrator roles: %v", roles)
	}
}

func TestAIGatewayIdentityEnsureFailsClosedWhenAdministratorCannotBeAssigned(t *testing.T) {
	ctx := context.Background()
	for name, administrator := range map[string]string{
		"empty":             "",
		"padded":            " " + "user-1",
		"non-canonical":     "user/1",
		"unknown user":      "missing-user-1",
		"workload subject":  "system:serviceaccount:tenant-1:runtime",
		"client credential": "code-llm-service",
	} {
		t.Run(name, func(t *testing.T) {
			s := newAIIdentityStores(t, "tenant-1")
			if _, _, err := s.service.Ensure(ctx, "tenant-1", administrator); !errors.Is(err, domain.ErrAIGatewayAdministrator) {
				t.Fatalf("err=%v", err)
			}
			if client, err := s.clients.Get(ctx, "tenant-1", aigateway.Audience); err != nil || client != nil {
				t.Fatalf("audience was activated without an administrator assignment: %#v %v", client, err)
			}
		})
	}
}

type conflictingAssignments struct {
	AIGatewayAssignmentStore
	conflicts int
	puts      int
}

func (c *conflictingAssignments) AddExactUserRole(ctx context.Context, tenantID, userID, role string, permissions []string) (*domain.AccessAssignment, bool, error) {
	c.puts++
	if c.conflicts > 0 {
		c.conflicts--
		return nil, false, domain.ErrVersionConflict
	}
	return c.AIGatewayAssignmentStore.AddExactUserRole(ctx, tenantID, userID, role, permissions)
}

func TestAIGatewayIdentityAssignmentRetriesConcurrencyThenFailsClosed(t *testing.T) {
	ctx := context.Background()
	s := newAIIdentityStores(t, "tenant-1")
	store := s.statusStore.(AIGatewayClientStore)
	flaky := &conflictingAssignments{AIGatewayAssignmentStore: aiAssignmentStore(t, s.directory), conflicts: 1}
	service := NewAIGatewayIdentityService(s.tenants, NewRoleService(s.roles), store, flaky)
	if _, _, err := service.Ensure(ctx, "tenant-1", s.admin); err != nil || flaky.puts != 2 {
		t.Fatalf("single conflict was not retried: puts=%d err=%v", flaky.puts, err)
	}
	s = newAIIdentityStores(t, "tenant-1")
	store = s.statusStore.(AIGatewayClientStore)
	stuck := &conflictingAssignments{AIGatewayAssignmentStore: aiAssignmentStore(t, s.directory), conflicts: 1 << 10}
	service = NewAIGatewayIdentityService(s.tenants, NewRoleService(s.roles), store, stuck)
	if _, _, err := service.Ensure(ctx, "tenant-1", s.admin); !errors.Is(err, domain.ErrVersionConflict) || stuck.puts != aiGatewayAssignmentAttempts {
		t.Fatalf("persistent conflict: puts=%d err=%v", stuck.puts, err)
	}
	if client, _ := s.clients.Get(ctx, "tenant-1", aigateway.Audience); client != nil {
		t.Fatal("audience was activated after the assignment failed")
	}
	var missing *aiGatewayIdentityService = &aiGatewayIdentityService{tenants: s.tenants, roles: NewRoleService(s.roles), clients: store}
	if _, _, err := missing.Ensure(ctx, "tenant-1", s.admin); !errors.Is(err, domain.ErrAuthenticationUnavailable) {
		t.Fatalf("missing assignment authority: err=%v", err)
	}
}

// ADR-0024 Amendment 2, decision 4: disabling deactivates the managed AI
// audience, retaining roles, assignments and the record; enabling reactivates.
func TestAIGatewayIdentityDeactivateRetainsRecordsAndReactivates(t *testing.T) {
	ctx := context.Background()
	s := newAIIdentityStores(t, "tenant-1", "tenant-2")

	absent, changed, err := s.service.Deactivate(ctx, "tenant-1")
	if err != nil || changed || absent.Status != domain.AIGatewayClientAbsent || absent.ClientId != aigateway.Audience || absent.TenantId != "tenant-1" {
		t.Fatalf("disable without client=%#v changed=%v err=%v", absent, changed, err)
	}
	if client, err := s.clients.Get(ctx, "tenant-1", aigateway.Audience); err != nil || client != nil {
		t.Fatalf("deactivation created a client: %#v %v", client, err)
	}

	for _, tenant := range []string{"tenant-1", "tenant-2"} {
		if _, _, err := s.service.Ensure(ctx, tenant, s.admin); err != nil {
			t.Fatal(err)
		}
	}
	off, changed, err := s.service.Deactivate(ctx, "tenant-1")
	if err != nil || !changed || off.Status != domain.ClientStatusInactive {
		t.Fatalf("deactivate=%#v changed=%v err=%v", off, changed, err)
	}
	stored, err := s.clients.Get(ctx, "tenant-1", aigateway.Audience)
	if err != nil || stored == nil || stored.Status != domain.ClientStatusInactive || stored.SecretHash != "" ||
		!domain.IsManagedAIGatewayAudienceRecord("tenant-1", stored) || domain.IsManagedAIGatewayAudience("tenant-1", stored) ||
		!slices.Equal(stored.DefaultScopes, AIGatewayClientScopes()) {
		t.Fatalf("inactive record not retained exactly: %#v %v", stored, err)
	}
	listed, err := s.clients.List(ctx, "tenant-1")
	inactiveListed := 0
	for _, client := range listed {
		if client.Id == aigateway.Audience && client.Status == domain.ClientStatusInactive {
			inactiveListed++
		}
	}
	if err != nil || len(listed) != 2 || inactiveListed != 1 {
		t.Fatalf("inactive managed record breaks listing: %#v %v", listed, err)
	}
	for _, role := range AIGatewayRoleDefinitions("tenant-1") {
		if kept, _ := s.roles.Get(ctx, "tenant-1", role.Name); kept == nil || !slices.Equal(kept.Permissions, role.Permissions) {
			t.Fatalf("role %s was not retained: %#v", role.Name, kept)
		}
	}
	if roles := s.directRoles(t, "tenant-1", s.admin); !slices.Equal(roles, []string{"tenant-1-ai-admin"}) {
		t.Fatalf("assignment was not retained: %v", roles)
	}
	if other, _ := s.clients.Get(ctx, "tenant-2", aigateway.Audience); other == nil || other.Status != domain.ClientStatusActive {
		t.Fatalf("another tenant was deactivated: %#v", other)
	}
	replay, changed, err := s.service.Deactivate(ctx, "tenant-1")
	if err != nil || changed || replay.Status != domain.ClientStatusInactive {
		t.Fatalf("deactivate replay=%#v changed=%v err=%v", replay, changed, err)
	}

	on, created, err := s.service.Ensure(ctx, "tenant-1", s.admin)
	if err != nil || created || on.Client.Status != domain.ClientStatusActive {
		t.Fatalf("re-enable=%#v created=%v err=%v", on, created, err)
	}
	if stored, _ := s.clients.Get(ctx, "tenant-1", aigateway.Audience); !domain.IsManagedAIGatewayAudience("tenant-1", stored) {
		t.Fatalf("audience was not reactivated: %#v", stored)
	}
}

func TestAIGatewayIdentityDeactivateFailsClosedOnLookAlikesAndInvalidTenants(t *testing.T) {
	ctx := context.Background()
	t.Run("unmanaged look-alike", func(t *testing.T) {
		s := newAIIdentityStores(t, "tenant-1")
		lookAlike := &domain.Client{Id: aigateway.Audience, TenantId: "tenant-1", SecretHash: "x", Type: domain.ClientTypeService, AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: []string{aigateway.InvokeScope}, Status: domain.ClientStatusActive}
		if err := s.clients.Create(ctx, "tenant-1", lookAlike); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.service.Deactivate(ctx, "tenant-1"); !errors.Is(err, domain.ErrManagedClientConflict) {
			t.Fatalf("err=%v", err)
		}
		if kept, _ := s.clients.Get(ctx, "tenant-1", aigateway.Audience); kept == nil || kept.Status != domain.ClientStatusActive || kept.SecretHash != "x" {
			t.Fatalf("look-alike was modified: %#v", kept)
		}
	})
	t.Run("other manager cannot flip the AI audience", func(t *testing.T) {
		s := newAIIdentityStores(t, "tenant-1")
		if _, _, err := s.service.Ensure(ctx, "tenant-1", s.admin); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.statusStore.SetManagedAudienceStatus(ctx, "tenant-1", aigateway.Audience, domain.WorkloadAccountBFFClientManager, domain.ClientStatusInactive); !errors.Is(err, domain.ErrManagedClientConflict) {
			t.Fatalf("err=%v", err)
		}
		if _, _, err := s.statusStore.SetManagedAudienceStatus(ctx, "tenant-1", aigateway.Audience, domain.AIGatewayAudienceClientManager, "DELETED"); !errors.Is(err, domain.ErrInvalidArgument) {
			t.Fatalf("unknown status err=%v", err)
		}
	})
	t.Run("invalid tenants", func(t *testing.T) {
		s := newAIIdentityStores(t, "tenant-1")
		for _, id := range []string{"", "missing", domain.RetiredDefaultTenantID, "Tenant-1", "tenant_1"} {
			if _, _, err := s.service.Deactivate(ctx, id); !errors.Is(err, domain.ErrInvalidTenant) {
				t.Fatalf("tenant %q: err=%v", id, err)
			}
		}
	})
	t.Run("suspended tenant may still deactivate", func(t *testing.T) {
		s := newAIIdentityStores(t, "tenant-1")
		disabled := &domain.Tenant{Id: "tenant-off", Slug: "tenant-off", Name: "off", Status: domain.TenantStatusDisabled, CreatedAt: time.Now().Add(-time.Hour).UTC()}
		if _, _, err := s.tenants.CreateIfAbsent(ctx, disabled); err != nil {
			t.Fatal(err)
		}
		if out, _, err := s.service.Deactivate(ctx, "tenant-off"); err != nil || out.Status != domain.AIGatewayClientAbsent {
			t.Fatalf("out=%#v err=%v", out, err)
		}
	})
	t.Run("unconfigured", func(t *testing.T) {
		var nilService *aiGatewayIdentityService
		if _, _, err := nilService.Deactivate(ctx, "tenant-1"); err == nil {
			t.Fatal("nil service succeeded")
		}
	})
}

// Exchange closes while the audience is INACTIVE and reopens on re-enable.
func TestAIGatewayIdentityDeactivationClosesUserExchange(t *testing.T) {
	s, request, _, user, tenant := aiUserFixture(t)
	stores := newAIIdentityStores(t, tenant.Id)
	s.clientSvc = NewClientService(stores.clients)
	s.roleSvc = NewRoleService(stores.roles)
	members := &mockMembershipRepo{listExactFn: func(context.Context, string) ([]string, error) { return []string{tenant.Id}, nil }, getExactFn: func(context.Context, string, string) (*domain.Membership, error) {
		return &domain.Membership{TenantId: tenant.Id, UserId: user.Id, Roles: []string{tenant.Id + "-ai-user"}}, nil
	}}
	s.membershipRepo, s.exactMembershipRepo = members, members
	ctx := context.Background()
	if _, _, err := stores.service.Ensure(ctx, tenant.Id, stores.admin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TokenExchange(ctx, request); err != nil {
		t.Fatalf("active exchange failed: %v", err)
	}
	if _, _, err := stores.service.Deactivate(ctx, tenant.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TokenExchange(ctx, request); err == nil {
		t.Fatal("exchange succeeded while the AI audience was INACTIVE")
	}
	if _, _, err := stores.service.Ensure(ctx, tenant.Id, stores.admin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TokenExchange(ctx, request); err != nil {
		t.Fatalf("re-enabled exchange failed: %v", err)
	}
}
