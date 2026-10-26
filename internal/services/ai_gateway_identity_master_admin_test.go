package services

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// bootstrapAdminScopes are platform scopes the MASTER bootstrap ADMIN role
// carries. They are valid audience scopes but not tenant-assignable, so the
// stored ADMIN role is not an exact tenant role definition.
var bootstrapAdminScopes = []string{"code-admin:clusters:admin", "code-admin:platform:admin", "code-admin:tenants:admin"}

// seedBootstrapAdmin reproduces tikti-bootstrap: the legacy role upsert of
// ADMIN with platform scopes and a direct repository assignment ["ADMIN"].
func seedBootstrapAdmin(t *testing.T, s aiIdentityStores, tenantID, userID string) (*domain.Role, *domain.AccessAssignment) {
	t.Helper()
	ctx := context.Background()
	scopes, ok := scopepolicy.CanonicalAudienceScopes(bootstrapAdminScopes)
	if !ok || scopepolicy.ValidCanonicalPermissions(scopes) {
		t.Fatalf("fixture no longer reproduces a non-tenant-assignable bootstrap role: %v ok=%v", scopes, ok)
	}
	if err := s.roles.Create(ctx, tenantID, &domain.Role{Name: "ADMIN", Scope: domain.RoleScopeTenant, TenantId: tenantID, Permissions: scopes}); err != nil {
		t.Fatal(err)
	}
	assignment, _, err := s.directoryRepo.PutAccessAssignment(ctx, tenantID, domain.AccessPrincipalUser, userID, []string{"ADMIN"}, "")
	if err != nil {
		t.Fatal(err)
	}
	role, err := s.roles.Get(ctx, tenantID, "ADMIN")
	if err != nil || role == nil {
		t.Fatalf("bootstrap role: %#v %v", role, err)
	}
	return role, assignment
}

// Production failure 2026-10-26: the MASTER administrator (bootstrap ADMIN with
// platform scopes) enabled AI; adding <tenant>-ai-admin re-validated ADMIN as
// an exact tenant role and failed with an unmapped 500.
func TestAIGatewayIdentityEnsurePreservesBootstrapMasterAdminRole(t *testing.T) {
	ctx := context.Background()
	tenantID := domain.MasterTenantID
	s := newAIIdentityStores(t, tenantID)
	adminRole, before := seedBootstrapAdmin(t, s, tenantID, s.admin)

	got, created, err := s.service.Ensure(ctx, tenantID, s.admin)
	if err != nil || !created || got == nil {
		t.Fatalf("ensure=%#v created=%v err=%v", got, created, err)
	}
	if got.AdminAssignment != (domain.AIGatewayAdminAssignmentResp{PrincipalId: s.admin, Role: tenantID + "-ai-admin"}) {
		t.Fatalf("unexpected admin assignment: %#v", got.AdminAssignment)
	}
	after, err := s.directory.GetAssignment(ctx, tenantID, domain.AccessPrincipalUser, s.admin)
	if err != nil || !slices.Equal(after.Roles, []string{"ADMIN", tenantID + "-ai-admin"}) || after.Version != before.Version+1 {
		t.Fatalf("assignment=%#v err=%v", after, err)
	}
	if kept, err := s.roles.Get(ctx, tenantID, "ADMIN"); err != nil || kept == nil || kept.Name != adminRole.Name ||
		kept.Scope != adminRole.Scope || kept.TenantId != adminRole.TenantId || !slices.Equal(kept.Permissions, adminRole.Permissions) {
		t.Fatalf("bootstrap ADMIN role changed: %#v %v", kept, err)
	}
	aiAdmin, err := s.roles.Get(ctx, tenantID, tenantID+"-ai-admin")
	if err != nil || aiAdmin == nil || !slices.Equal(aiAdmin.Permissions, AIGatewayRoleDefinitions(tenantID)[0].Permissions) {
		t.Fatalf("AI admin role is not the exact definition: %#v %v", aiAdmin, err)
	}

	again, created, err := s.service.Ensure(ctx, tenantID, s.admin)
	if err != nil || created || again.AdminAssignment.PrincipalId != s.admin {
		t.Fatalf("replay=%#v created=%v err=%v", again, created, err)
	}
	replayed, err := s.directory.GetAssignment(ctx, tenantID, domain.AccessPrincipalUser, s.admin)
	if err != nil || replayed.Version != after.Version || !slices.Equal(replayed.Roles, after.Roles) {
		t.Fatalf("replay rewrote the assignment: %#v %v", replayed, err)
	}

	// The administrative PutAssignment is not relaxed: it still validates every
	// role it writes and rejects the non-exact ADMIN without changing anything.
	if _, _, err := s.directory.PutAssignment(ctx, tenantID, domain.AccessPrincipalUser, s.admin, []string{"ADMIN", tenantID + "-ai-admin"}, repository.IdentityETag(replayed.Version)); err == nil || !repository.IsStoredRoleContractMismatch(err) {
		t.Fatalf("generic PutAssignment accepted a non-exact role: %v", err)
	}
	if _, _, err := s.directory.PutAssignment(ctx, tenantID, domain.AccessPrincipalUser, s.otherUser, []string{"ADMIN"}, ""); err == nil {
		t.Fatal("generic PutAssignment accepted a non-exact role for another user")
	}
	if unchanged, _ := s.directory.GetAssignment(ctx, tenantID, domain.AccessPrincipalUser, s.admin); unchanged.Version != replayed.Version {
		t.Fatalf("rejected generic write changed the assignment: %#v", unchanged)
	}

	// Deactivation still retains the assignment verbatim.
	if _, _, err := s.service.Deactivate(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	if roles := s.directRoles(t, tenantID, s.admin); !slices.Equal(roles, []string{"ADMIN", tenantID + "-ai-admin"}) {
		t.Fatalf("deactivation changed the assignment: %v", roles)
	}
}

// racingDirectory interleaves one concurrent writer between the exact
// operation's read of the assignment and its If-Match write.
type racingDirectory struct {
	repository.IdentityDirectoryRepository
	reads int
	race  func()
}

func (r *racingDirectory) GetAccessAssignment(ctx context.Context, tenantID string, kind domain.AccessPrincipalType, principalID string) (*domain.AccessAssignment, error) {
	current, err := r.IdentityDirectoryRepository.GetAccessAssignment(ctx, tenantID, kind, principalID)
	r.reads++
	if r.reads == 1 && r.race != nil {
		r.race()
	}
	return current, err
}

func racingAIService(t *testing.T, s aiIdentityStores, race func()) (AIGatewayIdentityService, *racingDirectory) {
	t.Helper()
	racing := &racingDirectory{IdentityDirectoryRepository: s.directoryRepo, race: race}
	directory := NewIdentityDirectoryService(racing, s.users, s.tenants.(repository.ExactTenantRepository), s.roles.(repository.ExactRoleBatchRepository), false)
	return NewAIGatewayIdentityService(s.tenants, NewRoleService(s.roles), s.statusStore.(AIGatewayClientStore), aiAssignmentStore(t, directory)), racing
}

func TestAIGatewayIdentityAssignmentNeverOverwritesConcurrentChanges(t *testing.T) {
	ctx := context.Background()
	tenantID := domain.MasterTenantID
	t.Run("concurrent addition is retried and preserved", func(t *testing.T) {
		s := newAIIdentityStores(t, tenantID)
		seedBootstrapAdmin(t, s, tenantID, s.admin)
		if _, _, err := NewRoleService(s.roles).CreateWithName(ctx, tenantID, "reader", domain.RolePutReq{Permissions: []string{"code-admin:services:read"}}); err != nil {
			t.Fatal(err)
		}
		service, racing := racingAIService(t, s, func() {
			if _, _, err := s.directoryRepo.PutAccessAssignment(ctx, tenantID, domain.AccessPrincipalUser, s.admin, []string{"ADMIN", "reader"}, "*"); err != nil {
				t.Error(err)
			}
		})
		if _, _, err := service.Ensure(ctx, tenantID, s.admin); err != nil || racing.reads != 2 {
			t.Fatalf("reads=%d err=%v", racing.reads, err)
		}
		if roles := s.directRoles(t, tenantID, s.admin); !slices.Equal(roles, []string{"ADMIN", tenantID + "-ai-admin", "reader"}) {
			t.Fatalf("concurrent change was overwritten: %v", roles)
		}
	})
	t.Run("concurrent removal is not resurrected", func(t *testing.T) {
		s := newAIIdentityStores(t, tenantID)
		seedBootstrapAdmin(t, s, tenantID, s.admin)
		service, racing := racingAIService(t, s, func() {
			if _, err := s.directoryRepo.DeleteAccessAssignment(ctx, tenantID, domain.AccessPrincipalUser, s.admin, "*"); err != nil {
				t.Error(err)
			}
		})
		if _, _, err := service.Ensure(ctx, tenantID, s.admin); err != nil || racing.reads != 2 {
			t.Fatalf("reads=%d err=%v", racing.reads, err)
		}
		if roles := s.directRoles(t, tenantID, s.admin); !slices.Equal(roles, []string{tenantID + "-ai-admin"}) {
			t.Fatalf("removed roles were resurrected: %v", roles)
		}
	})
	t.Run("concurrent creation is retried and preserved", func(t *testing.T) {
		s := newAIIdentityStores(t, tenantID)
		if err := s.roles.Create(ctx, tenantID, &domain.Role{Name: "ADMIN", Scope: domain.RoleScopeTenant, TenantId: tenantID, Permissions: []string{"code-admin:tenants:admin"}}); err != nil {
			t.Fatal(err)
		}
		service, racing := racingAIService(t, s, func() {
			if _, _, err := s.directoryRepo.PutAccessAssignment(ctx, tenantID, domain.AccessPrincipalUser, s.admin, []string{"ADMIN"}, ""); err != nil {
				t.Error(err)
			}
		})
		if _, _, err := service.Ensure(ctx, tenantID, s.admin); err != nil || racing.reads != 2 {
			t.Fatalf("reads=%d err=%v", racing.reads, err)
		}
		if roles := s.directRoles(t, tenantID, s.admin); !slices.Equal(roles, []string{"ADMIN", tenantID + "-ai-admin"}) {
			t.Fatalf("concurrently created assignment was overwritten: %v", roles)
		}
	})
}

func TestAIGatewayIdentityAssignmentRefusesIneligibleUsers(t *testing.T) {
	ctx := context.Background()
	tenantID := domain.MasterTenantID
	t.Run("user missing", func(t *testing.T) {
		s := newAIIdentityStores(t, tenantID)
		_, _, err := s.service.Ensure(ctx, tenantID, "missing-user-1")
		if !errors.Is(err, domain.ErrAIGatewayAdministrator) || AIGatewayIdentityFailureStage(err) != AIGatewayStageAssignment {
			t.Fatalf("stage=%q err=%v", AIGatewayIdentityFailureStage(err), err)
		}
	})
	t.Run("SAML user bound to another tenant", func(t *testing.T) {
		s := newAIIdentityStores(t, tenantID, "other-tenant")
		home := "other-tenant"
		user := &domain.User{Id: "foreign-saml", Email: "foreign-saml@example.test", Role: domain.RoleAdmin, Status: domain.UserStatusActive, AuthSource: domain.AuthSourceSAML, CompanyId: &home, ExternalSubject: "foreign-saml", CreatedAt: time.Now().UTC()}
		if err := s.users.CreateUser(ctx, user); err != nil {
			t.Fatal(err)
		}
		_, _, err := s.service.Ensure(ctx, tenantID, user.Id)
		if !errors.Is(err, domain.ErrAIGatewayAdministrator) || AIGatewayIdentityFailureStage(err) != AIGatewayStageAssignment {
			t.Fatalf("stage=%q err=%v", AIGatewayIdentityFailureStage(err), err)
		}
		if roles := s.directRoles(t, tenantID, user.Id); roles != nil {
			t.Fatalf("foreign SAML user received an assignment: %v", roles)
		}
		if client, _ := s.clients.Get(ctx, tenantID, domain.AIGatewayAudienceClientID); client != nil {
			t.Fatal("audience was activated without an administrator assignment")
		}
	})
}

func TestAddExactUserRoleValidatesOnlyTheAddedRole(t *testing.T) {
	ctx := context.Background()
	tenantID := domain.MasterTenantID
	s := newAIIdentityStores(t, tenantID)
	store := aiAssignmentStore(t, s.directory)
	seedBootstrapAdmin(t, s, tenantID, s.admin)
	permissions := []string{"code-admin:services:read"}
	if _, _, err := store.AddExactUserRole(ctx, tenantID, s.admin, "reader", permissions); !errors.Is(err, domain.ErrMembershipDependencyNotFound) {
		t.Fatalf("absent role: err=%v", err)
	}
	if _, _, err := NewRoleService(s.roles).CreateWithName(ctx, tenantID, "reader", domain.RolePutReq{Permissions: permissions}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddExactUserRole(ctx, tenantID, s.admin, "reader", []string{"code-admin:services:read", "code-admin:services:write"}); !errors.Is(err, domain.ErrRoleConflict) {
		t.Fatalf("different definition: err=%v", err)
	}
	// The added role itself must be an exact tenant-assignable definition.
	if _, _, err := store.AddExactUserRole(ctx, tenantID, s.admin, "ADMIN", bootstrapAdminScopes); !errors.Is(err, domain.ErrRoleConflict) {
		t.Fatalf("non-tenant-assignable added role: err=%v", err)
	}
	stored, changed, err := store.AddExactUserRole(ctx, tenantID, s.admin, "reader", permissions)
	if err != nil || !changed || !slices.Equal(stored.Roles, []string{"ADMIN", "reader"}) {
		t.Fatalf("add=%#v changed=%v err=%v", stored, changed, err)
	}
	replay, changed, err := store.AddExactUserRole(ctx, tenantID, s.admin, "reader", permissions)
	if err != nil || changed || replay.Version != stored.Version {
		t.Fatalf("replay=%#v changed=%v err=%v", replay, changed, err)
	}
	if _, _, err := store.AddExactUserRole(ctx, "tenant-absent", s.admin, "reader", permissions); err == nil {
		t.Fatal("absent tenant accepted")
	}
	// A full assignment is a directory state (409), never a caller identity
	// refusal, and is left untouched.
	full := make([]string, 0, 100)
	for index := range 100 {
		full = append(full, fmt.Sprintf("bulk-%03d", index))
	}
	saturated, _, err := s.directoryRepo.PutAccessAssignment(ctx, tenantID, domain.AccessPrincipalUser, s.otherUser, full, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AddExactUserRole(ctx, tenantID, s.otherUser, "reader", permissions); !errors.Is(err, domain.ErrDirectoryInvariant) {
		t.Fatalf("saturated assignment: err=%v", err)
	}
	if kept, _ := s.directory.GetAssignment(ctx, tenantID, domain.AccessPrincipalUser, s.otherUser); kept.Version != saturated.Version {
		t.Fatalf("saturated assignment changed: %#v", kept)
	}
}
