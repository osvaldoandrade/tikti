package services

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// Production failure 2026-10-27 (CODE): after ai-gateway activation the MASTER
// administrator holds the bootstrap ADMIN role (platform scopes, not tenant
// assignable) and <tenant>-ai-admin. The AI runtime exchange re-validated every
// role and refused the whole token (403) because of ADMIN, so the Console
// Playground could never obtain AI authority.
func TestAIUserEffectiveScopesIgnoreBootstrapMasterAdminRole(t *testing.T) {
	ctx := context.Background()
	tenantID := domain.MasterTenantID
	s := newAIIdentityStores(t, tenantID)
	seedBootstrapAdmin(t, s, tenantID, s.admin)
	if _, created, err := s.service.Ensure(ctx, tenantID, s.admin); err != nil || !created {
		t.Fatalf("activation created=%v err=%v", created, err)
	}
	svc := NewUserService(s.users, nil, NewRoleService(s.roles), NewClientService(s.clients),
		"jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithIdentityDirectoryAccess(s.directoryRepo),
		WithTenantTargetDiscoveryV2(true, []string{domain.MasterTenantID}, s.tenants),
	).(*userService)
	byID, ok := s.users.(repository.UserIDRepository)
	if !ok {
		t.Fatal("user repository lacks FindByID")
	}
	admin, err := byID.FindByID(ctx, s.admin)
	if err != nil || admin == nil {
		t.Fatalf("admin user: %#v %v", admin, err)
	}
	all := []string{aigateway.InvokeScope, aigateway.ModelsScope, aigateway.UsageScope}
	got, err := svc.aiUserEffectiveScopes(ctx, admin, tenantID, all)
	if err != nil || !slices.Equal(got, all) {
		t.Fatalf("MASTER AI admin scopes = %v, %v; want %v", got, err, all)
	}
	if err := svc.aiUserPermissions(ctx, admin, tenantID, all); err != nil {
		t.Fatalf("runtime validation of the same authority: %v", err)
	}

	// The generic tenant-scoped token authorization is unchanged: it still
	// refuses a holder of the non-exact role.
	if _, err := svc.resolveTenantScopedTokenAuthorization(ctx, admin, tenantID); !errors.Is(err, domain.ErrUnauthorizedScope) {
		t.Fatalf("generic authorization accepted a non-exact role: %v", err)
	}

	// ADMIN alone grants no AI authority: skipping a role only removes permissions.
	if _, _, err := s.directoryRepo.PutAccessAssignment(ctx, tenantID, domain.AccessPrincipalUser, s.otherUser, []string{"ADMIN"}, ""); err != nil {
		t.Fatal(err)
	}
	other, err := byID.FindByID(ctx, s.otherUser)
	if err != nil || other == nil {
		t.Fatalf("other user: %#v %v", other, err)
	}
	if got, err := svc.aiUserEffectiveScopes(ctx, other, tenantID, all); !errors.Is(err, domain.ErrUnauthorizedScope) {
		t.Fatalf("bootstrap ADMIN alone obtained AI scopes %v (%v)", got, err)
	}
}
