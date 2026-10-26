package services

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// AddExactUserRole adds exactly one tenant role to one user's direct
// assignment in tenantID. It is a narrow operation reserved for server-owned
// activations (the AI identity Ensure path); the administrative API keeps the
// generic PutAssignment, which re-validates every role it writes.
//
// Only the role being added is validated: it must exist in tenantID as the
// exact, tenant-scoped definition with exactly permissions, and permissions
// must be canonical and tenant-assignable. Every other role already present in
// the user's assignment is preserved verbatim and never re-read or
// re-validated: it was accepted by its own writer (for example the bootstrap
// MASTER ADMIN role, which carries platform scopes that are not
// tenant-assignable).
//
// This is a single optimistic attempt: the write uses the observed assignment
// version as If-Match (or create-only when no assignment was observed), so a
// concurrent change is never overwritten and surfaces as
// domain.ErrVersionConflict for the caller to retry. A role already present is
// a no-op. changed reports whether the stored assignment changed.
func (s *identityDirectoryService) AddExactUserRole(ctx context.Context, tenantID, userID, roleName string, permissions []string) (*domain.AccessAssignment, bool, error) {
	if s == nil || s.directory == nil || s.tenants == nil || s.roles == nil {
		return nil, false, domain.ErrDirectoryInvariant
	}
	// The definition is server-owned: a malformed or non-tenant-assignable
	// definition can never be the exact stored role.
	canonical, valid := scopepolicy.CanonicalPermissions(permissions)
	if roleName == "" || strings.TrimSpace(roleName) != roleName || !valid || !slices.Equal(canonical, permissions) {
		return nil, false, domain.ErrRoleConflict
	}
	tenant, err := s.tenants.GetExact(ctx, tenantID)
	if err != nil || tenant == nil {
		if err == nil {
			err = domain.ErrNotFound
		}
		return nil, false, err
	}
	if tenant.Status != domain.TenantStatusActive {
		return nil, false, domain.ErrMembershipDependencyInactive
	}
	definitions, err := s.roles.GetManyExact(ctx, tenantID, []string{roleName})
	if err != nil {
		return nil, false, err
	}
	if len(definitions) != 1 {
		return nil, false, domain.ErrDirectoryInvariant
	}
	definition := definitions[0]
	if definition == nil {
		return nil, false, domain.ErrMembershipDependencyNotFound
	}
	if definition.Name != roleName || definition.TenantId != tenantID || definition.Scope != domain.RoleScopeTenant ||
		definition.ResourceId != "" || !slices.Equal(definition.Permissions, permissions) {
		return nil, false, domain.ErrRoleConflict
	}
	current, err := s.directory.GetAccessAssignment(ctx, tenantID, domain.AccessPrincipalUser, userID)
	if err != nil {
		return nil, false, err
	}
	roles, ifMatch := []string{roleName}, ""
	if current != nil {
		if current.TenantID != tenantID || current.PrincipalType != domain.AccessPrincipalUser || current.PrincipalID != userID {
			return nil, false, domain.ErrDirectoryInvariant
		}
		if slices.Contains(current.Roles, roleName) {
			return current, false, nil
		}
		roles = append(slices.Clone(current.Roles), roleName)
		ifMatch = repository.IdentityETag(current.Version)
	}
	expected := slices.Clone(roles)
	sort.Strings(expected)
	stored, created, err := s.directory.PutAccessAssignment(ctx, tenantID, domain.AccessPrincipalUser, userID, roles, ifMatch)
	if errors.Is(err, domain.ErrInvalidArgument) {
		// The read above already accepted this tenant and principal with the
		// same checks, so the write can only refuse the role set itself (for
		// example the per-assignment role bound): a directory state, not a
		// caller identity problem.
		return nil, false, domain.ErrDirectoryInvariant
	}
	if err != nil {
		return nil, false, err
	}
	if stored == nil || stored.TenantID != tenantID || stored.PrincipalType != domain.AccessPrincipalUser ||
		stored.PrincipalID != userID || !slices.Equal(stored.Roles, expected) {
		return nil, false, domain.ErrDirectoryInvariant
	}
	changed := created || current == nil || stored.Version != current.Version
	return stored, changed, nil
}
