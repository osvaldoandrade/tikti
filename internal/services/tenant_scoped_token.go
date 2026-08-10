package services

import (
	"context"
	"sort"
	"strings"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type tenantScopedTokenAuthorization struct {
	roles       []string
	permissions []string
}

func WithTenantScopedTokenClaimsV1(enabled bool, tenants []string, tenantRepo repository.TenantRepository) UserServiceOption {
	return func(service *userService) {
		service.tenantRepo = tenantRepo
		service.tenantScopedTokenClaimsV1 = enabled
		service.tenantScopedTokenAllowlist = make(map[string]struct{}, len(tenants))
		for _, tenantID := range tenants {
			service.tenantScopedTokenAllowlist[tenantID] = struct{}{}
		}
	}
}

func (s *userService) tenantScopedTokenTarget(requested string) (string, bool) {
	if s == nil || !s.tenantScopedTokenClaimsV1 || requested == "" {
		return "", false
	}
	canonical := strings.ToLower(strings.TrimSpace(requested))
	if _, protected := s.tenantScopedTokenAllowlist[canonical]; !protected {
		return "", false
	}
	if canonical != requested {
		return "", true
	}
	return requested, true
}

func (s *userService) resolveTenantScopedTokenAuthorization(ctx context.Context, user *domain.User, target string) (tenantScopedTokenAuthorization, error) {
	if user == nil || user.Status != domain.UserStatusActive || !validRoleTenantID(target) || s.exactMembershipRepo == nil || s.tenantRepo == nil {
		return tenantScopedTokenAuthorization{}, domain.ErrInvalidTenant
	}
	tenantIDs, err := s.exactMembershipRepo.ListTenantIDsByUserExact(ctx, user.Id)
	if err != nil || len(tenantIDs) == 0 || !containsString(tenantIDs, target) {
		return tenantScopedTokenAuthorization{}, domain.ErrInvalidTenant
	}
	var selectedRoles []string
	for _, tenantID := range tenantIDs {
		membership, readErr := s.exactMembershipRepo.GetExact(ctx, tenantID, user.Id)
		if readErr != nil || membership == nil || membership.TenantId != tenantID || membership.UserId != user.Id {
			return tenantScopedTokenAuthorization{}, domain.ErrInvalidTenant
		}
		roles, valid := canonicalMembershipRoles(membership.Roles)
		if !valid {
			return tenantScopedTokenAuthorization{}, domain.ErrInvalidTenant
		}
		if tenantID == target {
			selectedRoles = roles
		}
	}
	tenant, err := s.tenantRepo.Get(ctx, target)
	if err != nil || tenant == nil || tenant.Id != target || tenant.Status != domain.TenantStatusActive {
		return tenantScopedTokenAuthorization{}, domain.ErrInvalidTenant
	}
	if s.roleSvc == nil {
		return tenantScopedTokenAuthorization{}, domain.ErrUnauthorizedScope
	}
	permissions := make(map[string]struct{})
	for _, roleName := range selectedRoles {
		role, roleErr := s.roleSvc.GetByName(ctx, target, roleName)
		if roleErr != nil || role == nil || role.Name != roleName || !validRolePermissions(role.Permissions) {
			return tenantScopedTokenAuthorization{}, domain.ErrUnauthorizedScope
		}
		for _, permission := range role.Permissions {
			permissions[permission] = struct{}{}
		}
	}
	resolved := make([]string, 0, len(permissions))
	for permission := range permissions {
		resolved = append(resolved, permission)
	}
	sort.Strings(resolved)
	return tenantScopedTokenAuthorization{roles: selectedRoles, permissions: resolved}, nil
}

func canonicalMembershipRoles(values []string) ([]string, bool) {
	if len(values) < 1 || len(values) > 500 {
		return nil, false
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	for index, value := range out {
		if !validRoleName(value) || index > 0 && out[index-1] == value {
			return nil, false
		}
	}
	return out, true
}
