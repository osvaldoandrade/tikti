package services

import (
	"context"
	"slices"
	"sort"
	"strings"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type tenantScopedTokenAuthorization struct {
	roles       []string
	permissions []string
}

type tenantDiscoveryAuthorization struct {
	tenantID          string
	principalTenantID string
	authorizedTenants []string
	roles             []string
	scopes            []string
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
		if roleErr != nil || role == nil || role.Name != roleName || !scopepolicy.ValidCanonicalPermissions(role.Permissions) {
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

func (s *userService) resolveTenantDiscoveryAuthorization(
	ctx context.Context,
	user *domain.User,
	target string,
	home string,
	signedRole string,
	scopeCeiling []string,
	requestedScopes []string,
) (tenantDiscoveryAuthorization, error) {
	if target == "" || strings.TrimSpace(target) != target || !validRoleTenantID(target) ||
		!validSignedHome(user, home, signedRole) || s.clientSvc == nil {
		return tenantDiscoveryAuthorization{}, domain.ErrInvalidTenant
	}
	authorized, err := s.authorizedTenantTargets(ctx, user, home)
	if err != nil || !slices.Contains(authorized, target) {
		return tenantDiscoveryAuthorization{}, domain.ErrInvalidTenant
	}
	ceiling, ok := scopepolicy.CanonicalAudienceScopes(scopeCeiling)
	if !ok {
		return tenantDiscoveryAuthorization{}, domain.ErrInvalidArgument
	}
	client, err := s.clientSvc.GetClient(ctx, target, domain.CodeAdminAudienceClientID)
	if err != nil {
		return tenantDiscoveryAuthorization{}, err
	}
	var clientDefaults []string
	if client != nil {
		clientDefaults = client.DefaultScopes
	}
	if target == home {
		canonical, valid := scopepolicy.CanonicalAudienceScopes(clientDefaults)
		if !validHomeAudienceClient(target, client) || !valid || len(canonical) != len(clientDefaults) {
			return tenantDiscoveryAuthorization{}, domain.ErrInvalidAudience
		}
		clientDefaults = canonical
	} else if !domain.IsManagedCodeAdminAudience(target, client) ||
		!scopepolicy.ValidCanonicalAudienceScopes(clientDefaults) {
		return tenantDiscoveryAuthorization{}, domain.ErrInvalidAudience
	}
	roles, authority, err := s.targetAuthority(ctx, user, target, home, signedRole, clientDefaults)
	if err != nil {
		return tenantDiscoveryAuthorization{}, err
	}
	effective := intersectScopeSets(clientDefaults, authority, ceiling)
	if len(requestedScopes) > 0 {
		requested, valid := scopepolicy.CanonicalAudienceScopes(requestedScopes)
		if !valid {
			return tenantDiscoveryAuthorization{}, domain.ErrUnauthorizedScope
		}
		if !subset(requested, effective) {
			return tenantDiscoveryAuthorization{}, domain.ErrUnauthorizedScope
		}
		effective = requested
	}
	if len(effective) == 0 {
		return tenantDiscoveryAuthorization{}, domain.ErrUnauthorizedScope
	}
	return tenantDiscoveryAuthorization{
		tenantID: target, principalTenantID: home,
		authorizedTenants: authorized, roles: roles, scopes: effective,
	}, nil
}

func validHomeAudienceClient(tenantID string, client *domain.Client) bool {
	if client == nil || client.Id != domain.CodeAdminAudienceClientID || client.TenantId != tenantID ||
		client.Status != domain.ClientStatusActive ||
		!slices.Equal(client.AllowedGrantTypes, []string{string(domain.GrantTypeTokenExchange)}) {
		return false
	}
	if client.ManagedBy == "" {
		return client.Type == domain.ClientTypePublic && client.SecretHash == ""
	}
	return domain.IsManagedCodeAdminAudience(tenantID, client)
}

func (s *userService) authorizedTenantTargets(
	ctx context.Context,
	user *domain.User,
	home string,
) ([]string, error) {
	if s.exactMembershipRepo == nil || s.tenantRepo == nil {
		return nil, domain.ErrInvalidTenant
	}
	homeTenant, err := s.tenantRepo.Get(ctx, home)
	if err != nil || homeTenant == nil || homeTenant.Id != home || homeTenant.Status != domain.TenantStatusActive {
		return nil, domain.ErrInvalidTenant
	}
	tenantIDs, err := s.exactMembershipRepo.ListTenantIDsByUserExact(ctx, user.Id)
	if err != nil || len(tenantIDs) > 500 {
		return nil, domain.ErrInvalidTenant
	}
	allowed := map[string]struct{}{home: {}}
	for _, tenantID := range tenantIDs {
		if _, canary := s.tenantScopedTokenAllowlist[tenantID]; !canary {
			continue
		}
		membership, readErr := s.exactMembershipRepo.GetExact(ctx, tenantID, user.Id)
		if readErr != nil || membership == nil || membership.TenantId != tenantID || membership.UserId != user.Id {
			return nil, domain.ErrInvalidTenant
		}
		if _, valid := canonicalMembershipRoles(membership.Roles); !valid {
			return nil, domain.ErrInvalidTenant
		}
		tenant, tenantErr := s.tenantRepo.Get(ctx, tenantID)
		if tenantErr != nil {
			return nil, domain.ErrInvalidTenant
		}
		if tenant != nil && tenant.Id == tenantID && tenant.Status == domain.TenantStatusActive {
			allowed[tenantID] = struct{}{}
		}
	}
	result := make([]string, 0, len(allowed))
	for tenantID := range allowed {
		result = append(result, tenantID)
	}
	sort.Strings(result)
	return result, nil
}

func (s *userService) targetAuthority(
	ctx context.Context,
	user *domain.User,
	target string,
	home string,
	signedRole string,
	candidates []string,
) ([]string, []string, error) {
	if target == home {
		return nil, homeAuthority(user, signedRole, candidates), nil
	}
	strict, protected := s.tenantScopedTokenTarget(target)
	if !protected || strict == "" {
		return nil, nil, domain.ErrInvalidTenant
	}
	authorization, err := s.resolveTenantScopedTokenAuthorization(ctx, user, strict)
	if err != nil {
		return nil, nil, err
	}
	authority := make([]string, 0, len(authorization.permissions)+len(candidates))
	for _, permission := range authorization.permissions {
		if scopepolicy.TenantRoleAssignable(permission) {
			authority = append(authority, permission)
		}
	}
	authority = append(authority, homeGlobalAuthority(user, signedRole, candidates)...)
	return authorization.roles, normalizePermissions(authority), nil
}

func validSignedHome(user *domain.User, home, signedRole string) bool {
	return user != nil && user.Status == domain.UserStatusActive && validRoleTenantID(home) &&
		user.CompanyId != nil && *user.CompanyId == home && signedRole == string(user.Role)
}

func homeAuthority(user *domain.User, signedRole string, candidates []string) []string {
	if user == nil || signedRole != string(user.Role) {
		return nil
	}
	switch user.Role {
	case domain.RoleAdmin:
		return append([]string(nil), candidates...)
	case domain.RoleCompanyAdmin:
		result := make([]string, 0, len(candidates))
		for _, scope := range candidates {
			if scope != domain.PlatformTenantAdminScope {
				result = append(result, scope)
			}
		}
		return result
	default:
		return nil
	}
}

func homeGlobalAuthority(user *domain.User, signedRole string, candidates []string) []string {
	fromHome := homeAuthority(user, signedRole, candidates)
	result := make([]string, 0, len(fromHome))
	for _, scope := range fromHome {
		if scopepolicy.RequiresHomeAuthority(scope) {
			result = append(result, scope)
		}
	}
	return result
}

func intersectScopeSets(first []string, others ...[]string) []string {
	result := append([]string(nil), first...)
	for _, values := range others {
		allowed := make(map[string]struct{}, len(values))
		for _, value := range values {
			allowed[value] = struct{}{}
		}
		filtered := result[:0]
		for _, value := range result {
			if _, exists := allowed[value]; exists {
				filtered = append(filtered, value)
			}
		}
		result = filtered
	}
	return append([]string(nil), result...)
}
