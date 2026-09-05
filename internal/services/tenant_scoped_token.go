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

type tenantDiscoverySnapshot struct {
	authorizedTenants []string
	authorizations    map[string]tenantScopedTokenAuthorization
}

const (
	tenantFeatureAdministrationScope = "code-admin:features:write"
	maximumMembershipsScanned        = 500
	maximumAuthorizedTenantTargets   = 100
	maximumMembershipRoles           = 500
	maximumDynamicMembershipRoles    = 100
	maximumDiscoveryRoleLookups      = 500
)

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

func WithTenantTargetDiscoveryV2(enabled bool, principalTenants []string, tenantRepo repository.TenantRepository) UserServiceOption {
	return func(service *userService) {
		service.tenantRepo = tenantRepo
		service.tenantTargetDiscoveryV2 = enabled
		service.tenantTargetDiscoveryV2Principals = make(map[string]struct{}, len(principalTenants))
		for _, tenantID := range principalTenants {
			service.tenantTargetDiscoveryV2Principals[tenantID] = struct{}{}
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
	tenantIDs, exceeded, err := s.exactMembershipRepo.ListTenantIDsByUserExactBounded(
		ctx, user.Id, maximumMembershipsScanned,
	)
	if err != nil || exceeded || len(tenantIDs) == 0 || !containsString(tenantIDs, target) {
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
	if len(values) < 1 || len(values) > maximumMembershipRoles {
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
	dynamicTargets bool,
	metricMode string,
) (tenantDiscoveryAuthorization, error) {
	if target == "" || strings.TrimSpace(target) != target || !validRoleTenantID(target) ||
		!validSignedHome(user, home, signedRole) || s.clientSvc == nil {
		return tenantDiscoveryAuthorization{}, domain.ErrInvalidTenant
	}
	discovery, err := s.discoverTenantTargets(ctx, user, home, dynamicTargets, metricMode)
	if err != nil || !slices.Contains(discovery.authorizedTenants, target) {
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
	roles, authority, err := s.targetAuthority(
		ctx, user, target, home, signedRole, clientDefaults, dynamicTargets, discovery.authorizations,
	)
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
		authorizedTenants: discovery.authorizedTenants, roles: roles, scopes: effective,
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
	dynamicTargets bool,
) ([]string, error) {
	metricMode := "v1"
	if dynamicTargets {
		metricMode = "v2"
	}
	discovery, err := s.discoverTenantTargets(ctx, user, home, dynamicTargets, metricMode)
	return discovery.authorizedTenants, err
}

func (s *userService) discoverTenantTargets(
	ctx context.Context,
	user *domain.User,
	home string,
	dynamicTargets bool,
	metricMode string,
) (tenantDiscoverySnapshot, error) {
	if user == nil || user.Status != domain.UserStatusActive || s.exactMembershipRepo == nil || s.tenantRepo == nil {
		return tenantDiscoverySnapshot{}, domain.ErrInvalidTenant
	}
	homeTenant, err := s.tenantRepo.Get(ctx, home)
	if err != nil || homeTenant == nil || homeTenant.Id != home || homeTenant.Status != domain.TenantStatusActive {
		return tenantDiscoverySnapshot{}, domain.ErrInvalidTenant
	}
	tenantIDs, exceeded, err := s.exactMembershipRepo.ListTenantIDsByUserExactBounded(
		ctx, user.Id, maximumMembershipsScanned,
	)
	if err != nil || exceeded {
		if exceeded {
			s.tenantDiscoveryMetrics.observeOmission(metricMode, "membership_limit")
		}
		return tenantDiscoverySnapshot{}, domain.ErrInvalidTenant
	}
	allowed := map[string]struct{}{home: {}}
	authorizations := make(map[string]tenantScopedTokenAuthorization, len(tenantIDs))
	resolvedRoleLookups := 0
	for _, tenantID := range tenantIDs {
		if !dynamicTargets {
			if _, canary := s.tenantScopedTokenAllowlist[tenantID]; !canary {
				s.tenantDiscoveryMetrics.observeOmission(metricMode, "not_in_v1_cohort")
				continue
			}
		}
		membership, readErr := s.exactMembershipRepo.GetExact(ctx, tenantID, user.Id)
		if readErr != nil || membership == nil || membership.TenantId != tenantID || membership.UserId != user.Id {
			return tenantDiscoverySnapshot{}, domain.ErrInvalidTenant
		}
		roles, valid := canonicalMembershipRoles(membership.Roles)
		if !valid {
			return tenantDiscoverySnapshot{}, domain.ErrInvalidTenant
		}
		if dynamicTargets && len(roles) > maximumDynamicMembershipRoles {
			s.tenantDiscoveryMetrics.observeOmission(metricMode, "role_budget_exceeded")
			return tenantDiscoverySnapshot{}, domain.ErrInvalidTenant
		}
		tenant, tenantErr := s.tenantRepo.Get(ctx, tenantID)
		if tenantErr != nil {
			return tenantDiscoverySnapshot{}, domain.ErrInvalidTenant
		}
		if tenant == nil || tenant.Id != tenantID || tenant.Status != domain.TenantStatusActive {
			s.tenantDiscoveryMetrics.observeOmission(metricMode, "tenant_inactive")
			continue
		}
		if dynamicTargets && tenantID != home {
			client, clientErr := s.clientSvc.GetClient(ctx, tenantID, domain.CodeAdminAudienceClientID)
			if clientErr != nil || !domain.IsManagedCodeAdminAudience(tenantID, client) ||
				!scopepolicy.ValidCanonicalAudienceScopes(client.DefaultScopes) {
				s.tenantDiscoveryMetrics.observeOmission(metricMode, "audience_unavailable")
				continue
			}
		}
		if dynamicTargets && tenantID != home {
			if len(roles) > maximumDiscoveryRoleLookups-resolvedRoleLookups {
				s.tenantDiscoveryMetrics.observeOmission(metricMode, "role_budget_exceeded")
				return tenantDiscoverySnapshot{}, domain.ErrInvalidTenant
			}
			resolvedRoleLookups += len(roles)
			authorization, resolvable := s.resolveMembershipRoleAuthorization(ctx, tenantID, roles)
			if !resolvable {
				s.tenantDiscoveryMetrics.observeOmission(metricMode, "role_unresolvable")
				continue
			}
			authorizations[tenantID] = authorization
		}
		allowed[tenantID] = struct{}{}
		if dynamicTargets && len(allowed) > maximumAuthorizedTenantTargets {
			s.tenantDiscoveryMetrics.observeOmission(metricMode, "target_limit")
			return tenantDiscoverySnapshot{}, domain.ErrInvalidTenant
		}
	}
	result := make([]string, 0, len(allowed))
	for tenantID := range allowed {
		result = append(result, tenantID)
	}
	sort.Strings(result)
	return tenantDiscoverySnapshot{
		authorizedTenants: result,
		authorizations:    authorizations,
	}, nil
}

func (s *userService) resolveMembershipRoleAuthorization(
	ctx context.Context,
	tenantID string,
	roles []string,
) (tenantScopedTokenAuthorization, bool) {
	if s.roleSvc == nil {
		return tenantScopedTokenAuthorization{}, false
	}
	permissions := make(map[string]struct{})
	for _, roleName := range roles {
		role, err := s.roleSvc.GetByName(ctx, tenantID, roleName)
		if err != nil || role == nil || role.Name != roleName || !scopepolicy.ValidCanonicalPermissions(role.Permissions) {
			return tenantScopedTokenAuthorization{}, false
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
	return tenantScopedTokenAuthorization{
		roles: append([]string(nil), roles...), permissions: resolved,
	}, true
}

func (s *userService) targetAuthority(
	ctx context.Context,
	user *domain.User,
	target string,
	home string,
	signedRole string,
	candidates []string,
	dynamicTargets bool,
	authorizations map[string]tenantScopedTokenAuthorization,
) ([]string, []string, error) {
	if target == home {
		return nil, homeAuthority(user, signedRole, candidates), nil
	}
	var authorization tenantScopedTokenAuthorization
	if dynamicTargets {
		var authorized bool
		authorization, authorized = authorizations[target]
		if !authorized {
			return nil, nil, domain.ErrInvalidTenant
		}
	} else {
		strict, protected := s.tenantScopedTokenTarget(target)
		if !protected || strict == "" {
			return nil, nil, domain.ErrInvalidTenant
		}
		var err error
		authorization, err = s.resolveTenantScopedTokenAuthorization(ctx, user, strict)
		if err != nil {
			return nil, nil, err
		}
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
		user.CompanyId != nil && *user.CompanyId == home && signedRole == string(effectiveUserRole(user))
}

func homeAuthority(user *domain.User, signedRole string, candidates []string) []string {
	role := effectiveUserRole(user)
	if user == nil || signedRole != string(role) {
		return nil
	}
	switch role {
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
		// Feature writes are requested only by Code Admin's fixed, short-lived
		// tenant-admin profile. Preserve the exact target-membership boundary,
		// while allowing the signed built-in ADMIN and COMPANY_ADMIN identities
		// to perform that elevation without delegating it to a custom tenant role.
		if scopepolicy.RequiresHomeAuthority(scope) || scope == tenantFeatureAdministrationScope {
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
