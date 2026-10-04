package workloadaccount

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// Reconcile installs the role and managed, credential-free audience required by
// each installation-owned workload account broker. Tikti is the sole owner of
// these records; replay accepts only an exact match. A base-role scope change
// requires an explicit previous definition and an atomic exact replacement.
func Reconcile(
	ctx context.Context,
	tenants repository.TenantRepository,
	roles repository.RoleRepository,
	clients repository.ClientRepository,
	desired []config.WorkloadAccountBFFClientConfig,
) error {
	if len(desired) > 16 {
		return fmt.Errorf("workload account reconciliation supports at most 16 clients")
	}
	seen := make(map[string]struct{}, len(desired))
	for index, broker := range desired {
		if broker.TenantID == "" || broker.Audience == "" || broker.Role == "" ||
			strings.TrimSpace(broker.TenantID) != broker.TenantID ||
			strings.TrimSpace(broker.Audience) != broker.Audience ||
			strings.TrimSpace(broker.Role) != broker.Role ||
			broker.Role == "ADMIN" || broker.Namespace != "workload-"+broker.TenantID ||
			broker.ServiceAccount != broker.Audience || broker.TTLSeconds < 60 || broker.TTLSeconds > 3600 ||
			!scopepolicy.ValidCanonicalPermissions(broker.Scopes) ||
			!scopepolicy.ValidCanonicalAudienceScopes(broker.Scopes) ||
			!validMemberScopes(broker.TenantID, broker.MemberScopes) ||
			!validPreviousBaseRoleScopes(broker) ||
			!validAdditionalRoles(broker) {
			return fmt.Errorf("workload account client %d is invalid", index)
		}
		key := broker.TenantID + "\x00" + broker.Audience
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("workload account reconciliation contains a duplicate client")
		}
		seen[key] = struct{}{}
		tenant, err := tenants.Get(ctx, broker.TenantID)
		if err == nil && tenant == nil {
			// A retired installation client must not resurrect its tenant or
			// prevent an unrelated platform revision from starting.
			if reader, ok := tenants.(interface {
				IsRetired(context.Context, string) (bool, error)
			}); ok {
				retired, retirementErr := reader.IsRetired(ctx, broker.TenantID)
				if retirementErr == nil && retired {
					continue
				}
			}
		}
		if err != nil || tenant == nil || tenant.Id != broker.TenantID || tenant.Status != domain.TenantStatusActive {
			return fmt.Errorf("workload account tenant %q is unavailable: %w", broker.TenantID, domain.ErrInvalidTenant)
		}
		baseScopes := append(append([]string(nil), broker.Scopes...), broker.MemberScopes...)
		slices.Sort(baseScopes)
		desiredRole := &domain.Role{
			Name: broker.Role, Scope: domain.RoleScopeTenant, TenantId: broker.TenantID,
			Permissions: baseScopes,
		}
		storedRole, _, roleErr := roles.CreateIfAbsent(ctx, broker.TenantID, desiredRole)
		if roleErr != nil || storedRole == nil || storedRole.Name != desiredRole.Name ||
			storedRole.Scope != desiredRole.Scope || storedRole.TenantId != desiredRole.TenantId ||
			storedRole.ResourceId != "" ||
			!slices.Equal(storedRole.Permissions, desiredRole.Permissions) &&
				(len(broker.PreviousBaseRoleScopes) == 0 || !slices.Equal(storedRole.Permissions, broker.PreviousBaseRoleScopes)) {
			return fmt.Errorf("workload account role %q conflicts: %w", broker.Role, domain.ErrRoleConflict)
		}
		allScopes := append([]string(nil), baseScopes...)
		for _, extra := range broker.AdditionalRoles {
			allScopes = append(allScopes, extra.Scopes...)
		}
		slices.Sort(allScopes)
		allScopes = slices.Compact(allScopes)
		desiredClient := &domain.Client{
			Id: broker.Audience, TenantId: broker.TenantID, Type: domain.ClientTypeService,
			AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
			DefaultScopes:     allScopes, Status: domain.ClientStatusActive,
			ManagedBy: domain.WorkloadAccountBFFClientManager,
		}
		storedClient, _, clientErr := clients.EnsureManagedAudience(ctx, broker.TenantID, desiredClient)
		if clientErr != nil || storedClient == nil ||
			!domain.IsManagedWorkloadAccountAudience(broker.TenantID, storedClient) ||
			storedClient.Id != desiredClient.Id || !slices.Equal(storedClient.DefaultScopes, desiredClient.DefaultScopes) {
			return fmt.Errorf("workload account audience %q conflicts: %w", broker.Audience, domain.ErrManagedClientConflict)
		}
		if !slices.Equal(storedRole.Permissions, desiredRole.Permissions) {
			migrator, ok := roles.(repository.ExactRoleMigrationRepository)
			if !ok {
				return fmt.Errorf("workload account role %q cannot migrate: %w", broker.Role, domain.ErrRoleConflict)
			}
			previousRole := *desiredRole
			previousRole.Permissions = broker.PreviousBaseRoleScopes
			if err := migrator.ReplaceExact(ctx, broker.TenantID, &previousRole, desiredRole); err != nil {
				reader, ok := roles.(repository.ExactRoleRepository)
				if !ok {
					return fmt.Errorf("workload account role %q cannot migrate: %w", broker.Role, err)
				}
				current, readErr := reader.GetExact(ctx, broker.TenantID, broker.Role)
				if readErr != nil || current == nil || current.Name != desiredRole.Name ||
					current.Scope != desiredRole.Scope || current.TenantId != desiredRole.TenantId ||
					current.ResourceId != "" || !slices.Equal(current.Permissions, desiredRole.Permissions) {
					return fmt.Errorf("workload account role %q cannot migrate: %w", broker.Role, err)
				}
			}
		}
	}
	return nil
}

func validMemberScopes(tenantID string, scopes []string) bool {
	if len(scopes) == 0 {
		return true
	}
	if len(scopes) > 32 || !scopepolicy.ValidCanonicalPermissions(scopes) ||
		!scopepolicy.ValidCanonicalAudienceScopes(scopes) {
		return false
	}
	for _, scope := range scopes {
		if !strings.HasPrefix(scope, tenantID+":") || !strings.HasSuffix(scope, ":self") {
			return false
		}
	}
	return true
}

func validPreviousBaseRoleScopes(broker config.WorkloadAccountBFFClientConfig) bool {
	scopes := broker.PreviousBaseRoleScopes
	if len(scopes) == 0 {
		return true
	}
	if len(scopes) > 64 || !scopepolicy.ValidCanonicalPermissions(scopes) ||
		!scopepolicy.ValidCanonicalAudienceScopes(scopes) {
		return false
	}
	for _, scope := range scopes {
		if strings.HasPrefix(scope, broker.Audience+":") ||
			strings.HasPrefix(scope, broker.TenantID+":") && strings.HasSuffix(scope, ":self") {
			continue
		}
		return false
	}
	desired := append(append([]string(nil), broker.Scopes...), broker.MemberScopes...)
	slices.Sort(desired)
	return !slices.Equal(scopes, desired)
}

func validAdditionalRoles(broker config.WorkloadAccountBFFClientConfig) bool {
	if len(broker.AdditionalRoles) > 8 {
		return false
	}
	previous := ""
	for _, extra := range broker.AdditionalRoles {
		if extra.Role == "" || extra.Role <= previous || extra.Role == broker.Role ||
			strings.TrimSpace(extra.Role) != extra.Role ||
			!strings.HasPrefix(extra.Role, broker.TenantID+"-") ||
			!scopepolicy.ValidCanonicalPermissions(extra.Scopes) ||
			!scopepolicy.ValidCanonicalAudienceScopes(extra.Scopes) {
			return false
		}
		for _, scope := range extra.Scopes {
			if !strings.HasPrefix(scope, broker.TenantID+":") {
				return false
			}
		}
		previous = extra.Role
	}
	return true
}
