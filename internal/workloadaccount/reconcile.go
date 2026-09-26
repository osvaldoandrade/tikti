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
// these records; replay accepts only an exact match and never adopts a
// tenant-managed role or client with different authority.
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
			!scopepolicy.ValidCanonicalAudienceScopes(broker.Scopes) {
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
		desiredRole := &domain.Role{
			Name: broker.Role, Scope: domain.RoleScopeTenant, TenantId: broker.TenantID,
			Permissions: append([]string(nil), broker.Scopes...),
		}
		storedRole, _, roleErr := roles.CreateIfAbsent(ctx, broker.TenantID, desiredRole)
		if roleErr != nil || storedRole == nil || storedRole.Name != desiredRole.Name ||
			storedRole.Scope != desiredRole.Scope || storedRole.TenantId != desiredRole.TenantId ||
			storedRole.ResourceId != "" || !slices.Equal(storedRole.Permissions, desiredRole.Permissions) {
			return fmt.Errorf("workload account role %q conflicts: %w", broker.Role, domain.ErrRoleConflict)
		}
		desiredClient := &domain.Client{
			Id: broker.Audience, TenantId: broker.TenantID, Type: domain.ClientTypeService,
			AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
			DefaultScopes:     append([]string(nil), broker.Scopes...), Status: domain.ClientStatusActive,
			ManagedBy: domain.WorkloadAccountBFFClientManager,
		}
		storedClient, _, clientErr := clients.EnsureManagedAudience(ctx, broker.TenantID, desiredClient)
		if clientErr != nil || storedClient == nil ||
			!domain.IsManagedWorkloadAccountAudience(broker.TenantID, storedClient) ||
			storedClient.Id != desiredClient.Id || !slices.Equal(storedClient.DefaultScopes, desiredClient.DefaultScopes) {
			return fmt.Errorf("workload account audience %q conflicts: %w", broker.Audience, domain.ErrManagedClientConflict)
		}
	}
	return nil
}
