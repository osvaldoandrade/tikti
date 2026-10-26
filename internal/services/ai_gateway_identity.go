package services

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// AIGatewayIdentityService installs the closed, tenant-scoped identity records
// that AI user exchange requires. It never edits an existing role, never
// assigns a role to a principal and never accepts caller-selected scopes.
type AIGatewayIdentityService interface {
	Ensure(ctx context.Context, tenantID string) (*domain.AIGatewayIdentityResp, bool, error)
}

type aiGatewayIdentityService struct {
	tenants repository.TenantRepository
	roles   RoleService
	clients repository.ClientRepository
	now     func() time.Time
}

func NewAIGatewayIdentityService(tenants repository.TenantRepository, roles RoleService, clients repository.ClientRepository) AIGatewayIdentityService {
	return &aiGatewayIdentityService{tenants: tenants, roles: roles, clients: clients, now: time.Now}
}

// AIGatewayClientScopes is the complete ceiling of the managed AI audience.
func AIGatewayClientScopes() []string {
	return []string{aigateway.InvokeScope, aigateway.ModelsScope, aigateway.UsageScope}
}

// AIGatewayRoleDefinitions returns the two dedicated, tenant-prefixed roles.
// Usage is authorized by code-admin:ai:read, so no code-llm:usage:read grant
// exists. The global code-admin:ai:platform/runtime scopes are never present.
func AIGatewayRoleDefinitions(tenantID string) []domain.RoleResp {
	return []domain.RoleResp{
		{Name: tenantID + "-ai-admin", Permissions: []string{"code-admin:ai:read", "code-admin:ai:write", aigateway.InvokeScope, aigateway.ModelsScope}},
		{Name: tenantID + "-ai-user", Permissions: []string{"code-admin:ai:read", aigateway.InvokeScope, aigateway.ModelsScope}},
	}
}

func (s *aiGatewayIdentityService) Ensure(ctx context.Context, tenantID string) (*domain.AIGatewayIdentityResp, bool, error) {
	if s == nil || s.tenants == nil || s.roles == nil || s.clients == nil {
		return nil, false, domain.ErrAuthenticationUnavailable
	}
	if !validRoleTenantID(tenantID) || tenantID == domain.RetiredDefaultTenantID {
		return nil, false, domain.ErrInvalidTenant
	}
	tenant, err := s.tenants.Get(ctx, tenantID)
	if err != nil {
		return nil, false, err
	}
	if !activeTenant(tenant, tenantID, s.now().UTC()) {
		return nil, false, domain.ErrInvalidTenant
	}
	created := false
	roles := AIGatewayRoleDefinitions(tenantID)
	out := &domain.AIGatewayIdentityResp{TenantId: tenantID, Roles: make([]domain.RoleResp, 0, len(roles))}
	for _, role := range roles {
		// Policy self-check: a tenant AI role must contain only tenant-assignable
		// Code Admin scopes. This rejects any future edit adding platform scopes.
		permissions, valid := scopepolicy.CanonicalPermissions(role.Permissions)
		if !valid || !slices.Equal(permissions, role.Permissions) || slices.Contains(permissions, "code-admin:ai:platform") || slices.Contains(permissions, aigateway.RuntimeScope) {
			return nil, false, domain.ErrInvalidArgument
		}
		stored, roleCreated, roleErr := s.roles.CreateWithName(ctx, tenantID, role.Name, domain.RolePutReq{Permissions: permissions})
		if roleErr != nil {
			return nil, false, roleErr
		}
		if stored == nil || stored.Name != role.Name || !slices.Equal(stored.Permissions, permissions) {
			return nil, false, domain.ErrRoleConflict
		}
		created = created || roleCreated
		out.Roles = append(out.Roles, domain.RoleResp{Name: stored.Name, Permissions: append([]string(nil), stored.Permissions...)})
	}
	// The client ceiling is written last: its presence is the activation marker
	// read by user exchange, so a partial run never leaves a usable audience
	// without its dedicated roles.
	desired := &domain.Client{
		Id: domain.AIGatewayAudienceClientID, TenantId: tenantID, Type: domain.ClientTypeService,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     AIGatewayClientScopes(), Status: domain.ClientStatusActive,
		ManagedBy: domain.AIGatewayAudienceClientManager,
	}
	stored, clientCreated, err := s.clients.EnsureManagedAudience(ctx, tenantID, desired)
	if err != nil {
		if errors.Is(err, domain.ErrManagedClientConflict) {
			return nil, false, domain.ErrManagedClientConflict
		}
		return nil, false, err
	}
	if !domain.IsManagedAIGatewayAudience(tenantID, stored) || !slices.Equal(stored.DefaultScopes, desired.DefaultScopes) {
		return nil, false, domain.ErrManagedClientConflict
	}
	out.Client = domain.ManagedAudienceClientResp{
		ClientId: stored.Id, TenantId: stored.TenantId, Type: stored.Type,
		AllowedGrantTypes: append([]string(nil), stored.AllowedGrantTypes...),
		DefaultScopes:     append([]string(nil), stored.DefaultScopes...), Status: stored.Status,
	}
	return out, created || clientCreated, nil
}
