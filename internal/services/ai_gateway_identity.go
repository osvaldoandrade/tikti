package services

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// AIGatewayIdentityService owns the closed, tenant-scoped identity records
// that AI user exchange requires. Activation first additively raises the
// tenant's managed code-admin-api ceiling with the tenant AI scopes, then
// ensures the two dedicated roles, assigns only <tenant>-ai-admin to the enabling administrator's own user and
// then (re)activates the managed audience. Deactivation marks the managed
// audience INACTIVE and retains roles, assignments and the record itself. It
// never edits an existing role and never accepts caller-selected scopes.
type AIGatewayIdentityService interface {
	Ensure(ctx context.Context, tenantID, administratorID string) (*domain.AIGatewayIdentityResp, bool, error)
	Deactivate(ctx context.Context, tenantID string) (*domain.AIGatewayDeactivationResp, bool, error)
}

// AIGatewayClientStore is the managed-audience persistence the service needs.
type AIGatewayClientStore interface {
	repository.ClientRepository
	repository.ManagedAudienceStatusRepository
	repository.CodeAdminAudienceScopeRaiser
}

// AIGatewayAssignmentStore is the directory assignment authority used for the
// single administrator assignment. IdentityDirectoryService satisfies it and
// verifies the tenant, the user and the role definitions on every write.
type AIGatewayAssignmentStore interface {
	GetAssignment(ctx context.Context, tenantID string, kind domain.AccessPrincipalType, principalID string) (*domain.AccessAssignment, error)
	PutAssignment(ctx context.Context, tenantID string, kind domain.AccessPrincipalType, principalID string, roles []string, ifMatch string) (*domain.AccessAssignment, bool, error)
}

type aiGatewayIdentityService struct {
	tenants     repository.TenantRepository
	roles       RoleService
	clients     AIGatewayClientStore
	assignments AIGatewayAssignmentStore
	now         func() time.Time
}

const aiGatewayAssignmentAttempts = 4

func NewAIGatewayIdentityService(tenants repository.TenantRepository, roles RoleService, clients AIGatewayClientStore, assignments AIGatewayAssignmentStore) AIGatewayIdentityService {
	return &aiGatewayIdentityService{tenants: tenants, roles: roles, clients: clients, assignments: assignments, now: time.Now}
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
		{Name: AIGatewayAdminRole(tenantID), Permissions: []string{"code-admin:ai:read", "code-admin:ai:write", aigateway.InvokeScope, aigateway.ModelsScope}},
		{Name: tenantID + "-ai-user", Permissions: []string{"code-admin:ai:read", aigateway.InvokeScope, aigateway.ModelsScope}},
	}
}

// AIGatewayConsoleCeilingScopes are the only scopes activation adds to the
// tenant's managed code-admin-api ceiling, so the dynamic Console session can
// carry the tenant AI roles. They are exactly the tenant-assignable AI scopes;
// the global code-admin:ai:platform/runtime scopes are never added.
func AIGatewayConsoleCeilingScopes() []string {
	return []string{"code-admin:ai:read", "code-admin:ai:write"}
}

// AIGatewayAdminRole is the only role activation assigns.
func AIGatewayAdminRole(tenantID string) string { return tenantID + "-ai-admin" }

func (s *aiGatewayIdentityService) Ensure(ctx context.Context, tenantID, administratorID string) (*domain.AIGatewayIdentityResp, bool, error) {
	if s == nil || s.tenants == nil || s.roles == nil || s.clients == nil || s.assignments == nil {
		return nil, false, domain.ErrAuthenticationUnavailable
	}
	if strings.TrimSpace(administratorID) != administratorID || administratorID == "" {
		return nil, false, domain.ErrAIGatewayAdministrator
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
	created, err := s.raiseConsoleCeiling(ctx, tenantID)
	if err != nil {
		return nil, false, err
	}
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
	// Decision 3 (ADR-0024 Amendment 2): the enabling administrator, and only
	// that user, receives the tenant AI admin role. A failure stops before the
	// audience is (re)activated so the API does not store the feature.
	adminRole := AIGatewayAdminRole(tenantID)
	assigned, err := s.assignAdministrator(ctx, tenantID, administratorID, adminRole)
	if err != nil {
		return nil, false, err
	}
	created = created || assigned
	out.AdminAssignment = domain.AIGatewayAdminAssignmentResp{PrincipalId: administratorID, Role: adminRole}
	// The client ceiling is written last: its ACTIVE presence is the activation
	// marker read by user exchange, so a partial run never leaves a usable
	// audience without its dedicated roles. An INACTIVE record is reactivated.
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

// raiseConsoleCeiling additively ensures the tenant's managed code-admin-api
// client ceiling (or the bootstrap's secret-free legacy PUBLIC home audience,
// kept in its legacy shape) contains the tenant-assignable AI scopes (ADR-0024
// Amendment 2). It runs before any other write so a missing or unmanaged Console client
// fails closed without creating roles, assignments or the AI audience. The
// ceiling is never shrunk here or on deactivation: a ceiling scope grants
// nothing on its own; it only lets a tenant role that already carries the
// tenant-assignable AI scope reach the Console token, and AI exchange still
// requires the ACTIVE AI audience.
func (s *aiGatewayIdentityService) raiseConsoleCeiling(ctx context.Context, tenantID string) (bool, error) {
	scopes := AIGatewayConsoleCeilingScopes()
	// Policy self-check: only tenant-assignable reserved scopes may be added.
	for _, scope := range scopes {
		if !scopepolicy.TenantRoleAssignable(scope) || scope == "code-admin:ai:platform" || scope == aigateway.RuntimeScope {
			return false, domain.ErrInvalidArgument
		}
	}
	stored, changed, err := s.clients.RaiseManagedCodeAdminAudienceScopes(ctx, tenantID, scopes)
	if err != nil {
		if errors.Is(err, domain.ErrManagedClientConflict) {
			return false, domain.ErrManagedClientConflict
		}
		return false, err
	}
	// The repository accepts only the managed record or the bootstrap's
	// secret-free legacy PUBLIC home audience; re-check both here.
	if !domain.IsManagedCodeAdminAudience(tenantID, stored) && !domain.IsBootstrapLegacyCodeAdminAudience(tenantID, stored) {
		return false, domain.ErrManagedClientConflict
	}
	for _, scope := range scopes {
		if !slices.Contains(stored.DefaultScopes, scope) {
			return false, domain.ErrManagedClientConflict
		}
	}
	return changed, nil
}

// assignAdministrator adds role to the user's direct assignment in tenantID,
// preserving every existing role, with optimistic concurrency. It reports
// whether the assignment changed.
func (s *aiGatewayIdentityService) assignAdministrator(ctx context.Context, tenantID, userID, role string) (bool, error) {
	for range aiGatewayAssignmentAttempts {
		roles, ifMatch := []string{role}, ""
		current, err := s.assignments.GetAssignment(ctx, tenantID, domain.AccessPrincipalUser, userID)
		switch {
		case errors.Is(err, domain.ErrNotFound):
		case errors.Is(err, domain.ErrInvalidArgument):
			return false, domain.ErrAIGatewayAdministrator
		case err != nil:
			return false, err
		default:
			if current == nil || current.TenantID != tenantID || current.PrincipalType != domain.AccessPrincipalUser || current.PrincipalID != userID {
				return false, domain.ErrDirectoryInvariant
			}
			if slices.Contains(current.Roles, role) {
				return false, nil
			}
			roles = append(slices.Clone(current.Roles), role)
			ifMatch = repository.IdentityETag(current.Version)
		}
		stored, _, err := s.assignments.PutAssignment(ctx, tenantID, domain.AccessPrincipalUser, userID, roles, ifMatch)
		switch {
		case errors.Is(err, domain.ErrVersionConflict):
			continue
		case errors.Is(err, domain.ErrNotFound), errors.Is(err, domain.ErrInvalidTenant), errors.Is(err, domain.ErrInvalidArgument):
			return false, domain.ErrAIGatewayAdministrator
		case err != nil:
			return false, err
		}
		if stored == nil || stored.TenantID != tenantID || stored.PrincipalID != userID || len(stored.Roles) != len(roles) || !slices.Contains(stored.Roles, role) {
			return false, domain.ErrDirectoryInvariant
		}
		return true, nil
	}
	return false, domain.ErrVersionConflict
}

// Deactivate marks the tenant's managed AI audience INACTIVE (ADR-0024
// Amendment 2, decision 4). Roles, assignments and the credential-free record
// are retained; a tenant without the audience is a no-op that creates nothing.
// An unmanaged look-alike conflicts.
func (s *aiGatewayIdentityService) Deactivate(ctx context.Context, tenantID string) (*domain.AIGatewayDeactivationResp, bool, error) {
	if s == nil || s.tenants == nil || s.clients == nil {
		return nil, false, domain.ErrAuthenticationUnavailable
	}
	if !validRoleTenantID(tenantID) || tenantID == domain.RetiredDefaultTenantID {
		return nil, false, domain.ErrInvalidTenant
	}
	// Disabling only narrows access, so a suspended tenant may still deactivate;
	// the tenant record itself must exist under exactly this identifier.
	tenant, err := s.tenants.Get(ctx, tenantID)
	if err != nil {
		return nil, false, err
	}
	if tenant == nil || tenant.Id != tenantID {
		return nil, false, domain.ErrInvalidTenant
	}
	stored, changed, err := s.clients.SetManagedAudienceStatus(ctx, tenantID, domain.AIGatewayAudienceClientID, domain.AIGatewayAudienceClientManager, domain.ClientStatusInactive)
	if err != nil {
		return nil, false, err
	}
	out := &domain.AIGatewayDeactivationResp{TenantId: tenantID, ClientId: domain.AIGatewayAudienceClientID, Status: domain.AIGatewayClientAbsent}
	if stored == nil {
		return out, false, nil
	}
	if !domain.IsManagedAIGatewayAudienceRecord(tenantID, stored) || stored.Status != domain.ClientStatusInactive {
		return nil, false, domain.ErrManagedClientConflict
	}
	out.Status = stored.Status
	return out, changed, nil
}
