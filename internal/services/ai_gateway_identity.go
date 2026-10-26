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
// single administrator assignment. The identity directory service satisfies
// it: AddExactUserRole validates the tenant and only the exact role being
// added, preserves every existing role of the user's direct assignment
// verbatim and writes with the observed version as If-Match. It is not part of
// the administrative IdentityDirectoryService surface.
type AIGatewayAssignmentStore interface {
	AddExactUserRole(ctx context.Context, tenantID, userID, roleName string, permissions []string) (*domain.AccessAssignment, bool, error)
}

// Closed Ensure stages attributed to a failure (audit and operator triage).
const (
	AIGatewayStageRequest    = "request"
	AIGatewayStageTenant     = "tenant"
	AIGatewayStageCeiling    = "ceiling"
	AIGatewayStageRoles      = "roles"
	AIGatewayStageAssignment = "assignment"
	AIGatewayStageAudience   = "audience"
)

// AIGatewayIdentityError attributes an Ensure failure to one closed stage.
// Error returns the wrapped error's text unchanged; errors.Is/As see through it.
type AIGatewayIdentityError struct {
	Stage string
	Err   error
}

func (e *AIGatewayIdentityError) Error() string { return e.Err.Error() }
func (e *AIGatewayIdentityError) Unwrap() error { return e.Err }

// AIGatewayIdentityFailureStage returns the closed stage of an Ensure failure,
// or "" when err carries none.
func AIGatewayIdentityFailureStage(err error) string {
	var staged *AIGatewayIdentityError
	if errors.As(err, &staged) && staged != nil {
		return staged.Stage
	}
	return ""
}

func aiGatewayStageError(stage string, err error) error {
	if repository.IsStoredRoleContractMismatch(err) {
		// A stored role under a server-owned name is not the exact tenant
		// definition: an actionable conflict, never an internal error.
		err = domain.ErrRoleConflict
	}
	return &AIGatewayIdentityError{Stage: stage, Err: err}
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
		return nil, false, aiGatewayStageError(AIGatewayStageRequest, domain.ErrAuthenticationUnavailable)
	}
	if strings.TrimSpace(administratorID) != administratorID || administratorID == "" {
		return nil, false, aiGatewayStageError(AIGatewayStageRequest, domain.ErrAIGatewayAdministrator)
	}
	if !validRoleTenantID(tenantID) || tenantID == domain.RetiredDefaultTenantID {
		return nil, false, aiGatewayStageError(AIGatewayStageRequest, domain.ErrInvalidTenant)
	}
	tenant, err := s.tenants.Get(ctx, tenantID)
	if err != nil {
		return nil, false, aiGatewayStageError(AIGatewayStageTenant, err)
	}
	if !activeTenant(tenant, tenantID, s.now().UTC()) {
		return nil, false, aiGatewayStageError(AIGatewayStageTenant, domain.ErrInvalidTenant)
	}
	created, err := s.raiseConsoleCeiling(ctx, tenantID)
	if err != nil {
		return nil, false, aiGatewayStageError(AIGatewayStageCeiling, err)
	}
	roles := AIGatewayRoleDefinitions(tenantID)
	out := &domain.AIGatewayIdentityResp{TenantId: tenantID, Roles: make([]domain.RoleResp, 0, len(roles))}
	for _, role := range roles {
		// Policy self-check: a tenant AI role must contain only tenant-assignable
		// Code Admin scopes. This rejects any future edit adding platform scopes.
		permissions, valid := scopepolicy.CanonicalPermissions(role.Permissions)
		if !valid || !slices.Equal(permissions, role.Permissions) || slices.Contains(permissions, "code-admin:ai:platform") || slices.Contains(permissions, aigateway.RuntimeScope) {
			return nil, false, aiGatewayStageError(AIGatewayStageRoles, domain.ErrInvalidArgument)
		}
		stored, roleCreated, roleErr := s.roles.CreateWithName(ctx, tenantID, role.Name, domain.RolePutReq{Permissions: permissions})
		if roleErr != nil {
			return nil, false, aiGatewayStageError(AIGatewayStageRoles, roleErr)
		}
		if stored == nil || stored.Name != role.Name || !slices.Equal(stored.Permissions, permissions) {
			return nil, false, aiGatewayStageError(AIGatewayStageRoles, domain.ErrRoleConflict)
		}
		created = created || roleCreated
		out.Roles = append(out.Roles, domain.RoleResp{Name: stored.Name, Permissions: append([]string(nil), stored.Permissions...)})
	}
	// Decision 3 (ADR-0024 Amendment 2): the enabling administrator, and only
	// that user, receives the tenant AI admin role. A failure stops before the
	// audience is (re)activated so the API does not store the feature.
	adminRole := AIGatewayAdminRole(tenantID)
	adminIndex := slices.IndexFunc(out.Roles, func(role domain.RoleResp) bool { return role.Name == adminRole })
	if adminIndex < 0 {
		return nil, false, aiGatewayStageError(AIGatewayStageRoles, domain.ErrRoleConflict)
	}
	assigned, err := s.assignAdministrator(ctx, tenantID, administratorID, out.Roles[adminIndex])
	if err != nil {
		return nil, false, aiGatewayStageError(AIGatewayStageAssignment, err)
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
			return nil, false, aiGatewayStageError(AIGatewayStageAudience, domain.ErrManagedClientConflict)
		}
		return nil, false, aiGatewayStageError(AIGatewayStageAudience, err)
	}
	if !domain.IsManagedAIGatewayAudience(tenantID, stored) || !slices.Equal(stored.DefaultScopes, desired.DefaultScopes) {
		return nil, false, aiGatewayStageError(AIGatewayStageAudience, domain.ErrManagedClientConflict)
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

// assignAdministrator adds only the exact tenant AI admin role to the user's
// direct assignment in tenantID through the narrow directory operation, which
// validates only that role and preserves every existing role verbatim. Each
// attempt writes with the observed version as If-Match; a version conflict is
// retried. It reports whether the assignment changed.
func (s *aiGatewayIdentityService) assignAdministrator(ctx context.Context, tenantID, userID string, role domain.RoleResp) (bool, error) {
	if role.Name != AIGatewayAdminRole(tenantID) {
		return false, domain.ErrInvalidArgument
	}
	for range aiGatewayAssignmentAttempts {
		stored, changed, err := s.assignments.AddExactUserRole(ctx, tenantID, userID, role.Name, slices.Clone(role.Permissions))
		switch {
		case errors.Is(err, domain.ErrVersionConflict):
			continue
		case errors.Is(err, domain.ErrNotFound), errors.Is(err, domain.ErrInvalidTenant), errors.Is(err, domain.ErrInvalidArgument):
			// Unknown or non-canonical user, or a SAML user bound to another tenant.
			return false, domain.ErrAIGatewayAdministrator
		case err != nil:
			return false, err
		}
		if stored == nil || stored.TenantID != tenantID || stored.PrincipalType != domain.AccessPrincipalUser ||
			stored.PrincipalID != userID || !slices.Contains(stored.Roles, role.Name) {
			return false, domain.ErrDirectoryInvariant
		}
		return changed, nil
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
