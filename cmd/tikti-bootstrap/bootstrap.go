package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type settings struct {
	tenantID         string
	tenantName       string
	email            string
	password         string
	passwordHash     string
	existingUserOnly bool
	audience         string
	scopes           []string
	workloadSubject  string
}

type stores struct {
	users       repository.UserRepository
	tenants     repository.TenantRepository
	memberships repository.MembershipRepository
	roles       repository.RoleRepository
	clients     repository.ClientRepository
	workloads   repository.WorkloadBindingRepository
	directory   repository.IdentityDirectoryRepository
}

type accountBrokerSettings struct {
	tenantID string
	audience string
	role     string
	scopes   []string
}

func bootstrap(ctx context.Context, data stores, cfg settings) error {
	if err := validateSettings(cfg); err != nil {
		return err
	}
	user, err := data.users.FindByEmail(ctx, cfg.email)
	if err != nil {
		return fmt.Errorf("get bootstrap user: %w", err)
	}
	if cfg.existingUserOnly {
		if user == nil || user.Status != domain.UserStatusActive || user.Role != domain.RoleAdmin ||
			user.AuthSource != domain.AuthSourcePassword || strings.TrimSpace(user.Password) == "" {
			return fmt.Errorf("existing bootstrap administrator is unavailable")
		}
		if err := utils.ValidatePasswordHash(user.Password); err != nil {
			return fmt.Errorf("existing bootstrap administrator credential is invalid")
		}
	}
	canonicalScopes, ok := scopepolicy.CanonicalAudienceScopes(cfg.scopes)
	if !ok {
		return fmt.Errorf("bootstrap scopes are invalid")
	}
	cfg.scopes = canonicalScopes
	if cfg.existingUserOnly {
		return bootstrapExistingUserMasterAccess(ctx, data, cfg, user)
	}
	tenant, err := data.tenants.Get(ctx, cfg.tenantID)
	if err != nil {
		return fmt.Errorf("get tenant: %w", err)
	}
	if tenant == nil {
		tenant = &domain.Tenant{
			Id: cfg.tenantID, Slug: cfg.tenantID, Name: cfg.tenantName,
			Status: domain.TenantStatusActive, CreatedAt: time.Now().UTC(),
		}
	} else {
		tenant.Name = cfg.tenantName
		tenant.Slug = cfg.tenantID
		tenant.Status = domain.TenantStatusActive
	}
	if err := data.tenants.Create(ctx, tenant); err != nil {
		return fmt.Errorf("upsert tenant: %w", err)
	}

	passwordHash := strings.TrimSpace(cfg.passwordHash)
	if passwordHash == "" {
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(cfg.password), bcrypt.DefaultCost)
		if hashErr != nil {
			return fmt.Errorf("hash bootstrap password: %w", hashErr)
		}
		passwordHash = string(hash)
	}
	if user == nil {
		user = &domain.User{Id: uuid.NewString(), Email: cfg.email, CreatedAt: time.Now().UTC()}
	}
	user.Email = cfg.email
	user.Password = passwordHash
	user.Role = domain.RoleAdmin
	user.Status = domain.UserStatusActive
	user.CompanyId = &cfg.tenantID
	user.AuthSource = domain.AuthSourcePassword
	if existing, verifyErr := data.users.FindByEmail(ctx, cfg.email); verifyErr != nil {
		return fmt.Errorf("verify bootstrap user: %w", verifyErr)
	} else if existing == nil {
		if err := data.users.CreateUser(ctx, user); err != nil {
			return fmt.Errorf("create bootstrap user: %w", err)
		}
	} else if err := data.users.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("update bootstrap user: %w", err)
	}

	if err := data.roles.Create(ctx, cfg.tenantID, &domain.Role{
		Name: "ADMIN", Scope: domain.RoleScopeTenant, TenantId: cfg.tenantID,
		Permissions: append([]string(nil), cfg.scopes...),
	}); err != nil {
		return fmt.Errorf("upsert bootstrap role: %w", err)
	}
	if data.directory != nil {
		if _, _, err := data.directory.PutAccessAssignment(ctx, cfg.tenantID, domain.AccessPrincipalUser, user.Id, []string{"ADMIN"}, ""); err != nil {
			return fmt.Errorf("upsert bootstrap access assignment: %w", err)
		}
	} else if err := data.memberships.Create(ctx, &domain.Membership{
		Id: uuid.NewString(), TenantId: cfg.tenantID, UserId: user.Id,
		Roles: []string{"ADMIN"}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		return fmt.Errorf("upsert bootstrap membership: %w", err)
	}
	if err := data.clients.UpsertBootstrap(ctx, cfg.tenantID, &domain.Client{
		Id: cfg.audience, TenantId: cfg.tenantID, Type: domain.ClientTypePublic,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     append([]string(nil), cfg.scopes...), Status: "ACTIVE",
	}); err != nil {
		return fmt.Errorf("upsert bootstrap client: %w", err)
	}
	if cfg.workloadSubject != "" {
		subject, valid := domain.ParseWorkloadSubject(cfg.workloadSubject)
		if !valid || data.workloads == nil {
			return fmt.Errorf("bootstrap workload subject is invalid")
		}
		if err := data.workloads.Upsert(ctx, &domain.WorkloadBinding{
			Subject: subject.Subject, Namespace: subject.Namespace, ServiceAccount: subject.ServiceAccount,
			Grants: []domain.WorkloadGrant{{
				TenantID: cfg.tenantID, Audience: domain.WorkloadTargetAudience,
				Scopes: []string{domain.WorkloadAdminScope},
			}},
			UpdatedAt: time.Now().UTC(),
		}); err != nil {
			return fmt.Errorf("upsert bootstrap workload binding: %w", err)
		}
	}
	return nil
}

// bootstrapExistingUserMasterAccess repairs an installation that has an
// existing workload administrator but no MASTER tenant. It deliberately leaves
// the user's credential, home tenant and identity fields untouched. Every
// object is create-once or installation-managed, and conflicting state fails
// closed before the access assignment is granted.
func bootstrapExistingUserMasterAccess(ctx context.Context, data stores, cfg settings, user *domain.User) error {
	roleScopes := make([]string, 0, len(cfg.scopes))
	for _, scope := range cfg.scopes {
		if scopepolicy.TenantRoleAssignable(scope) {
			roleScopes = append(roleScopes, scope)
		}
	}
	if len(roleScopes) == 0 {
		return fmt.Errorf("existing-user MASTER role has no tenant-assignable scopes")
	}

	desiredTenant := &domain.Tenant{
		Id: cfg.tenantID, Slug: cfg.tenantID, Name: cfg.tenantName,
		Status: domain.TenantStatusActive, CreatedAt: time.Now().UTC(),
	}
	storedTenant, _, err := data.tenants.CreateIfAbsent(ctx, desiredTenant)
	if err != nil || storedTenant == nil || storedTenant.Id != desiredTenant.Id ||
		storedTenant.Slug != desiredTenant.Slug || storedTenant.Name != desiredTenant.Name ||
		storedTenant.Status != desiredTenant.Status {
		return fmt.Errorf("ensure existing-user MASTER tenant: %w", conflictOr(err, domain.ErrTenantConflict))
	}

	desiredRole := &domain.Role{
		Name: "ADMIN", Scope: domain.RoleScopeTenant, TenantId: cfg.tenantID,
		Permissions: roleScopes,
	}
	storedRole, _, err := data.roles.CreateIfAbsent(ctx, cfg.tenantID, desiredRole)
	if err != nil || storedRole == nil || storedRole.Name != desiredRole.Name ||
		storedRole.Scope != desiredRole.Scope || storedRole.TenantId != desiredRole.TenantId ||
		storedRole.ResourceId != "" || !slices.Equal(storedRole.Permissions, desiredRole.Permissions) {
		return fmt.Errorf("ensure existing-user MASTER role: %w", conflictOr(err, domain.ErrRoleConflict))
	}

	desiredClient := &domain.Client{
		Id: cfg.audience, TenantId: cfg.tenantID, Type: domain.ClientTypeService,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     append([]string(nil), cfg.scopes...), Status: domain.ClientStatusActive,
		ManagedBy: domain.CodeAdminAudienceClientManager,
	}
	storedClient, _, err := data.clients.EnsureManagedAudience(ctx, cfg.tenantID, desiredClient)
	if err != nil || !domain.IsManagedCodeAdminAudience(cfg.tenantID, storedClient) ||
		!slices.Equal(storedClient.DefaultScopes, desiredClient.DefaultScopes) {
		return fmt.Errorf("ensure existing-user MASTER audience: %w", conflictOr(err, domain.ErrManagedClientConflict))
	}

	if data.directory == nil {
		return fmt.Errorf("existing-user MASTER recovery requires the identity directory")
	}
	if _, _, err := data.directory.PutAccessAssignment(
		ctx, cfg.tenantID, domain.AccessPrincipalUser, user.Id, []string{"ADMIN"}, "",
	); err != nil {
		return fmt.Errorf("ensure existing-user MASTER access assignment: %w", err)
	}
	return nil
}

func conflictOr(err error, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}

func bootstrapAccountBrokers(ctx context.Context, data stores, brokers []accountBrokerSettings) error {
	if len(brokers) > 16 {
		return fmt.Errorf("workload account bootstrap supports at most 16 clients")
	}
	seen := make(map[string]struct{}, len(brokers))
	for index, broker := range brokers {
		if strings.TrimSpace(broker.tenantID) != broker.tenantID || strings.TrimSpace(broker.audience) != broker.audience ||
			strings.TrimSpace(broker.role) != broker.role || broker.tenantID == "" || broker.audience == "" || broker.role == "" ||
			broker.role == "ADMIN" || !scopepolicy.ValidCanonicalPermissions(broker.scopes) ||
			!scopepolicy.ValidCanonicalAudienceScopes(broker.scopes) {
			return fmt.Errorf("workload account bootstrap client %d is invalid", index)
		}
		key := broker.tenantID + "\x00" + broker.audience
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("workload account bootstrap contains a duplicate client")
		}
		seen[key] = struct{}{}
		tenant, err := data.tenants.Get(ctx, broker.tenantID)
		if err == nil && tenant == nil {
			// A legacy installation client is not authority to resurrect a
			// removed tenant or to block a generic platform update. Missing
			// and unreadable tenants still fail closed without exact proof.
			if reader, ok := data.tenants.(interface {
				IsRetired(context.Context, string) (bool, error)
			}); ok {
				retired, retirementErr := reader.IsRetired(ctx, broker.tenantID)
				if retirementErr == nil && retired {
					continue
				}
			}
		}
		if err != nil || tenant == nil || tenant.Id != broker.tenantID || tenant.Status != domain.TenantStatusActive {
			return fmt.Errorf("workload account bootstrap tenant %q is unavailable", broker.tenantID)
		}
		desiredRole := &domain.Role{
			Name: broker.role, Scope: domain.RoleScopeTenant, TenantId: broker.tenantID,
			Permissions: append([]string(nil), broker.scopes...),
		}
		storedRole, _, err := data.roles.CreateIfAbsent(ctx, broker.tenantID, desiredRole)
		if err != nil || storedRole == nil || storedRole.Name != desiredRole.Name ||
			storedRole.Scope != desiredRole.Scope || storedRole.TenantId != desiredRole.TenantId ||
			!slices.Equal(storedRole.Permissions, desiredRole.Permissions) {
			return fmt.Errorf("workload account bootstrap role %q conflicts", broker.role)
		}
		desiredClient := &domain.Client{
			Id: broker.audience, TenantId: broker.tenantID, Type: domain.ClientTypeService,
			AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
			DefaultScopes:     append([]string(nil), broker.scopes...), Status: domain.ClientStatusActive,
			ManagedBy: domain.WorkloadAccountBFFClientManager,
		}
		storedClient, _, err := data.clients.EnsureManagedAudience(ctx, broker.tenantID, desiredClient)
		if err != nil || storedClient == nil || !domain.IsManagedWorkloadAccountAudience(broker.tenantID, storedClient) ||
			storedClient.Id != desiredClient.Id || !slices.Equal(storedClient.DefaultScopes, desiredClient.DefaultScopes) {
			return fmt.Errorf("workload account bootstrap audience %q conflicts", broker.audience)
		}
	}
	return nil
}

func validateSettings(cfg settings) error {
	if strings.TrimSpace(cfg.tenantID) == "" || strings.TrimSpace(cfg.tenantName) == "" {
		return fmt.Errorf("tenant id and name are required")
	}
	if strings.TrimSpace(cfg.email) == "" {
		return fmt.Errorf("bootstrap email is required")
	}
	if cfg.existingUserOnly {
		if cfg.tenantID != domain.MasterTenantID || cfg.tenantName != domain.MasterTenantName {
			return fmt.Errorf("existing-user-only bootstrap is restricted to the MASTER tenant")
		}
		if cfg.audience != domain.CodeAdminAudienceClientID {
			return fmt.Errorf("existing-user-only bootstrap requires the Code Admin audience")
		}
		if cfg.password != "" || cfg.passwordHash != "" {
			return fmt.Errorf("existing-user-only bootstrap cannot accept credential input")
		}
		if cfg.workloadSubject != "" {
			return fmt.Errorf("existing-user-only bootstrap cannot bind a workload subject")
		}
	} else if cfg.password != "" && cfg.passwordHash != "" {
		return fmt.Errorf("bootstrap password and password hash are mutually exclusive")
	} else if cfg.passwordHash != "" {
		if err := utils.ValidatePasswordHash(cfg.passwordHash); err != nil {
			return fmt.Errorf("bootstrap password hash is invalid: %w", err)
		}
	} else if len(cfg.password) < 12 {
		return fmt.Errorf("a bootstrap password of at least 12 characters is required")
	}
	if strings.TrimSpace(cfg.audience) == "" || len(cfg.scopes) == 0 {
		return fmt.Errorf("bootstrap audience and scopes are required")
	}
	if _, ok := scopepolicy.CanonicalAudienceScopes(cfg.scopes); !ok {
		return fmt.Errorf("bootstrap scopes are invalid")
	}
	if cfg.workloadSubject != "" {
		if _, valid := domain.ParseWorkloadSubject(cfg.workloadSubject); !valid {
			return fmt.Errorf("bootstrap workload subject is invalid")
		}
	}
	return nil
}
