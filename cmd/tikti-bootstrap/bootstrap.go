package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type settings struct {
	tenantID        string
	tenantName      string
	email           string
	password        string
	audience        string
	scopes          []string
	workloadSubject string
}

type stores struct {
	users       repository.UserRepository
	tenants     repository.TenantRepository
	memberships repository.MembershipRepository
	roles       repository.RoleRepository
	clients     repository.ClientRepository
	workloads   repository.WorkloadBindingRepository
}

func bootstrap(ctx context.Context, data stores, cfg settings) error {
	if err := validateSettings(cfg); err != nil {
		return err
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

	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash bootstrap password: %w", err)
	}
	user, err := data.users.FindByEmail(ctx, cfg.email)
	if err != nil {
		return fmt.Errorf("get bootstrap user: %w", err)
	}
	if user == nil {
		user = &domain.User{Id: uuid.NewString(), Email: cfg.email, CreatedAt: time.Now().UTC()}
	}
	user.Email = cfg.email
	user.Password = string(hash)
	user.Role = domain.RoleAdmin
	user.Status = domain.UserStatusActive
	user.CompanyId = &cfg.tenantID
	user.AuthSource = domain.AuthSourcePassword
	if existing, err := data.users.FindByEmail(ctx, cfg.email); err != nil {
		return fmt.Errorf("verify bootstrap user: %w", err)
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
	if err := data.memberships.Create(ctx, &domain.Membership{
		Id: uuid.NewString(), TenantId: cfg.tenantID, UserId: user.Id,
		Roles: []string{"ADMIN"}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		return fmt.Errorf("upsert bootstrap membership: %w", err)
	}
	if err := data.clients.Create(ctx, cfg.tenantID, &domain.Client{
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

func validateSettings(cfg settings) error {
	if strings.TrimSpace(cfg.tenantID) == "" || strings.TrimSpace(cfg.tenantName) == "" {
		return fmt.Errorf("tenant id and name are required")
	}
	if strings.TrimSpace(cfg.email) == "" || len(cfg.password) < 12 {
		return fmt.Errorf("bootstrap email and a password of at least 12 characters are required")
	}
	if strings.TrimSpace(cfg.audience) == "" || len(cfg.scopes) == 0 {
		return fmt.Errorf("bootstrap audience and scopes are required")
	}
	for _, scope := range cfg.scopes {
		if strings.TrimSpace(scope) == "" {
			return fmt.Errorf("bootstrap scopes must not contain empty values")
		}
	}
	if cfg.workloadSubject != "" {
		if _, valid := domain.ParseWorkloadSubject(cfg.workloadSubject); !valid {
			return fmt.Errorf("bootstrap workload subject is invalid")
		}
	}
	return nil
}
