package services

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestTenantCreatorAccessUsesExistingFederatedPlatformAuthority(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	users := repository.NewRedisRepo(client)
	tenants := repository.NewTenantRepo(client)
	roles := repository.NewRoleRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	if err := tenants.Create(ctx, &domain.Tenant{Id: "new-tenant", Slug: "new-tenant", Name: "New tenant"}); err != nil {
		t.Fatal(err)
	}
	home := domain.MasterTenantID
	user := &domain.User{Id: "platform-creator", Email: "creator@example.test", Role: domain.RoleAdmin, Status: domain.UserStatusActive, AuthSource: domain.AuthSourceSAML, CompanyId: &home, ExternalSubject: "saml-creator", CreatedAt: time.Now().UTC()}
	if err := users.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	service := NewIdentityDirectoryService(directory, users, tenants.(repository.ExactTenantRepository), roles.(repository.ExactRoleBatchRepository), false)
	resolver, ok := service.(interface {
		CreatorAccess(context.Context, string, string, string) (string, error)
	})
	if !ok {
		t.Fatal("creator access cannot distinguish existing platform authority from tenant membership")
	}
	mode, err := resolver.CreatorAccess(ctx, "new-tenant", user.Id, domain.PlatformPrivilegeAdmin)
	if err != nil || mode != "PLATFORM" {
		t.Fatalf("mode=%s err=%v", mode, err)
	}
	if mode, err = resolver.CreatorAccess(ctx, "new-tenant", user.Id, ""); err == nil || mode == "PLATFORM" {
		t.Fatal("unsigned platform privilege accepted")
	}
	assignments, err := directory.ListAccessAssignments(ctx, "new-tenant", "", 50)
	if err != nil || len(assignments.Assignments) != 0 {
		t.Fatal("platform access resolution created a foreign SAML membership")
	}
	for _, tc := range []struct {
		id, home, mode string
		source         domain.AuthSource
		role           domain.UserRole
		status         domain.UserStatus
	}{
		{"local-admin", "", "MEMBERSHIP", domain.AuthSourcePassword, domain.RoleAdmin, domain.UserStatusActive},
		{"foreign-saml", "other-tenant", "", domain.AuthSourceSAML, domain.RoleAdmin, domain.UserStatusActive},
		{"inactive-master", domain.MasterTenantID, "", domain.AuthSourceSAML, domain.RoleAdmin, domain.UserStatusSuspended},
		{"nonadmin-master", domain.MasterTenantID, "", domain.AuthSourceSAML, domain.RoleCompanyEmployee, domain.UserStatusActive},
	} {
		t.Run(tc.id, func(t *testing.T) {
			candidate := &domain.User{Id: tc.id, Email: tc.id + "@example.test", Role: tc.role, Status: tc.status, AuthSource: tc.source, CompanyId: &tc.home, ExternalSubject: tc.id, CreatedAt: time.Now().UTC()}
			if tc.source == domain.AuthSourcePassword {
				candidate.CompanyId = nil
				candidate.ExternalSubject = ""
				candidate.Password = "test-only-password-hash"
			}
			if err := users.CreateUser(ctx, candidate); err != nil {
				t.Fatal(err)
			}
			mode, err := resolver.CreatorAccess(ctx, "new-tenant", candidate.Id, domain.PlatformPrivilegeAdmin)
			if tc.mode == "" && (err == nil || mode != "") || tc.mode != "" && (err != nil || mode != tc.mode) {
				t.Fatalf("mode=%q err=%v", mode, err)
			}
		})
	}
}

func TestRetiredTenantRevokesCurrentTokenTarget(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	repo := repository.NewTenantRepo(client)
	ctx := context.Background()
	if err := repo.Create(ctx, &domain.Tenant{Id: "fresh-tenant", Slug: "fresh-tenant", Name: "Fresh tenant"}); err != nil {
		t.Fatal(err)
	}
	service := &userService{tenantRepo: repo}
	claims := jwt.MapClaims{"tid": "fresh-tenant"}
	if err := service.validateCurrentAccessTokenTarget(ctx, claims); err != nil {
		t.Fatal(err)
	}
	retirer := repo.(interface {
		Retire(context.Context, string) error
	})
	if err := retirer.Retire(ctx, "fresh-tenant"); err != nil {
		t.Fatal(err)
	}
	if err := service.validateCurrentAccessTokenTarget(ctx, claims); err == nil {
		t.Fatal("already-issued tenant token retained authority after removal")
	}
	if active, err := NewTenantService(repo).IsTenantActive(ctx, "fresh-tenant"); err != nil || active {
		t.Fatalf("retired tenant active=%v err=%v", active, err)
	}
}
