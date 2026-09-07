package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestIdentityDirectoryServiceTemporaryPasswordLifecycle(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	users := repository.NewRedisRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	service := NewIdentityDirectoryService(directory, users, nil, nil, false)

	created, err := service.CreateUser(context.Background(), domain.DirectoryUserCreateReq{Email: " NEW@Example.COM ", TemporaryPassword: "temporary-1234"})
	if err != nil || created.Email != "new@example.com" || !created.PasswordChangeRequired {
		t.Fatalf("create = %#v, %v", created, err)
	}
	stored, err := users.FindByEmail(context.Background(), created.Email)
	if err != nil || stored == nil || stored.Password == "temporary-1234" || !utils.VerifyPassword(stored.Password, "temporary-1234") || stored.CompanyId != nil {
		t.Fatalf("stored temporary user = %#v, %v", stored, err)
	}
	tokens := NewUserService(users, nil, nil, nil, "jwt-secret", "https://tikti", "tikti", "", "")
	if response, signInErr := tokens.SignIn(context.Background(), domain.SignInReq{Email: created.Email, Password: "temporary-1234"}); response != nil || !errors.Is(signInErr, domain.ErrPasswordChangeRequired) {
		t.Fatalf("temporary sign-in = %#v, %v", response, signInErr)
	}
	if _, err = service.CreateUser(context.Background(), domain.DirectoryUserCreateReq{Email: "NEW@example.com", TemporaryPassword: "temporary-5678"}); !errors.Is(err, domain.ErrEmailExists) {
		t.Fatalf("duplicate = %v", err)
	}
	if err = service.ChangeTemporaryPassword(context.Background(), domain.TemporaryPasswordChangeReq{Email: created.Email, TemporaryPassword: "wrong-password", NewPassword: "permanent-1234"}); !errors.Is(err, domain.ErrInvalidCreds) {
		t.Fatalf("wrong temporary password = %v", err)
	}
	if err = service.ChangeTemporaryPassword(context.Background(), domain.TemporaryPasswordChangeReq{Email: created.Email, TemporaryPassword: "temporary-1234", NewPassword: "permanent-1234"}); err != nil {
		t.Fatalf("change = %v", err)
	}
	stored, err = users.FindByEmail(context.Background(), created.Email)
	if err != nil || stored.PasswordChangeRequired || stored.TokenVersion != 1 || !utils.VerifyPassword(stored.Password, "permanent-1234") {
		t.Fatalf("rotated user = %#v, %v", stored, err)
	}
	if response, signInErr := tokens.SignIn(context.Background(), domain.SignInReq{Email: created.Email, Password: "permanent-1234"}); signInErr != nil || response == nil || response.IdToken == "" {
		t.Fatalf("normal sign-in after rotation = %#v, %v", response, signInErr)
	}
}

func TestTenantOOBOnboardingWritesOnlyCanonicalAccess(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	users := repository.NewRedisRepo(client)
	legacy := repository.NewMembershipRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	service := NewUserService(users, legacy, nil, nil, "jwt-secret", "https://tikti", "tikti", "", "", WithIdentityDirectoryAccess(directory))

	response, err := service.SendOobForTenant(ctx, "bereia", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "new@example.com"})
	if err != nil || response == nil || response.OobCode == "" {
		t.Fatalf("tenant OOB onboarding = %#v, %v", response, err)
	}
	user, err := users.FindByEmail(ctx, "new@example.com")
	if err != nil || user == nil {
		t.Fatalf("created user = %#v, %v", user, err)
	}
	assignment, err := directory.GetAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, user.Id)
	if err != nil || assignment == nil || len(assignment.Roles) != 1 || assignment.Roles[0] != string(domain.RoleCompanyEmployee) {
		t.Fatalf("canonical assignment = %#v, %v", assignment, err)
	}
	if membership, legacyErr := legacy.Get(ctx, "bereia", user.Id); legacyErr != nil || membership != nil {
		t.Fatalf("legacy membership was written = %#v, %v", membership, legacyErr)
	}
}

func TestIdentityDirectoryServiceValidatesTenantRolesAndDarkGroups(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	users := repository.NewRedisRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	tenants := repository.NewTenantRepo(client)
	roles := repository.NewRoleRepo(client)
	now := time.Now().UTC()
	if err := tenants.Create(context.Background(), &domain.Tenant{Id: "bereia", Slug: "bereia", Name: "Bereia", Status: domain.TenantStatusActive, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := roles.Create(context.Background(), "bereia", &domain.Role{Name: "reader", Scope: domain.RoleScopeTenant, TenantId: "bereia", Permissions: []string{"code-admin:services:read"}}); err != nil {
		t.Fatal(err)
	}
	user, err := directory.CreateDirectoryUser(context.Background(), &domain.User{Id: "user-1", Email: "one@example.com", Password: "hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	dark := NewIdentityDirectoryService(directory, users, tenants.(repository.ExactTenantRepository), roles.(repository.ExactRoleBatchRepository), false)
	if _, err = dark.CreateGroup(context.Background(), domain.IdentityGroupCreateReq{Name: "Readers"}); !errors.Is(err, domain.ErrGroupMutationsDisabled) {
		t.Fatalf("dark group = %v", err)
	}
	assignment, created, err := dark.PutAssignment(context.Background(), "bereia", domain.AccessPrincipalUser, user.ID, []string{"reader"}, "")
	if err != nil || !created || assignment.Version != 1 {
		t.Fatalf("direct = %#v %v %v", assignment, created, err)
	}
	if _, _, err = dark.PutAssignment(context.Background(), "bereia", domain.AccessPrincipalUser, user.ID, []string{"missing"}, ""); !errors.Is(err, domain.ErrMembershipDependencyNotFound) {
		t.Fatalf("missing role = %v", err)
	}
}
