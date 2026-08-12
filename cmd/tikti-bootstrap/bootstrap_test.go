package main

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestBootstrapIsIdempotentAndRotatesPassword(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	cfg := settings{
		tenantID: "local-tenant", tenantName: "Local Tenant", email: "admin@local.test",
		password: "initial-password-123", audience: "code-admin-api", scopes: []string{"code-admin:services:read"},
		workloadSubject: "system:serviceaccount:codecloud-control:code-admin-controller-queue",
	}
	if err := bootstrap(context.Background(), data, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.password = "rotated-password-456"
	if err := bootstrap(context.Background(), data, cfg); err != nil {
		t.Fatal(err)
	}
	user, err := data.users.FindByEmail(context.Background(), cfg.email)
	if err != nil {
		t.Fatal(err)
	}
	if user == nil || user.Role != domain.RoleAdmin || user.CompanyId == nil || *user.CompanyId != cfg.tenantID {
		t.Fatalf("unexpected bootstrap user: %#v", user)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(cfg.password)); err != nil {
		t.Fatal("bootstrap did not rotate the password")
	}
	membership, err := data.memberships.Get(context.Background(), cfg.tenantID, user.Id)
	if err != nil || membership == nil || len(membership.Roles) != 1 || membership.Roles[0] != "ADMIN" {
		t.Fatalf("unexpected membership: %#v, %v", membership, err)
	}
	clientRecord, err := data.clients.Get(context.Background(), cfg.tenantID, cfg.audience)
	if err != nil || clientRecord == nil || clientRecord.Status != "ACTIVE" {
		t.Fatalf("unexpected client: %#v, %v", clientRecord, err)
	}
	workload, err := data.workloads.Get(context.Background(), cfg.workloadSubject)
	if err != nil || workload == nil || workload.Namespace != "codecloud-control" ||
		len(workload.Grants) != 1 || workload.Grants[0].TenantID != cfg.tenantID {
		t.Fatalf("unexpected workload binding: %#v, %v", workload, err)
	}
}

func TestBootstrapImportsBoundedArgon2idPasswordHash(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	salt := []byte("0123456789abcdef")
	hash := argon2.IDKey([]byte("correct-password"), salt, 3, 64*1024, 4, 32)
	encoded := "$argon2id$v=19$m=65536,t=3,p=4$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(hash)
	cfg := settings{
		tenantID: "local-tenant", tenantName: "Local Tenant", email: "admin@codecloud.local",
		passwordHash: encoded, audience: "code-admin-api", scopes: []string{"code-admin:services:read"},
	}
	if err := bootstrap(context.Background(), data, cfg); err != nil {
		t.Fatal(err)
	}
	user, err := data.users.FindByEmail(context.Background(), cfg.email)
	if err != nil || user == nil || user.Password != encoded {
		t.Fatalf("unexpected imported password hash: user=%#v err=%v", user, err)
	}
}

func TestBootstrapFailsClosedForV2OwnedMembership(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	cfg := settings{
		tenantID: "local-tenant", tenantName: "Local Tenant", email: "admin@local.test",
		password: "initial-password-123", audience: "code-admin-api", scopes: []string{"code-admin:services:read"},
	}
	user := &domain.User{
		Id: "bootstrap-user", Email: cfg.email, Password: "stored-hash", Role: domain.RoleAdmin,
		Status: domain.UserStatusActive, CompanyId: &cfg.tenantID, AuthSource: domain.AuthSourcePassword,
	}
	if err := data.users.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	v2 := repository.NewMembershipV2Repo(client)
	created, wasCreated, err := v2.Ensure(context.Background(), cfg.tenantID, user.Id, []string{"ADMIN"})
	if err != nil || !wasCreated || created == nil {
		t.Fatalf("v2 create = %+v, %t, %v", created, wasCreated, err)
	}

	err = bootstrap(context.Background(), data, cfg)
	if !errors.Is(err, domain.ErrMembershipConflict) {
		t.Fatalf("bootstrap v2-owned pair error = %v", err)
	}
	v2Value, v2Err := v2.GetExact(context.Background(), cfg.tenantID, user.Id)
	legacyValue, legacyErr := data.memberships.Get(context.Background(), cfg.tenantID, user.Id)
	if v2Err != nil || legacyErr != nil || !reflect.DeepEqual(v2Value, created) || !reflect.DeepEqual(legacyValue, created) {
		t.Fatalf("bootstrap diverged projections: v2=%+v legacy=%+v errors=%v/%v", v2Value, legacyValue, v2Err, legacyErr)
	}
}

func TestBootstrapRejectsInvalidWorkloadSubject(t *testing.T) {
	err := validateSettings(settings{
		tenantID: "local", tenantName: "Local", email: "admin@example.com",
		password: "long-enough-password", audience: "api", scopes: []string{"read"},
		workloadSubject: "default/controller",
	})
	if err == nil {
		t.Fatal("validateSettings() error = nil")
	}
}

func TestBootstrapRejectsWeakPassword(t *testing.T) {
	err := validateSettings(settings{
		tenantID: "local", tenantName: "Local", email: "admin@example.com",
		password: "short", audience: "api", scopes: []string{"read"},
	})
	if err == nil {
		t.Fatal("validateSettings() error = nil")
	}
}
