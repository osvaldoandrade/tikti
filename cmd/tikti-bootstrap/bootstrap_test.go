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

func TestBootstrapRejectsDormantAudienceScope(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	cfg := settings{
		tenantID: "local", tenantName: "Local", email: "admin@example.com",
		password: "long-enough-password", audience: "api", scopes: []string{"code-admin:secrets:read"},
	}
	if err := bootstrap(context.Background(), data, cfg); err == nil {
		t.Fatal("bootstrap accepted a dormant reserved scope")
	}
	if tenant, err := data.tenants.Get(context.Background(), cfg.tenantID); err != nil || tenant != nil {
		t.Fatalf("invalid bootstrap wrote tenant=%#v err=%v", tenant, err)
	}
	if audience, err := data.clients.Get(context.Background(), cfg.tenantID, cfg.audience); err != nil || audience != nil {
		t.Fatalf("invalid bootstrap wrote audience=%#v err=%v", audience, err)
	}
}

func TestBootstrapCanonicalizesAudienceScopes(t *testing.T) {
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
		password: "initial-password-123", audience: "code-admin-api",
		scopes: []string{" code-admin:services:read ", "code-admin:clusters:read", "code-admin:services:read"},
	}
	if err := bootstrap(context.Background(), data, cfg); err != nil {
		t.Fatal(err)
	}
	want := []string{"code-admin:clusters:read", "code-admin:services:read"}
	role, err := data.roles.Get(context.Background(), cfg.tenantID, "ADMIN")
	if err != nil || role == nil || !reflect.DeepEqual(role.Permissions, want) {
		t.Fatalf("role scopes=%#v err=%v", role, err)
	}
	audience, err := data.clients.Get(context.Background(), cfg.tenantID, cfg.audience)
	if err != nil || audience == nil || !reflect.DeepEqual(audience.DefaultScopes, want) {
		t.Fatalf("audience scopes=%#v err=%v", audience, err)
	}
}

func TestBootstrapReconcilesWorkloadAccountBFFDependencies(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	if err := data.tenants.Create(context.Background(), &domain.Tenant{
		Id: "bereia", Slug: "bereia", Name: "Bereia", Status: domain.TenantStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	brokers := []accountBrokerSettings{{
		tenantID: "bereia", audience: "bereia-api", role: "bereia-user",
		scopes: []string{"bereia-api:read", "bereia-api:write"},
	}}
	if err := bootstrapAccountBrokers(context.Background(), data, brokers); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapAccountBrokers(context.Background(), data, brokers); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	role, err := data.roles.Get(context.Background(), "bereia", "bereia-user")
	if err != nil || role == nil || !reflect.DeepEqual(role.Permissions, brokers[0].scopes) {
		t.Fatalf("role=%#v err=%v", role, err)
	}
	audience, err := data.clients.Get(context.Background(), "bereia", "bereia-api")
	if err != nil || audience == nil || audience.SecretHash != "" ||
		audience.ManagedBy != domain.WorkloadAccountBFFClientManager ||
		!reflect.DeepEqual(audience.DefaultScopes, brokers[0].scopes) {
		t.Fatalf("audience=%#v err=%v", audience, err)
	}
}

func TestBootstrapWorkloadAccountBFFFailsClosed(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	if err := bootstrapAccountBrokers(context.Background(), data, []accountBrokerSettings{{
		tenantID: "missing", audience: "missing-api", role: "missing-user", scopes: []string{"missing-api:read"},
	}}); err == nil {
		t.Fatal("missing tenant was accepted")
	}
}
