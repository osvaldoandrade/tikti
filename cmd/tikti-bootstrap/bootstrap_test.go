package main

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
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
