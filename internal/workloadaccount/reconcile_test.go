package workloadaccount

import (
	"context"
	"errors"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestReconcileProvisionedBrokerDependencies(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	tenants := repository.NewTenantRepo(client)
	roles := repository.NewRoleRepo(client)
	clients := repository.NewClientRepo(client)
	ctx := context.Background()
	if err := tenants.Create(ctx, &domain.Tenant{Id: "conveste", Slug: "conveste", Name: "Conveste", Status: domain.TenantStatusActive}); err != nil {
		t.Fatal(err)
	}
	desired := []config.WorkloadAccountBFFClientConfig{{
		TenantID: "conveste", Namespace: "workload-conveste", ServiceAccount: "platform-backlog",
		Audience: "platform-backlog", Role: "platform-backlog-user",
		Scopes: []string{"platform-backlog:read", "platform-backlog:write"}, TTLSeconds: 900,
	}}
	for attempt := 0; attempt < 2; attempt++ {
		if err := Reconcile(ctx, tenants, roles, clients, desired); err != nil {
			t.Fatalf("reconcile attempt %d: %v", attempt, err)
		}
	}
	role, err := roles.Get(ctx, "conveste", "platform-backlog-user")
	if err != nil || role == nil || len(role.Permissions) != 2 || role.Permissions[0] != "platform-backlog:read" || role.Permissions[1] != "platform-backlog:write" {
		t.Fatalf("role not provisioned exactly: %#v, %v", role, err)
	}
	audience, err := clients.Get(ctx, "conveste", "platform-backlog")
	if err != nil || audience == nil || audience.ManagedBy != domain.WorkloadAccountBFFClientManager || audience.SecretHash != "" || audience.Status != domain.ClientStatusActive || len(audience.DefaultScopes) != 2 {
		t.Fatalf("managed audience not provisioned exactly: %#v, %v", audience, err)
	}
	if err := roles.Create(ctx, "conveste", &domain.Role{Name: "platform-backlog-user", Scope: domain.RoleScopeTenant, TenantId: "conveste", Permissions: []string{"platform-backlog:read"}}); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(ctx, tenants, roles, clients, desired); !errors.Is(err, domain.ErrRoleConflict) {
		t.Fatalf("conflicting role must fail closed: %v", err)
	}
}
