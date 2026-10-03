package workloadaccount

import (
	"context"
	"errors"
	"reflect"
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

func TestReconcileAdditionalRoleScopesStaySeparate(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	tenants := repository.NewTenantRepo(client)
	roles := repository.NewRoleRepo(client)
	clients := repository.NewClientRepo(client)
	ctx := context.Background()
	if err := tenants.Create(ctx, &domain.Tenant{Id: "wecare", Slug: "wecare", Name: "WeCare", Status: domain.TenantStatusActive}); err != nil {
		t.Fatal(err)
	}
	base := config.WorkloadAccountBFFClientConfig{
		TenantID: "wecare", Namespace: "workload-wecare", ServiceAccount: "wecare-social-api",
		Audience: "wecare-social-api", Role: "wecare-user",
		Scopes: []string{"wecare-social-api:read", "wecare-social-api:write"}, TTLSeconds: 900,
	}
	if err := Reconcile(ctx, tenants, roles, clients, []config.WorkloadAccountBFFClientConfig{base}); err != nil {
		t.Fatal(err)
	}
	base.AdditionalRoles = []config.WorkloadAccountBFFRoleConfig{{
		Role: "wecare-admin", Scopes: []string{"wecare:applications:review", "wecare:inventory:read"},
	}}
	for attempt := 0; attempt < 2; attempt++ {
		if err := Reconcile(ctx, tenants, roles, clients, []config.WorkloadAccountBFFClientConfig{base}); err != nil {
			t.Fatalf("reconcile attempt %d: %v", attempt, err)
		}
	}
	member, err := roles.Get(ctx, "wecare", "wecare-user")
	if err != nil || member == nil || !reflect.DeepEqual(member.Permissions, base.Scopes) {
		t.Fatalf("base role changed: %#v, %v", member, err)
	}
	admin, err := roles.Get(ctx, "wecare", "wecare-admin")
	if err != nil || admin != nil {
		t.Fatalf("reconciliation must not create an administrator role: %#v, %v", admin, err)
	}
	audience, err := clients.Get(ctx, "wecare", "wecare-social-api")
	wantScopes := []string{"wecare-social-api:read", "wecare-social-api:write", "wecare:applications:review", "wecare:inventory:read"}
	if err != nil || audience == nil || !reflect.DeepEqual(audience.DefaultScopes, wantScopes) {
		t.Fatalf("managed audience mismatch: %#v, %v", audience, err)
	}
}
