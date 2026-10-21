package main

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestReconcileManagedCodeAdminAudiencesExistingOnly(t *testing.T) {
	ctx := context.Background()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	// No user, credential, role, membership, workload or directory store is
	// available to this mode. It can only reconcile existing client ceilings.
	data := stores{tenants: repository.NewTenantRepo(client), clients: repository.NewClientRepo(client)}
	before := map[string]*domain.Client{}
	for _, tenantID := range []string{domain.MasterTenantID, "managed", "missing", "public", "legacy", "inactive"} {
		tenant := &domain.Tenant{Id: tenantID, Slug: tenantID, Name: tenantID, Status: domain.TenantStatusActive}
		if tenantID == "inactive" {
			tenant.Status = domain.TenantStatusDisabled
		}
		if err := data.tenants.Create(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		if tenantID == "missing" {
			continue
		}
		audience := &domain.Client{Id: domain.CodeAdminAudienceClientID, TenantId: tenantID,
			Type: domain.ClientTypeService, Status: domain.ClientStatusActive,
			AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
			DefaultScopes:     []string{"code-admin:logs:read"}, ManagedBy: domain.CodeAdminAudienceClientManager}
		if tenantID == domain.MasterTenantID || tenantID == "public" || tenantID == "legacy" {
			audience.ManagedBy = ""
			if tenantID == domain.MasterTenantID || tenantID == "public" {
				audience.Type = domain.ClientTypePublic
			}
			if err := data.clients.UpsertBootstrap(ctx, tenantID, audience); err != nil {
				t.Fatal(err)
			}
		} else if _, _, err := data.clients.EnsureManagedAudience(ctx, tenantID, audience); err != nil {
			t.Fatal(err)
		}
		before[tenantID] = audience
	}
	want := []string{"code-admin:logs:platform:read", "code-admin:logs:read"}
	for range 2 {
		if err := reconcileManagedCodeAdminAudiences(ctx, data, settings{
			audience: domain.CodeAdminAudienceClientID, scopes: want, audiencesOnly: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for tenantID, previous := range before {
		current, err := data.clients.Get(ctx, tenantID, domain.CodeAdminAudienceClientID)
		if err != nil {
			t.Fatal(err)
		}
		if tenantID == domain.MasterTenantID || tenantID == "managed" {
			updated := *previous
			updated.DefaultScopes = want
			if !reflect.DeepEqual(current, &updated) {
				t.Errorf("managed audience %s was not updated exactly", tenantID)
			}
		} else if !reflect.DeepEqual(current, previous) {
			t.Errorf("unowned or inactive audience %s was modified", tenantID)
		}
	}
	if created, err := data.clients.Get(ctx, "missing", domain.CodeAdminAudienceClientID); err != nil || created != nil {
		t.Fatal("audiences-only mode created a new client")
	}
}

func TestAudienceOnlyEnvironmentSkipsIdentityBootstrap(t *testing.T) {
	ctx := context.Background()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	if err := repository.NewTenantRepo(client).Create(ctx, &domain.Tenant{
		Id: domain.MasterTenantID, Slug: domain.MasterTenantID, Name: domain.MasterTenantName, Status: domain.TenantStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	clients := repository.NewClientRepo(client)
	if err := clients.UpsertBootstrap(ctx, domain.MasterTenantID, &domain.Client{
		Id: domain.CodeAdminAudienceClientID, TenantId: domain.MasterTenantID, Type: domain.ClientTypePublic,
		Status:            domain.ClientStatusActive,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)}, DefaultScopes: []string{"code-admin:logs:read"},
	}); err != nil {
		t.Fatal(err)
	}
	// These values must never be interpreted, read or repaired in this mode.
	for _, key := range []string{"users", "passwords", "roles", "assignments", "brokers"} {
		if err := server.Set(key, "preserved"); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("REDIS_ADDR", server.Addr())
	t.Setenv("REDIS_PASSWORD", "")
	t.Setenv("REDIS_PASSWORD_FILE", "")
	t.Setenv("TIKTI_BOOTSTRAP_TENANT_ID", "")
	t.Setenv("TIKTI_BOOTSTRAP_TENANT_NAME", "")
	t.Setenv("TIKTI_BOOTSTRAP_EMAIL", "")
	t.Setenv("TIKTI_BOOTSTRAP_PASSWORD_FILE", "/missing/user-password")
	t.Setenv("TIKTI_BOOTSTRAP_PASSWORD_HASH_FILE", "/missing/user-password-hash")
	t.Setenv("TIKTI_BOOTSTRAP_ACCOUNT_BFF_CLIENTS", "invalid broker configuration")
	t.Setenv("TIKTI_BOOTSTRAP_AUDIENCE", domain.CodeAdminAudienceClientID)
	t.Setenv("TIKTI_BOOTSTRAP_SCOPES", "code-admin:logs:read,code-admin:logs:platform:read")
	beforeKeys := server.Keys()
	for range 2 {
		if err := reconcileAudiencesOnlyFromEnvironment(); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(server.Keys(), beforeKeys) {
		t.Fatal("audience-only reconciliation created or removed non-client records")
	}
	for _, key := range []string{"users", "passwords", "roles", "assignments", "brokers"} {
		if value, err := server.Get(key); err != nil || value != "preserved" {
			t.Fatalf("audience-only reconciliation modified %s", key)
		}
	}
	audience, err := clients.Get(ctx, domain.MasterTenantID, domain.CodeAdminAudienceClientID)
	if err != nil || audience == nil || strings.Join(audience.DefaultScopes, ",") != "code-admin:logs:platform:read,code-admin:logs:read" {
		t.Fatal("MASTER audience ceiling was not reconciled")
	}
}
