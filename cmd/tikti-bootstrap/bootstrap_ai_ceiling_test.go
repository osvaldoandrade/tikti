package main

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// The AI activation raise and the bootstrap share one legacy-shape predicate:
// a legacy PUBLIC home audience raised at runtime keeps its shape and stays
// adoptable by every later bootstrap path.
func TestRaisedLegacyHomeAudienceRemainsAdoptableByBootstrap(t *testing.T) {
	ctx := context.Background()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	cfg := settings{
		tenantID: domain.MasterTenantID, tenantName: domain.MasterTenantName, email: "admin@local.test",
		password: "initial-password-123", audience: domain.CodeAdminAudienceClientID,
		scopes: []string{"code-admin:services:read"},
	}
	if err := bootstrap(ctx, data, cfg); err != nil {
		t.Fatal(err)
	}
	before, err := data.clients.Get(ctx, domain.MasterTenantID, domain.CodeAdminAudienceClientID)
	if err != nil || !domain.IsBootstrapLegacyCodeAdminAudience(domain.MasterTenantID, before) {
		t.Fatalf("bootstrap legacy home audience=%#v err=%v", before, err)
	}

	raiser := data.clients.(repository.CodeAdminAudienceScopeRaiser)
	aiScopes := []string{"code-admin:ai:read", "code-admin:ai:write"}
	raised, changed, err := raiser.RaiseManagedCodeAdminAudienceScopes(ctx, domain.MasterTenantID, aiScopes)
	if err != nil || !changed {
		t.Fatalf("raise changed=%v err=%v", changed, err)
	}
	stored, err := data.clients.Get(ctx, domain.MasterTenantID, domain.CodeAdminAudienceClientID)
	want := []string{"code-admin:ai:read", "code-admin:ai:write", "code-admin:services:read"}
	if err != nil || !reflect.DeepEqual(stored, raised) || !domain.IsBootstrapLegacyCodeAdminAudience(domain.MasterTenantID, stored) ||
		domain.IsManagedCodeAdminAudience(domain.MasterTenantID, stored) || !slices.Equal(stored.DefaultScopes, want) {
		t.Fatalf("raised legacy audience=%#v err=%v", stored, err)
	}

	// Exact replay writes nothing.
	replayed, changed, err := raiser.RaiseManagedCodeAdminAudienceScopes(ctx, domain.MasterTenantID, aiScopes)
	if err != nil || changed || !reflect.DeepEqual(replayed, stored) {
		t.Fatalf("replay=%#v changed=%v err=%v", replayed, changed, err)
	}

	// The installation's bootstrap scopes already include the AI scopes.
	cfg.scopes = want
	desired := &domain.Client{
		Id: cfg.audience, TenantId: domain.MasterTenantID, Type: domain.ClientTypePublic,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     append([]string(nil), want...), Status: domain.ClientStatusActive,
	}
	if !sameLegacyHomeAudienceOwner(stored, desired) || !adoptableLegacyHomeAudience(stored, desired) {
		t.Fatal("raised legacy home audience is no longer adoptable by the bootstrap")
	}
	if err := bootstrap(ctx, data, cfg); err != nil {
		t.Fatalf("full bootstrap re-run: %v", err)
	}
	cfg.audiencesOnly = true
	if err := reconcileManagedCodeAdminAudiences(ctx, data, cfg); err != nil {
		t.Fatalf("audience-only reconcile: %v", err)
	}
	after, err := data.clients.Get(ctx, domain.MasterTenantID, domain.CodeAdminAudienceClientID)
	if err != nil || !domain.IsBootstrapLegacyCodeAdminAudience(domain.MasterTenantID, after) || !slices.Equal(after.DefaultScopes, want) {
		t.Fatalf("legacy audience after bootstrap=%#v err=%v", after, err)
	}
}
