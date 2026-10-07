package main

import (
	"context"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func scopedBootstrapFixture(t *testing.T) (stores, settings) {
	t.Helper()
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
		workloadSubject:    "system:serviceaccount:codecloud-control:code-admin-controller-queue",
		trustedClusterRefs: []string{"conveste-hostgator", "code-cloud"},
		workloadClusterRef: "code-cloud", workloadServiceAccountUID: "031d59af-7dd7-4553-98bc-93d8687d13b6",
	}
	return data, cfg
}

func TestBootstrapWritesScopedWorkloadBindingWhenMultipleProvidersAreTrusted(t *testing.T) {
	data, cfg := scopedBootstrapFixture(t)
	if err := bootstrap(context.Background(), data, cfg); err != nil {
		t.Fatal(err)
	}
	scoped, err := data.workloads.Get(context.Background(), domain.WorkloadBindingKey("code-cloud", cfg.workloadSubject))
	if err != nil || scoped == nil || scoped.ClusterRef != "code-cloud" ||
		scoped.ServiceAccountUID != cfg.workloadServiceAccountUID || scoped.Subject != cfg.workloadSubject {
		t.Fatalf("scoped bootstrap binding = %#v, %v", scoped, err)
	}
	if unscoped, err := data.workloads.Get(context.Background(), cfg.workloadSubject); err != nil || unscoped != nil {
		t.Fatalf("bootstrap also wrote an unscoped record: %#v, %v", unscoped, err)
	}
	if other, err := data.workloads.Get(context.Background(), domain.WorkloadBindingKey("conveste-hostgator", cfg.workloadSubject)); err != nil || other != nil {
		t.Fatalf("bootstrap wrote a record for another cluster: %#v, %v", other, err)
	}
}

func TestBootstrapRefusesUnscopedOrUntrustedWorkloadScope(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*settings)
		want   string
	}{
		{name: "multiple providers without clusterRef", mutate: func(cfg *settings) { cfg.workloadClusterRef = "" }, want: "requires a clusterRef"},
		{name: "untrusted clusterRef", mutate: func(cfg *settings) { cfg.workloadClusterRef = "itransform-cluster" }, want: "not a trusted provider"},
		{name: "clusterRef with no trusted list", mutate: func(cfg *settings) { cfg.trustedClusterRefs = nil }, want: "not a trusted provider"},
		{name: "invalid trusted clusterRef", mutate: func(cfg *settings) { cfg.trustedClusterRefs = []string{"Code_Cloud", "code-cloud"} }, want: "trusted clusterRef is invalid"},
		{name: "duplicate trusted clusterRef", mutate: func(cfg *settings) { cfg.trustedClusterRefs = []string{"code-cloud", "code-cloud"} }, want: "duplicated"},
		{name: "invalid ServiceAccount UID", mutate: func(cfg *settings) { cfg.workloadServiceAccountUID = "uid with spaces" }, want: "UID is invalid"},
		{name: "scope without subject", mutate: func(cfg *settings) { cfg.workloadSubject = "" }, want: "requires a workload subject"},
	}
	for _, test := range tests {
		data, cfg := scopedBootstrapFixture(t)
		test.mutate(&cfg)
		err := bootstrap(context.Background(), data, cfg)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%s: error = %v, want %q", test.name, err, test.want)
		}
	}
}

func TestBootstrapKeepsUnscopedWorkloadBindingForSingleProvider(t *testing.T) {
	data, cfg := scopedBootstrapFixture(t)
	cfg.trustedClusterRefs = []string{"code-cloud"}
	cfg.workloadClusterRef, cfg.workloadServiceAccountUID = "", ""
	if err := bootstrap(context.Background(), data, cfg); err != nil {
		t.Fatal(err)
	}
	if binding, err := data.workloads.Get(context.Background(), cfg.workloadSubject); err != nil || binding == nil || binding.ClusterRef != "" {
		t.Fatalf("single-provider bootstrap binding = %#v, %v", binding, err)
	}
}

func TestExistingUserOnlyBootstrapRefusesWorkloadScope(t *testing.T) {
	cfg := settings{
		tenantID: domain.MasterTenantID, tenantName: domain.MasterTenantName, email: "admin@local.test",
		existingUserOnly: true, audience: domain.CodeAdminAudienceClientID, scopes: []string{"code-admin:services:read"},
		workloadClusterRef: "code-cloud",
	}
	if err := validateSettings(cfg); err == nil || !strings.Contains(err.Error(), "cannot bind a workload subject") {
		t.Fatalf("validateSettings() = %v", err)
	}
}
