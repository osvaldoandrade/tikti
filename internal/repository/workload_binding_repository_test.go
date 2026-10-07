package repository

import (
	"context"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestWorkloadBindingRepositoryLifecycle(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	t.Cleanup(server.Close)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	repo := NewWorkloadBindingRepo(client)

	missing, err := repo.Get(context.Background(), "system:serviceaccount:code-admin:queue")
	if err != nil || missing != nil {
		t.Fatalf("missing Get() = %#v, %v", missing, err)
	}
	binding := &domain.WorkloadBinding{
		Subject: "system:serviceaccount:code-admin:queue", Namespace: "code-admin", ServiceAccount: "queue",
		Grants:    []domain.WorkloadGrant{{TenantID: "payments", Audience: domain.WorkloadTargetAudience, Scopes: []string{domain.WorkloadAdminScope}}},
		UpdatedAt: time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC),
	}
	if err := repo.Upsert(context.Background(), binding); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}
	stored, err := repo.Get(context.Background(), binding.Subject)
	if err != nil || stored == nil || stored.Revoked || stored.Grants[0].TenantID != "payments" {
		t.Fatalf("Get() = %#v, %v", stored, err)
	}

	revokedAt := time.Date(2026, 7, 21, 13, 0, 0, 0, time.UTC)
	revoked, err := repo.Revoke(context.Background(), binding.Subject, revokedAt)
	if err != nil || revoked == nil || !revoked.Revoked || !revoked.UpdatedAt.Equal(revokedAt) {
		t.Fatalf("Revoke() = %#v, %v", revoked, err)
	}
	if unknown, err := repo.Revoke(context.Background(), "system:serviceaccount:code-admin:missing", revokedAt); err != nil || unknown != nil {
		t.Fatalf("unknown Revoke() = %#v, %v", unknown, err)
	}
	if err := client.HSet(context.Background(), workloadBindingsKey, "bad", "{").Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Get(context.Background(), "bad"); err == nil {
		t.Fatal("invalid stored binding was accepted")
	}
}

func TestWorkloadBindingRepositoryRejectsInvalidInput(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	repo := NewWorkloadBindingRepo(client)
	if err := repo.Upsert(context.Background(), nil); err == nil {
		t.Fatal("nil binding was accepted")
	}
	if _, err := repo.Get(context.Background(), ""); err == nil {
		t.Fatal("empty subject was accepted")
	}
	if err := client.HSet(context.Background(), workloadBindingsKey, "bad", "{").Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Get(context.Background(), "bad"); err == nil {
		t.Fatal("invalid binding JSON was accepted")
	}
	if _, err := repo.Revoke(context.Background(), "bad", time.Now()); err == nil {
		t.Fatal("invalid binding was revoked")
	}
}

func TestWorkloadBindingRepositoryStoresScopedRecordsUnderClusterKey(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	repo := NewWorkloadBindingRepo(client)
	ctx := context.Background()
	subject := "system:serviceaccount:workload-conveste:cflow-codeq-worker-cf"
	grants := []domain.WorkloadGrant{{TenantID: "conveste", Audience: domain.WorkloadTargetAudience, Scopes: []string{domain.WorkloadAdminScope}}}
	unscoped := &domain.WorkloadBinding{Subject: subject, Namespace: "workload-conveste", ServiceAccount: "cflow-codeq-worker-cf", Grants: grants}
	master := &domain.WorkloadBinding{Subject: subject, Namespace: "workload-conveste", ServiceAccount: "cflow-codeq-worker-cf", ClusterRef: "code-cloud", Grants: grants}
	k3s := &domain.WorkloadBinding{Subject: subject, Namespace: "workload-conveste", ServiceAccount: "cflow-codeq-worker-cf", ClusterRef: "conveste-hostgator", ServiceAccountUID: "6b0f8a52-4c55-4f3c-9d1e-1a2b3c4d5e6f", Grants: grants}
	for _, binding := range []*domain.WorkloadBinding{unscoped, master, k3s} {
		if err := repo.Upsert(ctx, binding); err != nil {
			t.Fatalf("Upsert(%q) = %v", binding.ClusterRef, err)
		}
	}
	fields, err := client.HKeys(ctx, workloadBindingsKey).Result()
	if err != nil || len(fields) != 3 {
		t.Fatalf("stored keys = %q, %v", fields, err)
	}
	got, err := repo.Get(ctx, domain.WorkloadBindingKey("conveste-hostgator", subject))
	if err != nil || got == nil || got.ClusterRef != "conveste-hostgator" || got.ServiceAccountUID != k3s.ServiceAccountUID {
		t.Fatalf("scoped Get() = %#v, %v", got, err)
	}
	if got, err := repo.Get(ctx, subject); err != nil || got == nil || got.ClusterRef != "" {
		t.Fatalf("unscoped Get() = %#v, %v", got, err)
	}
	revoked, err := repo.Revoke(ctx, domain.WorkloadBindingKey("code-cloud", subject), time.Now())
	if err != nil || revoked == nil || !revoked.Revoked || revoked.ClusterRef != "code-cloud" {
		t.Fatalf("scoped Revoke() = %#v, %v", revoked, err)
	}
	if other, _ := repo.Get(ctx, domain.WorkloadBindingKey("conveste-hostgator", subject)); other == nil || other.Revoked {
		t.Fatalf("revoking one cluster's record changed another: %#v", other)
	}
	// A record whose content disagrees with its storage key is never returned.
	raw := `{"subject":"` + subject + `","namespace":"workload-conveste","serviceAccount":"cflow-codeq-worker-cf","clusterRef":"code-cloud","grants":[]}`
	if err := client.HSet(ctx, workloadBindingsKey, domain.WorkloadBindingKey("conveste-hostgator", subject), raw).Err(); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.Get(ctx, domain.WorkloadBindingKey("conveste-hostgator", subject)); err == nil || got != nil {
		t.Fatalf("mismatched record accepted: %#v, %v", got, err)
	}
}
