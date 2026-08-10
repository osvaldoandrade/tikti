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
