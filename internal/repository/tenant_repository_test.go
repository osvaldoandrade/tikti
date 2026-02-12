package repository

import (
	"context"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func newTenantRepoForTest(t *testing.T) (*redis.Client, TenantRepository) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, NewTenantRepo(rdb)
}

func TestNewTenantRepo(t *testing.T) {
	_, repo := newTenantRepoForTest(t)
	if repo == nil {
		t.Fatalf("expected repo")
	}
}

func TestTenantRepo_CreateAndGet(t *testing.T) {
	_, repo := newTenantRepoForTest(t)
	ctx := context.Background()

	tr := repo.(*tenantRepo)
	tenant := &domain.Tenant{Slug: "s", Name: "n"}
	if err := tr.Create(ctx, tenant); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if tenant.Id == "" || tenant.Status == "" || tenant.CreatedAt.IsZero() {
		t.Fatalf("expected defaults to be populated: %+v", tenant)
	}

	got, err := tr.Get(ctx, tenant.Id)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got == nil || got.Id != tenant.Id {
		t.Fatalf("unexpected tenant: %+v", got)
	}
}

func TestTenantRepo_Get_NotFoundAndInvalidJSON(t *testing.T) {
	rdb, repo := newTenantRepoForTest(t)
	ctx := context.Background()
	tr := repo.(*tenantRepo)

	got, err := tr.Get(ctx, "missing")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil tenant")
	}

	if err := rdb.HSet(ctx, tenantsHash, "bad", "{").Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	if _, err := tr.Get(ctx, "bad"); err == nil {
		t.Fatalf("expected unmarshal error")
	}
}

func TestTenantRepo_EnsureDefault(t *testing.T) {
	_, repo := newTenantRepoForTest(t)
	ctx := context.Background()
	tr := repo.(*tenantRepo)

	def, err := tr.EnsureDefault(ctx)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if def == nil || def.Id != "default" {
		t.Fatalf("unexpected default tenant: %+v", def)
	}

	def2, err := tr.EnsureDefault(ctx)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if def2 == nil || def2.Id != "default" {
		t.Fatalf("unexpected default tenant: %+v", def2)
	}
}
