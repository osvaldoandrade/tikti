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
	if _, _, err := tr.List(ctx, 0, 10); err == nil {
		t.Fatal("expected list unmarshal error")
	}
}

func TestTenantRepo_ListIsStableAndPaginated(t *testing.T) {
	rdb, repo := newTenantRepoForTest(t)
	ctx := context.Background()
	for _, tenant := range []*domain.Tenant{
		{Id: "tenant-c", Name: "C", Slug: "c"},
		{Id: "tenant-a", Name: "A", Slug: "a"},
		{Id: "tenant-b", Name: "B", Slug: "b", Status: domain.TenantStatusDisabled},
	} {
		if err := repo.Create(ctx, tenant); err != nil {
			t.Fatalf("create tenant: %v", err)
		}
	}
	first, next, err := repo.List(ctx, 0, 2)
	if err != nil || len(first) != 2 || first[0].Id != "tenant-a" || first[1].Id != "tenant-b" || next != "2" {
		t.Fatalf("unexpected first page: %+v next=%q err=%v", first, next, err)
	}
	second, next, err := repo.List(ctx, 2, 2)
	if err != nil || len(second) != 1 || second[0].Id != "tenant-c" || next != "" {
		t.Fatalf("unexpected second page: %+v next=%q err=%v", second, next, err)
	}
	if empty, _, err := repo.List(ctx, 99, 2); err != nil || len(empty) != 0 {
		t.Fatalf("offset page: %+v, %v", empty, err)
	}
	_ = rdb.HSet(ctx, tenantsHash, "empty", "").Err()
	if tenants, _, err := repo.List(ctx, 0, 10); err != nil || len(tenants) != 3 {
		t.Fatalf("empty tenant value was not skipped: %+v, %v", tenants, err)
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
