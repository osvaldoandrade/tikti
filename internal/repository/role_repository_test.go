package repository

import (
	"context"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func newRoleRepoForTest(t *testing.T) (*redis.Client, RoleRepository) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, NewRoleRepo(rdb)
}

func TestNewRoleRepo(t *testing.T) {
	_, repo := newRoleRepoForTest(t)
	if repo == nil {
		t.Fatalf("expected repo")
	}
}

func TestRoleRepo_CreateGetList(t *testing.T) {
	_, repo := newRoleRepoForTest(t)
	ctx := context.Background()
	r := repo.(*roleRepo)

	role := &domain.Role{Name: "R1", Scope: domain.RoleScopeTenant, Permissions: []string{"p1"}}
	if err := r.Create(ctx, "t1", role); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	got, err := r.Get(ctx, "t1", "R1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got == nil || got.Name != "R1" {
		t.Fatalf("unexpected role: %+v", got)
	}

	list, err := r.List(ctx, "t1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(list) != 1 || list[0].Name != "R1" {
		t.Fatalf("unexpected list: %+v", list)
	}
}

func TestRoleRepo_CreateInvalidArgument(t *testing.T) {
	_, repo := newRoleRepoForTest(t)
	ctx := context.Background()
	r := repo.(*roleRepo)

	if err := r.Create(ctx, "", &domain.Role{Name: "R1"}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for empty tenant, got %v", err)
	}
	if err := r.Create(ctx, "t1", nil); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for nil role, got %v", err)
	}
	if err := r.Create(ctx, "t1", &domain.Role{}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for empty role name, got %v", err)
	}
}

func TestRoleRepo_GetNotFoundAndInvalidJSON(t *testing.T) {
	rdb, repo := newRoleRepoForTest(t)
	ctx := context.Background()
	r := repo.(*roleRepo)

	got, err := r.Get(ctx, "t1", "missing")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil role")
	}

	if err := rdb.HSet(ctx, rolesKey("t1"), "bad", "{").Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	if _, err := r.Get(ctx, "t1", "bad"); err == nil {
		t.Fatalf("expected unmarshal error")
	}
}

func TestRoleRepo_ListInvalidJSON(t *testing.T) {
	rdb, repo := newRoleRepoForTest(t)
	ctx := context.Background()
	r := repo.(*roleRepo)

	if err := rdb.HSet(ctx, rolesKey("t1"), "bad", "{").Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	if _, err := r.List(ctx, "t1"); err == nil {
		t.Fatalf("expected unmarshal error")
	}
}

func TestRolesKey(t *testing.T) {
	if got := rolesKey("x"); got != "roles:x" {
		t.Fatalf("unexpected key: %s", got)
	}
}
