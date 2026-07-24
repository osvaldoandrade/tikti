package repository

import (
	"context"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func newMembershipRepoForTest(t *testing.T) (*redis.Client, MembershipRepository) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, NewMembershipRepo(rdb)
}

func TestNewMembershipRepo(t *testing.T) {
	_, repo := newMembershipRepoForTest(t)
	if repo == nil {
		t.Fatalf("expected repo")
	}
}

func TestMembershipRepo_CreateGetListDelete(t *testing.T) {
	_, repo := newMembershipRepoForTest(t)
	ctx := context.Background()
	r := repo.(*membershipRepo)

	m := &domain.Membership{Id: "m1", TenantId: "t1", UserId: "u1", Roles: []string{"R1"}}
	if err := r.Create(ctx, m); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if m.CreatedAt.IsZero() {
		t.Fatalf("expected createdAt populated")
	}

	got, err := r.Get(ctx, "t1", "u1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got == nil || got.UserId != "u1" {
		t.Fatalf("unexpected membership: %+v", got)
	}

	tenants, err := r.ListTenantIDsByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(tenants) != 1 || tenants[0] != "t1" {
		t.Fatalf("unexpected tenants: %v", tenants)
	}

	memberships, cursor, err := r.ListByTenant(ctx, "t1", 0, 50)
	if err != nil {
		t.Fatalf("list by tenant: %v", err)
	}
	if cursor != 0 || len(memberships) != 1 || memberships[0].UserId != "u1" {
		t.Fatalf("unexpected memberships page: cursor=%d values=%+v", cursor, memberships)
	}

	if err := r.Delete(ctx, "t1", "u1"); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	got, err = r.Get(ctx, "t1", "u1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected membership removed")
	}
}

func TestMembershipRepo_GetInvalidJSON(t *testing.T) {
	rdb, repo := newMembershipRepoForTest(t)
	ctx := context.Background()
	r := repo.(*membershipRepo)

	if err := rdb.HSet(ctx, membershipsKey("t1"), "u1", "{").Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	if _, err := r.Get(ctx, "t1", "u1"); err == nil {
		t.Fatalf("expected unmarshal error")
	}
}

func TestMembershipRepo_ListTenantIDsByUser_NotFoundReturnsEmpty(t *testing.T) {
	_, repo := newMembershipRepoForTest(t)
	ctx := context.Background()
	r := repo.(*membershipRepo)

	tenants, err := r.ListTenantIDsByUser(ctx, "missing")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(tenants) != 0 {
		t.Fatalf("expected empty list, got %v", tenants)
	}
}

func TestMembershipRepo_ListTenantIDsByUser_RedisNilReturnsEmpty(t *testing.T) {
	rdb, repo := newMembershipRepoForTest(t)
	ctx := context.Background()
	r := repo.(*membershipRepo)

	rdb.AddHook(commandErrorHook{byName: map[string]error{"smembers": redis.Nil}})
	tenants, err := r.ListTenantIDsByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(tenants) != 0 {
		t.Fatalf("expected empty tenant list, got %v", tenants)
	}
}

func TestMembershipsKey(t *testing.T) {
	if got := membershipsKey("x"); got != "memberships:x" {
		t.Fatalf("unexpected key: %s", got)
	}
}
