package repository

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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
	if _, _, err := r.ListByTenant(ctx, "t1", 0, 10); err == nil {
		t.Fatal("expected list unmarshal error")
	}
	rdb.AddHook(commandErrorHook{byName: map[string]error{"hscan": context.Canceled}})
	if _, _, err := r.ListByTenant(ctx, "t1", 0, 10); err == nil {
		t.Fatal("expected list storage error")
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

func TestMembershipRepoExactReadsFailClosed(t *testing.T) {
	rdb, legacy := newMembershipRepoForTest(t)
	repo := legacy.(ExactMembershipRepository)
	ctx := context.Background()
	for _, membership := range []*domain.Membership{
		{Id: "m2", TenantId: "storifly", UserId: "user-1", Roles: []string{"storifly-admin"}},
		{Id: "m1", TenantId: "bereia", UserId: "user-1", Roles: []string{"bereia-read"}},
	} {
		if err := legacy.Create(ctx, membership); err != nil {
			t.Fatalf("create membership: %v", err)
		}
	}
	tenants, err := repo.ListTenantIDsByUserExact(ctx, "user-1")
	if err != nil || len(tenants) != 2 || tenants[0] != "bereia" || tenants[1] != "storifly" {
		t.Fatalf("exact tenants=%v err=%v", tenants, err)
	}
	membership, err := repo.GetExact(ctx, "bereia", "user-1")
	if err != nil || membership == nil || membership.Roles[0] != "bereia-read" {
		t.Fatalf("exact membership=%+v err=%v", membership, err)
	}
	missing, err := repo.GetExact(ctx, "missing", "user-1")
	if err != nil || missing != nil {
		t.Fatalf("missing membership=%+v err=%v", missing, err)
	}

	for name, value := range map[string]string{
		"empty":           "",
		"malformed":       "{",
		"tenant-mismatch": `{"tenantId":"other","userId":"user-1"}`,
		"user-mismatch":   `{"tenantId":"user-mismatch","userId":"other"}`,
	} {
		if err := rdb.HSet(ctx, membershipsKey(name), "user-1", value).Err(); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		if _, err := repo.GetExact(ctx, name, "user-1"); err != errStoredMembershipContract {
			t.Fatalf("%s exact error=%v", name, err)
		}
	}
	if err := rdb.SAdd(ctx, membershipsByUserPrefix+"unsafe", "Bereia").Err(); err != nil {
		t.Fatalf("seed reverse index: %v", err)
	}
	if _, err := repo.ListTenantIDsByUserExact(ctx, "unsafe"); err != errStoredMembershipContract {
		t.Fatalf("unsafe reverse index error=%v", err)
	}
	if _, err := repo.ListTenantIDsByUserExact(ctx, " user-1"); err != errStoredMembershipContract {
		t.Fatalf("unsafe user identity error=%v", err)
	}
	if canonicalMembershipTenantID("-bereia") {
		t.Fatal("non-canonical tenant boundary accepted")
	}
}

func TestMembershipRepoExactReverseIndexIsAtomicallyBounded(t *testing.T) {
	rdb, legacy := newMembershipRepoForTest(t)
	repo := legacy.(ExactMembershipRepository)
	ctx := context.Background()
	values := make([]interface{}, maximumExactMembershipTenantReads)
	for index := range values {
		values[index] = fmt.Sprintf("tenant-%03d", index)
	}
	if err := rdb.SAdd(ctx, membershipsByUserPrefix+"user-1", values...).Err(); err != nil {
		t.Fatalf("seed reverse index: %v", err)
	}

	tenants, exceeded, err := repo.ListTenantIDsByUserExactBounded(ctx, "user-1", maximumExactMembershipTenantReads)
	if err != nil || exceeded || len(tenants) != maximumExactMembershipTenantReads || tenants[0] != "tenant-000" || tenants[499] != "tenant-499" {
		t.Fatalf("bounded exact tenants=%d exceeded=%t err=%v", len(tenants), exceeded, err)
	}
	if err := rdb.SAdd(ctx, membershipsByUserPrefix+"user-1", "tenant-500").Err(); err != nil {
		t.Fatalf("grow reverse index: %v", err)
	}
	tenants, exceeded, err = repo.ListTenantIDsByUserExactBounded(ctx, "user-1", maximumExactMembershipTenantReads)
	if err != nil || !exceeded || tenants != nil {
		t.Fatalf("bounded overflow tenants=%v exceeded=%t err=%v", tenants, exceeded, err)
	}
	if _, _, err := repo.ListTenantIDsByUserExactBounded(ctx, "user-1", 0); err != errStoredMembershipContract {
		t.Fatalf("invalid limit error=%v", err)
	}
	if _, _, err := repo.ListTenantIDsByUserExactBounded(ctx, "user-1", maximumExactMembershipTenantReads+1); err != errStoredMembershipContract {
		t.Fatalf("unsafe limit error=%v", err)
	}
}

func TestMembershipRepoExactReadsPropagateRedisErrors(t *testing.T) {
	rdb, legacy := newMembershipRepoForTest(t)
	repo := legacy.(ExactMembershipRepository)
	if err := rdb.Close(); err != nil {
		t.Fatalf("close Redis client: %v", err)
	}
	if _, err := repo.ListTenantIDsByUserExact(context.Background(), "user-1"); err == nil {
		t.Fatal("reverse-index storage error was swallowed")
	}
	if _, err := repo.GetExact(context.Background(), "bereia", "user-1"); err == nil {
		t.Fatal("exact membership storage error was swallowed")
	}
}

func TestMembershipRepoV2GuardPreventsCrossAPISplitBrain(t *testing.T) {
	rdb, _ := newMembershipRepoForTest(t)
	ctx := context.Background()
	// Construct the legacy writer before v2 data exists to model a process
	// started while the write route is still dark during a rolling rollout.
	legacyWriter := NewMembershipRepo(rdb)
	v2 := NewMembershipV2Repo(rdb)
	roles := []string{"reader"}
	created, wasCreated, err := v2.Ensure(ctx, "bereia", "user-1", roles)
	if err != nil || !wasCreated || created == nil {
		t.Fatalf("v2 create = %+v, %t, %v", created, wasCreated, err)
	}
	for _, mutation := range []struct {
		name string
		run  func() error
	}{
		{name: "legacy replay", run: func() error {
			return legacyWriter.Create(ctx, &domain.Membership{Id: "legacy-replay", TenantId: "bereia", UserId: "user-1", Roles: roles})
		}},
		{name: "legacy update", run: func() error {
			return legacyWriter.Create(ctx, &domain.Membership{Id: "legacy-update", TenantId: "bereia", UserId: "user-1", Roles: []string{"writer"}})
		}},
		{name: "legacy delete", run: func() error { return legacyWriter.Delete(ctx, "bereia", "user-1") }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if err := mutation.run(); !errors.Is(err, domain.ErrMembershipConflict) {
				t.Fatalf("mutation error = %v", err)
			}
			v2Value, readErr := v2.GetExact(ctx, "bereia", "user-1")
			legacyValue, legacyErr := NewMembershipRepo(rdb).Get(ctx, "bereia", "user-1")
			if readErr != nil || legacyErr != nil || !reflect.DeepEqual(v2Value, created) || !reflect.DeepEqual(legacyValue, created) {
				t.Fatalf("projections diverged: v2=%+v legacy=%+v errors=%v/%v", v2Value, legacyValue, readErr, legacyErr)
			}
		})
	}
}

func TestMembershipRepoV2GuardPreservesLegacyOnlyLifecycle(t *testing.T) {
	_, repo := newMembershipRepoForTest(t)
	ctx := context.Background()
	create := func(id, role string) error {
		return repo.Create(ctx, &domain.Membership{Id: id, TenantId: "legacy", UserId: "user-1", Roles: []string{role}})
	}
	if err := create("legacy-1", "reader"); err != nil {
		t.Fatal(err)
	}
	if err := create("legacy-2", "writer"); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.Get(ctx, "legacy", "user-1")
	if err != nil || stored == nil || stored.Id != "legacy-2" || !reflect.DeepEqual(stored.Roles, []string{"writer"}) {
		t.Fatalf("legacy update = %+v, %v", stored, err)
	}
	if err := repo.Delete(ctx, "legacy", "user-1"); err != nil {
		t.Fatal(err)
	}
	if stored, err = repo.Get(ctx, "legacy", "user-1"); err != nil || stored != nil {
		t.Fatalf("legacy delete = %+v, %v", stored, err)
	}
}
