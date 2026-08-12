package repository

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
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

func TestRoleRepoGetManyExact(t *testing.T) {
	rdb, legacy := newRoleRepoForTest(t)
	repo := legacy.(*roleRepo)
	ctx := context.Background()
	for _, role := range []*domain.Role{
		{Name: "reader", Scope: domain.RoleScopeTenant, TenantId: "bereia", Permissions: []string{"content:read"}},
		{Name: "writer", Scope: domain.RoleScopeTenant, TenantId: "bereia", Permissions: []string{"content:write"}},
	} {
		if err := repo.Create(ctx, "bereia", role); err != nil {
			t.Fatal(err)
		}
	}
	got, err := repo.GetManyExact(ctx, "bereia", []string{"reader", "writer"})
	if err != nil || len(got) != 2 || got[0].Name != "reader" || got[1].Name != "writer" {
		t.Fatalf("GetManyExact() = %#v, %v", got, err)
	}
	got, err = repo.GetManyExact(ctx, "bereia", []string{"missing", "writer"})
	if err != nil || got[0] != nil || got[1] == nil {
		t.Fatalf("missing batch = %#v, %v", got, err)
	}
	if err := rdb.HSet(ctx, rolesKey("bereia"), "reader", `{"name":"other","scope":"TENANT","tenantId":"bereia","permissions":["content:read"]}`).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetManyExact(ctx, "bereia", []string{"reader"}); !errors.Is(err, errStoredRoleContract) {
		t.Fatalf("corrupt batch error = %v", err)
	}
	for _, names := range [][]string{nil, {"writer", "reader"}, {"reader", "reader"}, {"bad/role"}} {
		if _, err := repo.GetManyExact(ctx, "bereia", names); !errors.Is(err, domain.ErrInvalidArgument) {
			t.Fatalf("invalid names %#v = %v", names, err)
		}
	}
	if _, err := repo.GetManyExact(ctx, "Bereia", []string{"reader"}); !errors.Is(err, domain.ErrInvalidTenant) {
		t.Fatalf("invalid tenant = %v", err)
	}
	if _, err := repo.GetManyExact(ctx, "bereia", make([]string, membershipV2RoleMax+1)); !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("over limit = %v", err)
	}
	names := make([]string, membershipV2RoleMax)
	for index := range names {
		names[index] = fmt.Sprintf("role%03d", index)
		if err := repo.Create(ctx, "bereia", &domain.Role{Name: names[index], Scope: domain.RoleScopeTenant, TenantId: "bereia", Permissions: []string{"content:read"}}); err != nil {
			t.Fatal(err)
		}
	}
	if roles, err := repo.GetManyExact(ctx, "bereia", names); err != nil || len(roles) != membershipV2RoleMax {
		t.Fatalf("max batch = %d, %v", len(roles), err)
	}
	if _, err := decodeExactRoleBatch("bereia", []string{"reader"}, nil); !errors.Is(err, errStoredRoleContract) {
		t.Fatalf("short result = %v", err)
	}
	if _, err := decodeExactRoleBatch("bereia", []string{"reader"}, []interface{}{42}); !errors.Is(err, errStoredRoleContract) {
		t.Fatalf("non-string result = %v", err)
	}
	_ = rdb.Close()
	if _, err := repo.GetManyExact(ctx, "bereia", []string{"reader"}); err == nil {
		t.Fatal("storage error accepted")
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

func TestRoleRepo_ExactReadsPreserveHashIdentityAndRedactCorruption(t *testing.T) {
	rdb, repository := newRoleRepoForTest(t)
	repo := repository.(*roleRepo)
	ctx := context.Background()
	valid := &domain.Role{Name: "read", Scope: domain.RoleScopeTenant, TenantId: "bereia", Permissions: []string{"scope:read"}}
	if err := repo.Create(ctx, "bereia", valid); err != nil {
		t.Fatalf("create exact role: %v", err)
	}
	got, err := repo.GetExact(ctx, "bereia", "read")
	if err != nil || got == nil || got.Name != "read" {
		t.Fatalf("GetExact() = %+v, %v", got, err)
	}
	listed, err := repo.ListExact(ctx, "bereia")
	if err != nil || len(listed) != 1 || listed[0].Name != "read" {
		t.Fatalf("ListExact() = %+v, %v", listed, err)
	}
	missing, err := repo.GetExact(ctx, "bereia", "missing")
	if err != nil || missing != nil {
		t.Fatalf("missing exact role = %+v, %v", missing, err)
	}
	empty, err := repo.ListExact(ctx, "empty")
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty exact list = %#v, %v", empty, err)
	}
	if _, err := repo.GetExact(ctx, "Bereia", "read"); !errors.Is(err, domain.ErrInvalidTenant) {
		t.Fatalf("invalid exact tenant = %v", err)
	}
	if _, err := repo.GetExact(ctx, "bereia", "read/secret"); !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("invalid exact role = %v", err)
	}
	if _, err := repo.ListExact(ctx, "Bereia"); !errors.Is(err, domain.ErrInvalidTenant) {
		t.Fatalf("invalid exact list tenant = %v", err)
	}

	for _, corrupt := range []struct{ field, value string }{
		{field: "empty", value: ""},
		{field: "alias", value: `{"name":"admin","tenantId":"bereia","permissions":["credential-canary"]}`},
		{field: "json", value: "redis-password-canary"},
		{field: "unknown", value: `{"name":"unknown","scope":"TENANT","tenantId":"corrupt","permissions":["read"],"extra":true}`},
		{field: "duplicate", value: `{"name":"duplicate","name":"duplicate","scope":"TENANT","tenantId":"corrupt","permissions":["read"]}`},
		{field: "null", value: `{"name":"null","scope":null,"tenantId":"corrupt","permissions":["read"]}`},
		{field: "trailing", value: `{"name":"trailing","scope":"TENANT","tenantId":"corrupt","permissions":["read"]} {}`},
		{field: "scope", value: `{"name":"scope","scope":"RESOURCE","tenantId":"corrupt","resourceId":"other","permissions":["read"]}`},
		{field: "resource", value: `{"name":"resource","scope":"TENANT","tenantId":"corrupt","resourceId":"other","permissions":["read"]}`},
		{field: "tenant", value: `{"name":"tenant","scope":"TENANT","tenantId":"other","permissions":["read"]}`},
		{field: "order", value: `{"name":"order","scope":"TENANT","tenantId":"corrupt","permissions":["write","read"]}`},
		{field: "permission", value: `{"name":"permission","scope":"TENANT","tenantId":"corrupt","permissions":["read","read"]}`},
		{field: "policy", value: `{"name":"policy","scope":"TENANT","tenantId":"corrupt","permissions":["code-admin:tenants:admin"]}`},
	} {
		if err := rdb.HSet(ctx, rolesKey("corrupt"), corrupt.field, corrupt.value).Err(); err != nil {
			t.Fatalf("seed corrupt role: %v", err)
		}
		_, exactErr := repo.GetExact(ctx, "corrupt", corrupt.field)
		_, listErr := repo.ListExact(ctx, "corrupt")
		leaked := corrupt.value != "" && (strings.Contains(exactErr.Error(), corrupt.value) || strings.Contains(listErr.Error(), corrupt.value))
		if !errors.Is(exactErr, errStoredRoleContract) || !errors.Is(listErr, errStoredRoleContract) || leaked {
			t.Fatalf("corruption was not redacted: exact=%v list=%v", exactErr, listErr)
		}
		if err := rdb.Del(ctx, rolesKey("corrupt")).Err(); err != nil {
			t.Fatalf("clear corrupt role: %v", err)
		}
	}
	closed := NewRoleRepo(closedRedisClient()).(*roleRepo)
	if _, err := closed.GetExact(ctx, "bereia", "read"); err == nil {
		t.Fatal("closed Redis exact get succeeded")
	}
	if _, err := closed.ListExact(ctx, "bereia"); err == nil {
		t.Fatal("closed Redis exact list succeeded")
	}
}

func FuzzDecodeExactRole(f *testing.F) {
	for _, seed := range [][2]string{
		{"read", `{"name":"read","scope":"TENANT","tenantId":"bereia","permissions":["scope:read"]}`},
		{"alias", `{"name":"admin"}`},
		{"empty", ""},
		{"json", "{"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, name, value string) {
		if len(name) > 256 || len(value) > 4096 {
			return
		}
		role, err := decodeExactRole("bereia", name, value)
		if err == nil && (value == "" || role == nil || role.Name != name) {
			t.Fatalf("invalid exact role accepted: name=%q role=%+v", name, role)
		}
	})
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

func TestRoleRepo_CreateIfAbsentAtomicAndTenantScoped(t *testing.T) {
	_, repository := newRoleRepoForTest(t)
	repo := repository.(*roleRepo)
	ctx := context.Background()
	definitions := [][]string{{"scope:read"}, {"scope:write"}}
	var wait sync.WaitGroup
	created := make(chan bool, 32)
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			role := &domain.Role{Name: "bereia-role", Scope: domain.RoleScopeTenant, TenantId: "bereia", Permissions: definitions[index%2]}
			_, wasCreated, err := repo.CreateIfAbsent(ctx, "bereia", role)
			if err != nil {
				t.Errorf("concurrent create: %v", err)
			}
			created <- wasCreated
		}(index)
	}
	wait.Wait()
	winners := 0
	for range 32 {
		if <-created {
			winners++
		}
	}
	stored, err := repo.Get(ctx, "bereia", "bereia-role")
	if err != nil || winners != 1 || !reflect.DeepEqual(stored.Permissions, definitions[0]) && !reflect.DeepEqual(stored.Permissions, definitions[1]) {
		t.Fatalf("winners=%d stored=%+v err=%v", winners, stored, err)
	}
	other, otherCreated, err := repo.CreateIfAbsent(ctx, "storifly", &domain.Role{Name: stored.Name, Scope: domain.RoleScopeTenant, TenantId: "storifly", Permissions: []string{"storifly:admin"}})
	if err != nil || !otherCreated || other.TenantId != "storifly" {
		t.Fatalf("other tenant = %+v, %v, %v", other, otherCreated, err)
	}
	replay, replayCreated, err := repo.CreateIfAbsent(ctx, "bereia", &domain.Role{Name: stored.Name, Scope: domain.RoleScopeTenant, TenantId: "bereia", Permissions: []string{"scope:other"}})
	if err != nil || replayCreated || !reflect.DeepEqual(replay, stored) {
		t.Fatalf("replay overwrote canonical role: %+v, %v, %v", replay, replayCreated, err)
	}
}

func TestRoleRepo_CreateIfAbsentRejectsInvalidAndStorageFailure(t *testing.T) {
	_, repository := newRoleRepoForTest(t)
	repo := repository.(*roleRepo)
	for _, input := range []struct {
		tenant string
		role   *domain.Role
	}{{role: &domain.Role{Name: "r"}}, {tenant: "t"}, {tenant: "t", role: &domain.Role{}}} {
		if _, _, err := repo.CreateIfAbsent(context.Background(), input.tenant, input.role); err != domain.ErrInvalidArgument {
			t.Fatalf("invalid input accepted: %+v", input)
		}
	}
	closed := NewRoleRepo(closedRedisClient()).(*roleRepo)
	if _, _, err := closed.CreateIfAbsent(context.Background(), "t", &domain.Role{Name: "r", Scope: domain.RoleScopeTenant, TenantId: "t", Permissions: []string{"read"}}); err == nil {
		t.Fatal("closed Redis create succeeded")
	}
}
