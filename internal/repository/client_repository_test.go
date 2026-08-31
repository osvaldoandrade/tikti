package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func newClientRepoForTest(t *testing.T) (*redis.Client, ClientRepository) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, NewClientRepo(rdb)
}

func TestNewClientRepo(t *testing.T) {
	_, repo := newClientRepoForTest(t)
	if repo == nil {
		t.Fatalf("expected repo")
	}
}

func TestClientRepo_CreateGetList(t *testing.T) {
	_, repo := newClientRepoForTest(t)
	ctx := context.Background()
	r := repo.(*clientRepo)

	c := &domain.Client{Id: "c1", Type: domain.ClientTypeService}
	if err := r.Create(ctx, "t1", c); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	got, err := r.Get(ctx, "t1", "c1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got == nil || got.Id != "c1" {
		t.Fatalf("unexpected client: %+v", got)
	}

	list, err := r.List(ctx, "t1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(list) != 1 || list[0].Id != "c1" {
		t.Fatalf("unexpected list: %+v", list)
	}
}

func TestClientRepoUsesDirectEvalForKvrocksCompatibility(t *testing.T) {
	rdb, repo := newClientRepoForTest(t)
	rdb.AddHook(commandErrorHook{byName: map[string]error{
		"evalsha": errors.New("EVALSHA forbidden"),
	}})
	ctx := context.Background()

	if err := repo.Create(ctx, "local-tenant", &domain.Client{
		Id: "legacy-client", Type: domain.ClientTypeService,
	}); err != nil {
		t.Fatalf("create with direct EVAL: %v", err)
	}
	if _, _, err := repo.EnsureManagedAudience(
		ctx,
		"bereia",
		managedAudienceFixture("bereia", "code-admin:workloads:read"),
	); err != nil {
		t.Fatalf("ensure managed audience with direct EVAL: %v", err)
	}
	if _, err := repo.Get(ctx, "bereia", domain.CodeAdminAudienceClientID); err != nil {
		t.Fatalf("get with direct EVAL: %v", err)
	}
	if _, err := repo.List(ctx, "bereia"); err != nil {
		t.Fatalf("list with direct EVAL: %v", err)
	}
}

func TestClientRepo_CreateInvalidArgument(t *testing.T) {
	_, repo := newClientRepoForTest(t)
	ctx := context.Background()
	r := repo.(*clientRepo)

	if err := r.Create(ctx, "", &domain.Client{Id: "c1"}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for empty tenant, got %v", err)
	}
	if err := r.Create(ctx, "t1", nil); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for nil client, got %v", err)
	}
	if err := r.Create(ctx, "t1", &domain.Client{}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for empty client id, got %v", err)
	}
}

func TestClientRepo_GetNotFoundAndInvalidJSON(t *testing.T) {
	rdb, repo := newClientRepoForTest(t)
	ctx := context.Background()
	r := repo.(*clientRepo)

	got, err := r.Get(ctx, "t1", "missing")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil client")
	}

	if err := rdb.HSet(ctx, clientsKey("t1"), "bad", "{").Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	if _, err := r.Get(ctx, "t1", "bad"); err == nil {
		t.Fatalf("expected unmarshal error")
	}
}

func TestClientRepo_ListInvalidJSON(t *testing.T) {
	rdb, repo := newClientRepoForTest(t)
	ctx := context.Background()
	r := repo.(*clientRepo)

	if err := rdb.HSet(ctx, clientsKey("t1"), "bad", "{").Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	if _, err := r.List(ctx, "t1"); err == nil {
		t.Fatalf("expected unmarshal error")
	}
}

func TestClientsKey(t *testing.T) {
	if got := clientsKey("x"); got != "clients:x" {
		t.Fatalf("unexpected key: %s", got)
	}
}

func managedAudienceFixture(tenantID string, scopes ...string) *domain.Client {
	return &domain.Client{
		Id: domain.CodeAdminAudienceClientID, TenantId: tenantID,
		Type: domain.ClientTypeService, Status: domain.ClientStatusActive,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     scopes, ManagedBy: domain.CodeAdminAudienceClientManager,
	}
}

func TestClientRepo_EnsureManagedAudienceConcurrentReplay(t *testing.T) {
	rdb, repo := newClientRepoForTest(t)
	ctx := context.Background()
	const workers = 24
	var created atomic.Int32
	errorsSeen := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			stored, wasCreated, err := repo.EnsureManagedAudience(ctx, "bereia", managedAudienceFixture(
				"bereia", "code-admin:clusters:read", "code-admin:workloads:read", "console:clusters:read",
			))
			if err == nil && !domain.IsManagedCodeAdminAudience("bereia", stored) {
				err = errors.New("invalid managed client returned")
			}
			if wasCreated {
				created.Add(1)
			}
			errorsSeen <- err
		}()
	}
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent ensure: %v", err)
		}
	}
	if created.Load() != 1 {
		t.Fatalf("expected one creator, got %d", created.Load())
	}
	if rdb.HLen(ctx, clientsKey("bereia")).Val() != 1 || rdb.HLen(ctx, managedClientsKey("bereia")).Val() != 1 {
		t.Fatal("managed client and marker were not stored separately")
	}
	raw := rdb.HGet(ctx, clientsKey("bereia"), domain.CodeAdminAudienceClientID).Val()
	if strings.Contains(strings.ToLower(raw), "secret") {
		t.Fatalf("managed payload contains secret material: %s", raw)
	}
}

func TestClientRepo_EnsureManagedAudienceReconcilesOwnedDefinition(t *testing.T) {
	rdb, repo := newClientRepoForTest(t)
	ctx := context.Background()
	initial := managedAudienceFixture("bereia", "code-admin:workloads:read")
	if _, created, err := repo.EnsureManagedAudience(ctx, "bereia", initial); err != nil || !created {
		t.Fatalf("initial ensure: created=%v err=%v", created, err)
	}

	desired := managedAudienceFixture(
		"bereia",
		"code-admin:features:read",
		"code-admin:features:write",
		"code-admin:workloads:read",
	)
	stored, created, err := repo.EnsureManagedAudience(ctx, "bereia", desired)
	if err != nil || created {
		t.Fatalf("reconcile: created=%v err=%v", created, err)
	}
	if !sameManagedAudienceClient(stored, desired) {
		t.Fatalf("reconciled client=%+v, want %+v", stored, desired)
	}
	want, err := json.Marshal(desired)
	if err != nil {
		t.Fatalf("marshal desired client: %v", err)
	}
	for _, key := range []string{clientsKey("bereia"), managedClientsKey("bereia")} {
		if got := rdb.HGet(ctx, key, domain.CodeAdminAudienceClientID).Val(); got != string(want) {
			t.Fatalf("%s contains %q, want %q", key, got, want)
		}
	}
}

func TestClientRepo_EnsureManagedAudienceRejectsUnownedDefinition(t *testing.T) {
	rdb, repo := newClientRepoForTest(t)
	ctx := context.Background()
	want := managedAudienceFixture("bereia", "code-admin:workloads:read")
	if _, created, err := repo.EnsureManagedAudience(ctx, "bereia", want); err != nil || !created {
		t.Fatalf("first ensure: created=%v err=%v", created, err)
	}
	if _, created, err := repo.EnsureManagedAudience(ctx, "bereia", managedAudienceFixture(
		"bereia", "code-admin:workloads:read",
	)); err != nil || created {
		t.Fatalf("replay: created=%v err=%v", created, err)
	}
	legacy := `{"clientId":"code-admin-api","tenantId":"storifly","type":"SERVICE","allowedGrantTypes":["token_exchange"],"defaultScopes":["code-admin:workloads:read"],"status":"ACTIVE"}`
	if err := rdb.HSet(ctx, clientsKey("storifly"), domain.CodeAdminAudienceClientID, legacy).Err(); err != nil {
		t.Fatalf("seed legacy client: %v", err)
	}
	if _, _, err := repo.EnsureManagedAudience(ctx, "storifly", managedAudienceFixture(
		"storifly", "code-admin:workloads:read",
	)); !errors.Is(err, domain.ErrManagedClientConflict) {
		t.Fatalf("expected legacy shadow conflict, got %v", err)
	}
	if rdb.HExists(ctx, managedClientsKey("storifly"), domain.CodeAdminAudienceClientID).Val() {
		t.Fatal("legacy client was adopted")
	}

	corrupt := `{"clientId":"code-admin-api","tenantId":"bereia","type":"SERVICE","allowedGrantTypes":["token_exchange"],"defaultScopes":["not canonical"],"status":"ACTIVE","managedBy":"tikti:code-admin-audience:v1"}`
	if err := rdb.HSet(ctx, clientsKey("bereia"), domain.CodeAdminAudienceClientID, corrupt).Err(); err != nil {
		t.Fatalf("seed corrupt client: %v", err)
	}
	if err := rdb.HSet(ctx, managedClientsKey("bereia"), domain.CodeAdminAudienceClientID, corrupt).Err(); err != nil {
		t.Fatalf("seed corrupt marker: %v", err)
	}
	if _, _, err := repo.EnsureManagedAudience(ctx, "bereia", want); !errors.Is(err, errStoredManagedClientContract) {
		t.Fatalf("expected corrupt managed definition failure, got %v", err)
	}
	if got := rdb.HGet(ctx, clientsKey("bereia"), domain.CodeAdminAudienceClientID).Val(); got != corrupt {
		t.Fatal("corrupt managed client was overwritten")
	}
}

func TestClientRepo_LegacyCreateCannotOverwriteManagedAudience(t *testing.T) {
	rdb, repo := newClientRepoForTest(t)
	ctx := context.Background()
	if _, _, err := repo.EnsureManagedAudience(ctx, "bereia", managedAudienceFixture(
		"bereia", "code-admin:workloads:read",
	)); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	before := rdb.HGet(ctx, clientsKey("bereia"), domain.CodeAdminAudienceClientID).Val()
	err := repo.Create(ctx, "bereia", &domain.Client{
		Id: domain.CodeAdminAudienceClientID, TenantId: "bereia", SecretHash: "hash",
		Type: domain.ClientTypePublic, DefaultScopes: []string{"code-admin:workloads:write"}, Status: "DISABLED",
	})
	if !errors.Is(err, domain.ErrManagedClientConflict) {
		t.Fatalf("expected reserved client conflict, got %v", err)
	}
	if after := rdb.HGet(ctx, clientsKey("bereia"), domain.CodeAdminAudienceClientID).Val(); after != before {
		t.Fatal("legacy create changed the managed client")
	}
}
