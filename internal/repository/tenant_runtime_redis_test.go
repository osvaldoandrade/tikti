package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/internal/testredis"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestSQLTenantRuntimeRealRedisCAS(t *testing.T) {
	server, err := testredis.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	repo := NewTenantRepo(server.Client)
	assertSQLBootstrapRetirementRace(t, repo)
	reader := repo.(RetainedTenantRepository)
	server.Close()
	if got, err := reader.GetRetained(context.Background(), "payments", time.Now().UTC()); got != nil || err == nil {
		t.Fatal("real Redis outage became authority or absence")
	}
}

type bootstrapCASBarrier struct {
	once   sync.Once
	read   chan struct{}
	resume chan struct{}
	before bool
}

func (h *bootstrapCASBarrier) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
	if h.before && cmd.Name() == "hget" {
		h.once.Do(func() { close(h.read); <-h.resume })
	}
	return ctx, nil
}
func (h *bootstrapCASBarrier) AfterProcess(_ context.Context, cmd redis.Cmder) error {
	if !h.before && cmd.Name() == "hget" {
		h.once.Do(func() { close(h.read); <-h.resume })
	}
	return nil
}

func TestSQLTenantRuntimeRealRedisReplayConcurrentRetirementIsConflict(t *testing.T) {
	server, err := testredis.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx := context.Background()
	repo := NewTenantRepo(server.Client)
	if err := repo.Create(ctx, &domain.Tenant{Id: "payments", Slug: "payments", Name: "Payments"}); err != nil {
		t.Fatal(err)
	}
	options := *server.Client.Options()
	other := redis.NewClient(&options)
	defer other.Close()
	barrier := &bootstrapCASBarrier{read: make(chan struct{}), resume: make(chan struct{}), before: true}
	other.AddHook(barrier)
	result := make(chan error, 1)
	go func() {
		_, _, err := NewTenantRepo(other).CreateIfAbsent(ctx, &domain.Tenant{Id: "payments", Slug: "payments", Name: "Replay"})
		result <- err
	}()
	select {
	case <-barrier.read:
	case <-time.After(5 * time.Second):
		close(barrier.resume)
		t.Fatal("replay did not reach read")
	}
	retireErr := repo.(*tenantRepo).Retire(ctx, "payments")
	close(barrier.resume)
	if retireErr != nil {
		t.Fatal(retireErr)
	}
	select {
	case err := <-result:
		if !errors.Is(err, domain.ErrTenantConflict) {
			t.Fatal("valid concurrent retirement was not classified as an occupied lifetime")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("replay did not settle")
	}
}
func (*bootstrapCASBarrier) BeforeProcessPipeline(ctx context.Context, _ []redis.Cmder) (context.Context, error) {
	return ctx, nil
}
func (*bootstrapCASBarrier) AfterProcessPipeline(context.Context, []redis.Cmder) error { return nil }

func TestSQLTenantRuntimeRealRedisRetirementWinsWatchedBootstrap(t *testing.T) {
	server, err := testredis.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx := context.Background()
	repo := NewTenantRepo(server.Client)
	birth := time.Date(2024, 1, 2, 3, 4, 5, 6, time.UTC)
	if err := repo.Create(ctx, &domain.Tenant{Id: "payments", Slug: "payments", Name: "Payments", CreatedAt: birth}); err != nil {
		t.Fatal(err)
	}
	options := *server.Client.Options()
	other := redis.NewClient(&options)
	defer other.Close()
	bootstrap := NewTenantRepo(other)
	barrier := &bootstrapCASBarrier{read: make(chan struct{}), resume: make(chan struct{})}
	other.AddHook(barrier)
	result := make(chan error, 1)
	go func() {
		result <- bootstrap.Create(ctx, &domain.Tenant{Id: "payments", Slug: "payments", Name: "Bootstrap"})
	}()
	select {
	case <-barrier.read:
	case <-time.After(5 * time.Second):
		close(barrier.resume)
		t.Fatal("bootstrap never reached watched read")
	}
	retireErr := repo.(*tenantRepo).Retire(ctx, "payments")
	close(barrier.resume)
	if retireErr != nil {
		t.Fatal(retireErr)
	}
	select {
	case err := <-result:
		if !errors.Is(err, domain.ErrTenantConflict) {
			t.Fatal("stale bootstrap transaction did not fail after retirement")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bootstrap CAS did not settle")
	}
	retained, err := repo.(RetainedTenantRepository).GetRetained(ctx, "payments", time.Now().UTC())
	if err != nil || retained == nil || retained.RetiredAt == nil || !retained.CreatedAt.Equal(birth) {
		t.Fatal("WATCH retry destroyed retained lifetime")
	}
}
