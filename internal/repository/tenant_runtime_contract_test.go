package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type retainedRuntimeReader interface {
	GetRetained(context.Context, string, time.Time) (*domain.Tenant, error)
}

func TestSQLTenantRuntimeBootstrapPreservesLifetimeAndDisabledState(t *testing.T) {
	client, repo := newTenantRepoForTest(t)
	ctx := context.Background()
	birth := time.Date(2024, 3, 4, 5, 6, 7, 123, time.UTC)
	for _, status := range []domain.TenantStatus{domain.TenantStatusActive, domain.TenantStatusDisabled} {
		t.Run(string(status), func(t *testing.T) {
			id := strings.ToLower(string(status))
			if err := repo.Create(ctx, &domain.Tenant{Id: id, Slug: id, Name: id, CreatedAt: birth, Status: status}); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				if err := repo.Create(ctx, &domain.Tenant{Id: id, Slug: id, Name: "Bootstrap replay", CreatedAt: time.Now().UTC(), Status: domain.TenantStatusActive}); err != nil {
					t.Fatal(err)
				}
			}
			var stored domain.Tenant
			if err := json.Unmarshal([]byte(client.HGet(ctx, tenantsHash, id).Val()), &stored); err != nil {
				t.Fatal(err)
			}
			if !stored.CreatedAt.Equal(birth) || stored.Status != status {
				t.Fatal("bootstrap rewrote the lifetime or resurrected a disabled tenant")
			}
		})
	}
}

func TestSQLTenantRuntimeStrictRetainedReadAndInvalidReplay(t *testing.T) {
	client, repo := newTenantRepoForTest(t)
	reader, ok := repo.(retainedRuntimeReader)
	if !ok {
		t.Fatal("strict retained runtime reader is missing")
	}
	ctx := context.Background()
	now := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	birth := now.Add(-time.Hour)
	valid := `{"id":"payments","slug":"payments","name":"Payments","status":"ACTIVE","createdAt":"` + birth.Format(time.RFC3339Nano) + `"}`
	if got, err := reader.GetRetained(ctx, "payments", now); err != nil || got != nil {
		t.Fatal("Redis nil must be the only absent record")
	}
	bad := []string{
		"", "null", "[]", "{}", valid + `{}`, strings.Replace(valid, `"id":"payments"`, `"id":"foreign"`, 1),
		strings.Replace(valid, `"slug":"payments"`, `"slug":"alias"`, 1),
		strings.Replace(valid, `"id":`, `"ID":`, 1),
		strings.Replace(valid, `"status":"ACTIVE"`, `"status":"UNKNOWN"`, 1),
		strings.Replace(valid, `"status":"ACTIVE"`, `"status":null`, 1),
		strings.Replace(valid, `"createdAt":"`+birth.Format(time.RFC3339Nano)+`"`, `"createdAt":"0001-01-01T00:00:00Z"`, 1),
		strings.Replace(valid, birth.Format(time.RFC3339Nano), time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339Nano), 1),
		strings.Replace(valid, birth.Format(time.RFC3339Nano), "2024-01-01T00:00:00+24:00", 1),
		strings.Replace(valid, birth.Format(time.RFC3339Nano), "2024-01-01T00:00:00.000Z", 1),
		strings.Replace(valid, `"name":"Payments"`, `"name":" Payments"`, 1),
		strings.Replace(valid, `}`, `,"unknown":"store-secret-sentinel"}`, 1),
		strings.Replace(valid, `}`, `,"id":"payments"}`, 1),
		strings.Replace(valid, `}`, `,"retiredAt":null}`, 1),
		strings.Replace(valid, `}`, `,"retiredAt":"`+birth.Add(time.Minute).Format(time.RFC3339Nano)+`"}`, 1),
		strings.Replace(strings.Replace(valid, `ACTIVE`, `DISABLED`, 1), `}`, `,"retiredAt":"`+birth.Add(-time.Second).Format(time.RFC3339Nano)+`"}`, 1),
		strings.Replace(strings.Replace(valid, `ACTIVE`, `DISABLED`, 1), `}`, `,"retiredAt":"`+time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339Nano)+`"}`, 1),
	}
	for i, raw := range bad {
		if err := client.HSet(ctx, tenantsHash, "payments", raw).Err(); err != nil {
			t.Fatal(err)
		}
		if got, err := reader.GetRetained(ctx, "payments", now); got != nil || err == nil || strings.Contains(err.Error(), "sentinel") {
			t.Fatalf("invalid retained fixture %d was accepted or disclosed", i)
		}
		candidate := &domain.Tenant{Id: "payments", Slug: "payments", Name: "Payments", CreatedAt: birth}
		if err := repo.Create(ctx, candidate); err == nil {
			t.Fatalf("Create repaired invalid retained fixture %d", i)
		}
		if _, created, err := repo.CreateIfAbsent(ctx, candidate); created || err == nil {
			t.Fatalf("CreateIfAbsent accepted invalid retained fixture %d", i)
		}
		if got := client.HGet(ctx, tenantsHash, "payments").Val(); got != raw {
			t.Fatalf("invalid stored fixture %d was overwritten", i)
		}
	}
	for _, id := range []string{"", "default", "Payments", "payments/", strings.Repeat("a", 64)} {
		if got, err := reader.GetRetained(ctx, id, now); got != nil || !errors.Is(err, domain.ErrInvalidTenant) {
			t.Fatal("noncanonical tenant ID reached retained authority")
		}
	}
	if err := client.HSet(ctx, tenantsHash, "payments", valid).Err(); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.GetRetained(ctx, "payments", now); err != nil || got == nil || !got.CreatedAt.Equal(birth) {
		t.Fatal("valid retained lifetime rejected")
	}
	if err := repo.(*tenantRepo).Retire(ctx, "payments"); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.GetRetained(ctx, "payments", time.Now().UTC()); err != nil || got == nil || got.RetiredAt == nil || !got.CreatedAt.Equal(birth) {
		t.Fatal("retired lifetime was lost")
	}
	if got, err := repo.Get(ctx, "payments"); err != nil || got != nil {
		t.Fatal("legacy Get revealed retained tenant")
	}
	if got, err := repo.(ExactTenantRepository).GetExact(ctx, "payments"); err != nil || got != nil {
		t.Fatal("GetExact revealed retained tenant")
	}
}

func TestSQLTenantRuntimeConcurrentBootstrapRetirement(t *testing.T) {
	_, repo := newTenantRepoForTest(t)
	assertSQLBootstrapRetirementRace(t, repo)
}

func assertSQLBootstrapRetirementRace(t *testing.T, repo TenantRepository) {
	t.Helper()
	ctx := context.Background()
	birth := time.Date(2024, 1, 2, 3, 4, 5, 6, time.UTC)
	if err := repo.Create(ctx, &domain.Tenant{Id: "payments", Slug: "payments", Name: "Payments", CreatedAt: birth}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var group sync.WaitGroup
	for worker := range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			var err error
			switch worker % 3 {
			case 0:
				err = repo.Create(ctx, &domain.Tenant{Id: "payments", Slug: "payments", Name: "Bootstrap"})
			case 1:
				_, _, err = repo.CreateIfAbsent(ctx, &domain.Tenant{Id: "payments", Slug: "payments", Name: "Replay"})
			case 2:
				err = repo.(*tenantRepo).Retire(ctx, "payments")
			}
			if err != nil && !errors.Is(err, domain.ErrTenantConflict) && !errors.Is(err, domain.ErrVersionConflict) {
				t.Errorf("unexpected concurrent operation failure: worker=%d invariant=%t", worker, errors.Is(err, domain.ErrTenantInvariant))
			}
		}()
	}
	close(start)
	group.Wait()
	if err := repo.(*tenantRepo).Retire(ctx, "payments"); err != nil {
		t.Fatal(err)
	}
	reader, ok := repo.(retainedRuntimeReader)
	if !ok {
		t.Fatal("strict retained runtime reader is missing")
	}
	retained, err := reader.GetRetained(ctx, "payments", time.Now().UTC())
	if err != nil || retained == nil || retained.RetiredAt == nil || retained.Status != domain.TenantStatusDisabled || !retained.CreatedAt.Equal(birth) {
		t.Fatal("concurrent bootstrap/retirement changed lifetime or resurrected authority")
	}
}

// The read contract is a single HGET, with no lazy repairs or inventory reads.
type runtimeCommandsHook struct{ commands []string }

func (h *runtimeCommandsHook) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
	h.commands = append(h.commands, cmd.Name())
	return ctx, nil
}
func (*runtimeCommandsHook) AfterProcess(context.Context, redis.Cmder) error { return nil }
func (h *runtimeCommandsHook) BeforeProcessPipeline(ctx context.Context, cmds []redis.Cmder) (context.Context, error) {
	for _, cmd := range cmds {
		h.commands = append(h.commands, cmd.Name())
	}
	return ctx, nil
}
func (*runtimeCommandsHook) AfterProcessPipeline(context.Context, []redis.Cmder) error { return nil }

func TestSQLTenantRuntimeReadHasExactlyOneHGET(t *testing.T) {
	client, repo := newTenantRepoForTest(t)
	reader, ok := repo.(retainedRuntimeReader)
	if !ok {
		t.Fatal("strict retained runtime reader is missing")
	}
	hook := &runtimeCommandsHook{}
	client.AddHook(hook)
	if _, err := reader.GetRetained(context.Background(), "payments", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(hook.commands, ",") != "hget" {
		t.Fatal("authority performed something other than one HGET")
	}
}
