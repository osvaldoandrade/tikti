package repository

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/internal/testredis"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestCanonicalEmailLookupNeverImportsLegacyAfterBackfill(t *testing.T) {
	client, _ := newIdentityDirectoryForTest(t)
	ctx := context.Background()
	user := &domain.User{Id: "historic-user", Email: "historic@example.com", Password: "old-hash"}
	raw, _ := json.Marshal(user)
	client.HSet(ctx, legacyUsersHash, user.Email, raw)
	client.Set(ctx, directoryBackfillMarker, directoryBackfillVersion, 0)
	if got, err := NewRedisRepo(client).FindByEmail(ctx, user.Email); err != nil || got != nil {
		t.Fatalf("legacy became authority after backfill: present=%v err=%v", got != nil, err)
	}
	if client.HExists(ctx, usersHashV2, user.Id).Val() || client.Exists(ctx, userByEmailKeyNS+user.Email).Val() != 0 {
		t.Fatal("legacy imported after backfill")
	}
}

func TestLegacyEmailImportDoesNotOverwriteExistingUID(t *testing.T) {
	client, directory := newIdentityDirectoryForTest(t)
	ctx := context.Background()
	user := &domain.User{Id: "same-uid", Email: "current@example.com", Password: "current-hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now().UTC()}
	if _, err := directory.CreateDirectoryUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	legacy := *user
	legacy.Email = "previous@example.com"
	legacy.Password = "previous-hash"
	raw, _ := json.Marshal(legacy)
	client.HSet(ctx, legacyUsersHash, legacy.Email, raw)
	if got, err := NewRedisRepo(client).FindByEmail(ctx, legacy.Email); got != nil || !errors.Is(err, domain.ErrDirectoryInvariant) {
		t.Fatalf("legacy overwrite present=%v err=%v", got != nil, err)
	}
	current, err := NewRedisRepo(client).FindByEmail(ctx, user.Email)
	if err != nil || current == nil || current.Password != "current-hash" {
		t.Fatal("legacy overwrote current UID")
	}
}

type legacyCompletionHook struct {
	once     sync.Once
	complete func()
}

func (h *legacyCompletionHook) BeforeProcess(ctx context.Context, _ redis.Cmder) (context.Context, error) {
	return ctx, nil
}
func (h *legacyCompletionHook) AfterProcess(_ context.Context, cmd redis.Cmder) error {
	args := cmd.Args()
	if cmd.Name() == "hget" && len(args) > 1 && args[1] == legacyUsersHash {
		h.once.Do(h.complete)
	}
	return nil
}
func (h *legacyCompletionHook) BeforeProcessPipeline(ctx context.Context, _ []redis.Cmder) (context.Context, error) {
	return ctx, nil
}
func (h *legacyCompletionHook) AfterProcessPipeline(context.Context, []redis.Cmder) error { return nil }

func TestLegacyEmailImportCannotRaceBackfillCompletion(t *testing.T) {
	server, err := testredis.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	client := server.Client
	ctx := context.Background()
	other := redis.NewClient(&redis.Options{Network: "unix", Addr: client.Options().Addr})
	t.Cleanup(func() { _ = other.Close() })
	user := &domain.User{Id: "old-uid", Email: "old@example.com", Password: "old-hash"}
	raw, _ := json.Marshal(user)
	client.HSet(ctx, legacyUsersHash, user.Email, raw)
	client.AddHook(&legacyCompletionHook{complete: func() {
		if err := other.Set(ctx, directoryBackfillMarker, directoryBackfillVersion, 0).Err(); err != nil {
			t.Error(err)
		}
		if err := other.HDel(ctx, legacyUsersHash, user.Email).Err(); err != nil {
			t.Error(err)
		}
	}})
	if got, err := NewRedisRepo(client).FindByEmail(ctx, user.Email); err != nil || got != nil {
		t.Fatalf("inflight legacy import survived completion: present=%v err=%v", got != nil, err)
	}
	if other.HExists(ctx, usersHashV2, user.Id).Val() {
		t.Fatal("late HSET resurrected old UID")
	}
}
