package repository

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/internal/testredis"
	"sync"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestDirectoryUserDeletionCleansRetiredDefaultMembership(t *testing.T) {
	client, directory, actor, target := newDeletionUsers(t)
	ctx := context.Background()
	membership := &domain.Membership{Id: "historic-membership", TenantId: domain.RetiredDefaultTenantID, UserId: target.Id, Roles: []string{"reader"}, CreatedAt: time.Now().UTC()}
	raw, _ := json.Marshal(membership)
	client.HSet(ctx, membershipsKey(domain.RetiredDefaultTenantID), target.Id, raw)
	client.SAdd(ctx, membershipsByUserPrefix+target.Id, domain.RetiredDefaultTenantID)
	if deleted, err := directory.DeleteDirectoryUser(ctx, target.Id, 1, actor); err != nil || !deleted {
		t.Fatalf("delete=%v err=%v", deleted, err)
	}
	if client.HExists(ctx, membershipsKey(domain.RetiredDefaultTenantID), target.Id).Val() {
		t.Fatal("retired membership remains")
	}
}

type deletionInterleaveHook struct {
	once   sync.Once
	change func()
}

func (h *deletionInterleaveHook) BeforeProcess(ctx context.Context, _ redis.Cmder) (context.Context, error) {
	return ctx, nil
}
func (h *deletionInterleaveHook) AfterProcess(context.Context, redis.Cmder) error { return nil }
func (h *deletionInterleaveHook) BeforeProcessPipeline(ctx context.Context, _ []redis.Cmder) (context.Context, error) {
	h.once.Do(h.change)
	return ctx, nil
}
func (h *deletionInterleaveHook) AfterProcessPipeline(context.Context, []redis.Cmder) error {
	return nil
}

func TestDirectoryUserDeletionRechecksAuthorityAtCommit(t *testing.T) {
	for _, scenario := range []string{"actor changed", "target changed"} {
		t.Run(scenario, func(t *testing.T) {
			server, err := testredis.Start()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(server.Close)
			client, directory, actor, target := newDeletionUsers(t, server.Client)
			ctx := context.Background()
			second := redis.NewClient(&redis.Options{Network: "unix", Addr: client.Options().Addr})
			t.Cleanup(func() { _ = second.Close() })
			id := actor.UserID
			want := domain.ErrDirectoryDeletionDenied
			if scenario == "target changed" {
				id = target.Id
				want = domain.ErrVersionConflict
			}
			client.AddHook(&deletionInterleaveHook{change: func() {
				raw, err := second.HGet(ctx, usersHashV2, id).Result()
				if err != nil {
					t.Error(err)
					return
				}
				var user domain.User
				if err = json.Unmarshal([]byte(raw), &user); err != nil {
					t.Error(err)
					return
				}
				user.Revision++
				payload, _ := json.Marshal(user)
				if err = second.HSet(ctx, usersHashV2, id, payload).Err(); err != nil {
					t.Error(err)
				}
			}})
			if deleted, err := directory.DeleteDirectoryUser(ctx, target.Id, 1, actor); deleted || !errors.Is(err, want) {
				t.Fatalf("interleaved delete=%v err=%v want=%v", deleted, err, want)
			}
			if !second.HExists(ctx, usersHashV2, target.Id).Val() {
				t.Fatal("concurrent change did not preserve target")
			}
		})
	}
}

func TestDirectoryUserDeletionCannotResurrectPreviousEmail(t *testing.T) {
	client, directory, actor, target := newDeletionUsers(t)
	ctx := context.Background()
	client.Set(ctx, directoryBackfillMarker, directoryBackfillVersion, 0)
	oldEmail := target.Email
	raw, _ := json.Marshal(target)
	client.HSet(ctx, legacyUsersHash, oldEmail, raw)
	target.Email = "renamed@example.com"
	if _, err := directory.UpdateDirectoryUser(ctx, target); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.DeleteDirectoryUser(ctx, target.Id, 2, actor); err != nil {
		t.Fatal(err)
	}
	if restored, err := NewRedisRepo(client).FindByEmail(ctx, oldEmail); err != nil || restored != nil {
		t.Fatalf("deleted UID resurrected from old email: present=%v err=%v", restored != nil, err)
	}
	if client.HExists(ctx, usersHashV2, target.Id).Val() {
		t.Fatal("deleted UID reimported")
	}
}

func TestDirectoryUserDeletionRequiresCompletedMigrationEvenWhenAbsent(t *testing.T) {
	for _, id := range []string{"target-user", "absent-user"} {
		t.Run(id, func(t *testing.T) {
			client, directory, actor, _ := newDeletionUsers(t)
			ctx := context.Background()
			client.Del(ctx, directoryBackfillMarker)
			if deleted, err := directory.DeleteDirectoryUser(ctx, id, 1, actor); err == nil || deleted {
				t.Fatalf("delete before complete=%v err=%v", deleted, err)
			}
			if !client.HExists(ctx, usersHashV2, "target-user").Val() {
				t.Fatal("incomplete migration delete changed target")
			}
		})
	}
}
