package repository

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestWorkloadAccountDeletionRemovesIdentityAndTenantMembershipAtomically(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	user := &domain.User{
		Id: "user-1", Email: "reader@example.com", Password: "hash", Status: domain.UserStatusActive,
		CreatedAt: time.Now().UTC(), AuthSource: domain.AuthSourcePassword,
	}
	userJSON, err := json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	membership := domain.Membership{
		Id: membershipV2ID("bereia", user.Id), TenantId: "bereia", UserId: user.Id,
		Roles: []string{"bereia-user"}, CreatedAt: time.Now().UTC(),
	}
	membershipJSON, err := json.Marshal(membership)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.HSet(ctx, usersHashV2, user.Id, userJSON).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.Set(ctx, userByEmailKeyNS+user.Email, user.Id, 0).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.HSet(ctx, membershipV2Key("bereia"), user.Id, membershipJSON).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.SAdd(ctx, membershipV2ByUserKey(user.Id), "bereia").Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.HSet(ctx, membershipsKey("bereia"), user.Id, membershipJSON).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.SAdd(ctx, membershipsByUserPrefix+user.Id, "bereia").Err(); err != nil {
		t.Fatal(err)
	}

	repository := NewWorkloadAccountDeletionRepo(client)
	if err := repository.Delete(ctx, "bereia", user.Id, user.Email); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	for _, key := range []string{userByEmailKeyNS + user.Email, membershipV2ByUserKey(user.Id), membershipsByUserPrefix + user.Id} {
		if exists, err := client.Exists(ctx, key).Result(); err != nil || exists != 0 {
			t.Fatalf("key %q remains, exists=%d err=%v", key, exists, err)
		}
	}
	for _, item := range []struct{ key, field string }{
		{usersHashV2, user.Id}, {membershipV2Key("bereia"), user.Id}, {membershipsKey("bereia"), user.Id},
	} {
		if exists, err := client.HExists(ctx, item.key, item.field).Result(); err != nil || exists {
			t.Fatalf("hash field %q/%q remains, exists=%t err=%v", item.key, item.field, exists, err)
		}
	}
}

func TestWorkloadAccountDeletionFailsClosedWithoutCompleteMembershipPair(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	if err := client.HSet(ctx, usersHashV2, "user-1", `{}`).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.Set(ctx, userByEmailKeyNS+"reader@example.com", "user-1", 0).Err(); err != nil {
		t.Fatal(err)
	}
	err := NewWorkloadAccountDeletionRepo(client).Delete(ctx, "bereia", "user-1", "reader@example.com")
	if !errors.Is(err, errWorkloadAccountDeletionContract) {
		t.Fatalf("Delete() error = %v", err)
	}
	if exists, _ := client.HExists(ctx, usersHashV2, "user-1").Result(); !exists {
		t.Fatal("corrupt account was partially deleted")
	}
}
