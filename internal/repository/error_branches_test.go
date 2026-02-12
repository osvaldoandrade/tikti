package repository

import (
	"context"
	"testing"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func closedRedisClient() *redis.Client {
	c := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	_ = c.Close()
	return c
}

func TestRepository_ErrorBranches_WithClosedRedisClient(t *testing.T) {
	ctx := context.Background()
	rdb := closedRedisClient()

	// client repository
	cr := NewClientRepo(rdb).(*clientRepo)
	if err := cr.Create(ctx, "t1", &domain.Client{Id: "c1"}); err == nil {
		t.Fatalf("expected client create error")
	}
	if _, err := cr.Get(ctx, "t1", "c1"); err == nil {
		t.Fatalf("expected client get error")
	}
	if _, err := cr.List(ctx, "t1"); err == nil {
		t.Fatalf("expected client list error")
	}

	// membership repository
	mr := NewMembershipRepo(rdb).(*membershipRepo)
	if err := mr.Create(ctx, &domain.Membership{TenantId: "t1", UserId: "u1"}); err == nil {
		t.Fatalf("expected membership create error")
	}
	if _, err := mr.Get(ctx, "t1", "u1"); err == nil {
		t.Fatalf("expected membership get error")
	}
	if _, err := mr.ListTenantIDsByUser(ctx, "u1"); err == nil {
		t.Fatalf("expected membership list error")
	}

	// role repository
	rr := NewRoleRepo(rdb).(*roleRepo)
	if err := rr.Create(ctx, "t1", &domain.Role{Name: "R1"}); err == nil {
		t.Fatalf("expected role create error")
	}
	if _, err := rr.Get(ctx, "t1", "R1"); err == nil {
		t.Fatalf("expected role get error")
	}
	if _, err := rr.List(ctx, "t1"); err == nil {
		t.Fatalf("expected role list error")
	}

	// tenant repository
	tr := NewTenantRepo(rdb).(*tenantRepo)
	if err := tr.Create(ctx, &domain.Tenant{Id: "t1"}); err == nil {
		t.Fatalf("expected tenant create error")
	}
	if _, err := tr.Get(ctx, "t1"); err == nil {
		t.Fatalf("expected tenant get error")
	}
	if _, err := tr.EnsureDefault(ctx); err == nil {
		t.Fatalf("expected tenant ensure default error")
	}

	// user repository
	ur := NewRedisRepo(rdb).(*redisRepo)
	if err := ur.CreateUser(ctx, &domain.User{Id: "u1", Email: "u1@x.com", Password: "h"}); err == nil {
		t.Fatalf("expected user create error")
	}
	if _, err := ur.FindByEmail(ctx, "u1@x.com"); err == nil {
		t.Fatalf("expected user find error")
	}
	if err := ur.UpdateUser(ctx, &domain.User{Id: "u1", Email: "u1@x.com"}); err == nil {
		t.Fatalf("expected user update error")
	}
	if _, err := ur.SetStatus(ctx, "u1@x.com", domain.UserStatusActive); err == nil {
		t.Fatalf("expected user set status error")
	}
	if _, _, err := ur.IncrementTokenVersion(ctx, "u1@x.com"); err == nil {
		t.Fatalf("expected increment token version error")
	}
	if err := ur.SaveOobCode(ctx, "c1", "u1@x.com", "EMAIL_SIGNIN"); err == nil {
		t.Fatalf("expected save oob error")
	}
	if _, err := ur.ConsumeOobCode(ctx, "c1", "EMAIL_SIGNIN"); err == nil {
		t.Fatalf("expected consume oob error")
	}
	if _, err := ur.GetAllUsers(ctx); err == nil {
		t.Fatalf("expected get all users error")
	}
}
