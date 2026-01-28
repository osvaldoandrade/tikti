package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type MembershipRepository interface {
	Create(ctx context.Context, membership *domain.Membership) error
	Get(ctx context.Context, tenantID string, userID string) (*domain.Membership, error)
	ListTenantIDsByUser(ctx context.Context, userID string) ([]string, error)
	Delete(ctx context.Context, tenantID string, userID string) error
}

type membershipRepo struct {
	client *redis.Client
}

const membershipsByUserPrefix = "membershipsByUser:"

func NewMembershipRepo(rdb *redis.Client) MembershipRepository {
	return &membershipRepo{client: rdb}
}

func (r *membershipRepo) Create(ctx context.Context, membership *domain.Membership) error {
	if membership.CreatedAt.IsZero() {
		membership.CreatedAt = time.Now()
	}
	data, err := json.Marshal(membership)
	if err != nil {
		return err
	}
	key := membershipsKey(membership.TenantId)
	if err := r.client.HSet(ctx, key, membership.UserId, data).Err(); err != nil {
		return err
	}
	return r.client.SAdd(ctx, membershipsByUserPrefix+membership.UserId, membership.TenantId).Err()
}

func (r *membershipRepo) Get(ctx context.Context, tenantID string, userID string) (*domain.Membership, error) {
	val, err := r.client.HGet(ctx, membershipsKey(tenantID), userID).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if val == "" {
		return nil, nil
	}
	var m domain.Membership
	if e := json.Unmarshal([]byte(val), &m); e != nil {
		return nil, e
	}
	return &m, nil
}

func (r *membershipRepo) ListTenantIDsByUser(ctx context.Context, userID string) ([]string, error) {
	vals, err := r.client.SMembers(ctx, membershipsByUserPrefix+userID).Result()
	if err == redis.Nil {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	return vals, nil
}

func (r *membershipRepo) Delete(ctx context.Context, tenantID string, userID string) error {
	_ = r.client.HDel(ctx, membershipsKey(tenantID), userID).Err()
	_ = r.client.SRem(ctx, membershipsByUserPrefix+userID, tenantID).Err()
	return nil
}

func membershipsKey(tenantID string) string {
	return "memberships:" + tenantID
}
