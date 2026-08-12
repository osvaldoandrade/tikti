package repository

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type MembershipRepository interface {
	Create(ctx context.Context, membership *domain.Membership) error
	Get(ctx context.Context, tenantID string, userID string) (*domain.Membership, error)
	ListByTenant(ctx context.Context, tenantID string, cursor uint64, count int64) ([]*domain.Membership, uint64, error)
	ListTenantIDsByUser(ctx context.Context, userID string) ([]string, error)
	Delete(ctx context.Context, tenantID string, userID string) error
}

// ExactMembershipRepository exposes fail-closed reads for token authorization
// without changing the legacy membership read contract.
type ExactMembershipRepository interface {
	GetExact(ctx context.Context, tenantID string, userID string) (*domain.Membership, error)
	ListTenantIDsByUserExact(ctx context.Context, userID string) ([]string, error)
}

type membershipRepo struct {
	client *redis.Client
}

const membershipsByUserPrefix = "membershipsByUser:"

var errStoredMembershipContract = errors.New("stored membership contract mismatch")

const membershipLegacyCreateV2GuardScript = `
local v2 = redis.call("HGET", KEYS[1], ARGV[1])
local v2Reverse = redis.call("SISMEMBER", KEYS[2], ARGV[2])
redis.call("HGET", KEYS[3], ARGV[1])
redis.call("SISMEMBER", KEYS[4], ARGV[2])
if v2 or v2Reverse == 1 then return "locked" end
redis.call("HSET", KEYS[3], ARGV[1], ARGV[3])
redis.call("SADD", KEYS[4], ARGV[2])
return "created"
`

const membershipLegacyDeleteV2GuardScript = `
local v2 = redis.call("HGET", KEYS[1], ARGV[1])
local v2Reverse = redis.call("SISMEMBER", KEYS[2], ARGV[2])
redis.call("HGET", KEYS[3], ARGV[1])
redis.call("SISMEMBER", KEYS[4], ARGV[2])
if v2 or v2Reverse == 1 then return "locked" end
redis.call("HDEL", KEYS[3], ARGV[1])
redis.call("SREM", KEYS[4], ARGV[2])
return "deleted"
`

// NewMembershipRepo keeps legacy-only records writable but permanently guards
// every legacy mutation once either v2 marker exists for the tenant/user pair.
// Route flags never disable this storage invariant.
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
	status, evalErr := r.client.Eval(ctx, membershipLegacyCreateV2GuardScript, []string{
		membershipV2Key(membership.TenantId), membershipV2ByUserKey(membership.UserId),
		membershipsKey(membership.TenantId), membershipsByUserPrefix + membership.UserId,
	}, membership.UserId, membership.TenantId, string(data)).Text()
	if evalErr != nil {
		return evalErr
	}
	if status == "locked" {
		return domain.ErrMembershipConflict
	}
	if status != "created" {
		return errStoredMembershipContract
	}
	return nil
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

func (r *membershipRepo) GetExact(ctx context.Context, tenantID string, userID string) (*domain.Membership, error) {
	value, err := r.client.HGet(ctx, membershipsKey(tenantID), userID).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if value == "" {
		return nil, errStoredMembershipContract
	}
	var membership domain.Membership
	if json.Unmarshal([]byte(value), &membership) != nil || membership.TenantId != tenantID || membership.UserId != userID {
		return nil, errStoredMembershipContract
	}
	return &membership, nil
}

func (r *membershipRepo) ListByTenant(ctx context.Context, tenantID string, cursor uint64, count int64) ([]*domain.Membership, uint64, error) {
	values, nextCursor, err := r.client.HScan(ctx, membershipsKey(tenantID), cursor, "", count).Result()
	if err == redis.Nil {
		return []*domain.Membership{}, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	memberships := make([]*domain.Membership, 0, len(values)/2)
	for index := 1; index < len(values); index += 2 {
		var membership domain.Membership
		if err := json.Unmarshal([]byte(values[index]), &membership); err != nil {
			return nil, 0, err
		}
		memberships = append(memberships, &membership)
	}
	return memberships, nextCursor, nil
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

func (r *membershipRepo) ListTenantIDsByUserExact(ctx context.Context, userID string) ([]string, error) {
	if userID == "" || strings.TrimSpace(userID) != userID {
		return nil, errStoredMembershipContract
	}
	values, err := r.client.SMembers(ctx, membershipsByUserPrefix+userID).Result()
	if err == redis.Nil {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	for _, tenantID := range values {
		if !canonicalMembershipTenantID(tenantID) {
			return nil, errStoredMembershipContract
		}
	}
	sort.Strings(values)
	return values, nil
}

func (r *membershipRepo) Delete(ctx context.Context, tenantID string, userID string) error {
	status, err := r.client.Eval(ctx, membershipLegacyDeleteV2GuardScript, []string{
		membershipV2Key(tenantID), membershipV2ByUserKey(userID), membershipsKey(tenantID), membershipsByUserPrefix + userID,
	}, userID, tenantID).Text()
	if err != nil {
		return err
	}
	if status == "locked" {
		return domain.ErrMembershipConflict
	}
	if status != "deleted" {
		return errStoredMembershipContract
	}
	return nil
}

func membershipsKey(tenantID string) string {
	return "memberships:" + tenantID
}

func canonicalMembershipTenantID(value string) bool {
	if len(value) < 1 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range []byte(value) {
		if strings.IndexByte("abcdefghijklmnopqrstuvwxyz0123456789-", character) < 0 {
			return false
		}
	}
	return true
}
