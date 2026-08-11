package repository

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	membershipV2ForwardPrefix = "memberships:v2:"
	membershipV2ReversePrefix = "membershipsByUser:v2:"
	membershipV2IDDomain      = "tikti-membership-v2-id-v1\x00"
	membershipV2IDPrefix      = "m2_"
	membershipV2RoleMax       = 100
	membershipV2PayloadMax    = 16 << 10
)

var errStoredMembershipV2Contract = errors.New("stored membership v2 contract mismatch")

const membershipV2EnsureScript = `
local value = redis.call("HGET", KEYS[1], ARGV[1])
local reverse = redis.call("SISMEMBER", KEYS[2], ARGV[2])
local legacy = redis.call("HGET", KEYS[3], ARGV[1])
local legacyReverse = redis.call("SISMEMBER", KEYS[4], ARGV[2])
if value then
  if reverse ~= 1 or not legacy or legacyReverse ~= 1 or legacy ~= value then
    return {"corrupt", value}
  end
  return {"existing", value}
end
if reverse ~= 0 then return {"corrupt", ""} end
if legacy or legacyReverse == 1 then return {"shadow", ""} end
redis.call("HSET", KEYS[1], ARGV[1], ARGV[3])
redis.call("SADD", KEYS[2], ARGV[2])
redis.call("HSET", KEYS[3], ARGV[1], ARGV[3])
redis.call("SADD", KEYS[4], ARGV[2])
return {"created", ARGV[3]}
`

const membershipV2ReadScript = `
local value = redis.call("HGET", KEYS[1], ARGV[1])
local reverse = redis.call("SISMEMBER", KEYS[2], ARGV[2])
if not value then
  if reverse == 0 then return {"missing", ""} end
  return {"corrupt", ""}
end
if reverse ~= 1 then return {"corrupt", value} end
return {"found", value}
`

// MembershipV2Repository owns immutable membership v2 records. Its atomic
// scripts span tenant and user keys and therefore require one Redis/Kvrocks
// node; Redis Cluster cross-slot operation is deliberately not claimed.
type MembershipV2Repository interface {
	Ensure(ctx context.Context, tenantID, userID string, roles []string) (*domain.Membership, bool, error)
	GetExact(ctx context.Context, tenantID, userID string) (*domain.Membership, error)
}

type membershipV2Repo struct {
	client *redis.Client
}

func NewMembershipV2Repo(client *redis.Client) MembershipV2Repository {
	return &membershipV2Repo{client: client}
}

func (r *membershipV2Repo) Ensure(ctx context.Context, tenantID, userID string, roles []string) (*domain.Membership, bool, error) {
	if !canonicalTenantIdentity(tenantID) {
		return nil, false, domain.ErrInvalidTenant
	}
	if !canonicalMembershipV2UserID(userID) || !validMembershipV2Roles(roles) {
		return nil, false, domain.ErrInvalidArgument
	}
	if r == nil || r.client == nil {
		return nil, false, errStoredMembershipV2Contract
	}
	candidate := domain.Membership{
		Id: membershipV2ID(tenantID, userID), TenantId: tenantID, UserId: userID,
		Roles: append([]string(nil), roles...), CreatedAt: time.Now().UTC(),
	}
	payload, err := json.Marshal(candidate)
	if err != nil || len(payload) > membershipV2PayloadMax {
		return nil, false, domain.ErrInvalidArgument
	}
	status, value, err := r.eval(ctx, membershipV2EnsureScript, []string{
		membershipV2Key(tenantID), membershipV2ByUserKey(userID), membershipsKey(tenantID), membershipsByUserPrefix + userID,
	}, userID, tenantID, string(payload))
	if err != nil {
		return nil, false, err
	}
	switch status {
	case "shadow":
		return nil, false, domain.ErrMembershipConflict
	case "corrupt":
		return nil, false, errStoredMembershipV2Contract
	case "created", "existing":
		stored, ok := decodeMembershipV2(tenantID, userID, value)
		if !ok {
			return nil, false, errStoredMembershipV2Contract
		}
		if !slices.Equal(stored.Roles, roles) {
			if status == "existing" {
				return nil, false, domain.ErrMembershipConflict
			}
			return nil, false, errStoredMembershipV2Contract
		}
		return stored, status == "created", nil
	default:
		return nil, false, errStoredMembershipV2Contract
	}
}

func (r *membershipV2Repo) GetExact(ctx context.Context, tenantID, userID string) (*domain.Membership, error) {
	if !canonicalTenantIdentity(tenantID) {
		return nil, domain.ErrInvalidTenant
	}
	if !canonicalMembershipV2UserID(userID) {
		return nil, domain.ErrInvalidArgument
	}
	if r == nil || r.client == nil {
		return nil, errStoredMembershipV2Contract
	}
	status, value, err := r.eval(ctx, membershipV2ReadScript, []string{
		membershipV2Key(tenantID), membershipV2ByUserKey(userID),
	}, userID, tenantID)
	if err != nil {
		return nil, err
	}
	switch status {
	case "missing":
		return nil, nil
	case "found":
		membership, ok := decodeMembershipV2(tenantID, userID, value)
		if !ok {
			return nil, errStoredMembershipV2Contract
		}
		return membership, nil
	default:
		return nil, errStoredMembershipV2Contract
	}
}

func (r *membershipV2Repo) eval(ctx context.Context, script string, keys []string, args ...interface{}) (string, string, error) {
	values, err := r.client.Eval(ctx, script, keys, args...).StringSlice()
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "", "", err
	}
	if err != nil || len(values) != 2 {
		return "", "", errStoredMembershipV2Contract
	}
	return values[0], values[1], nil
}

func decodeMembershipV2(tenantID, userID, value string) (*domain.Membership, bool) {
	var membership domain.Membership
	if len(value) < 1 || len(value) > membershipV2PayloadMax ||
		!decodeExactObject(value, exactMembershipFields, &membership) ||
		membership.Id != membershipV2ID(tenantID, userID) || membership.TenantId != tenantID || membership.UserId != userID ||
		!canonicalTenantIdentity(membership.TenantId) || !canonicalMembershipV2UserID(membership.UserId) ||
		!validMembershipV2Roles(membership.Roles) || membership.CreatedAt.IsZero() {
		return nil, false
	}
	return &membership, true
}

func validMembershipV2Roles(values []string) bool {
	if len(values) < 1 || len(values) > membershipV2RoleMax {
		return false
	}
	for index, value := range values {
		if !canonicalMembershipRoleName(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func canonicalMembershipV2UserID(value string) bool {
	return value != "." && value != ".." && canonicalUserIdentity(value)
}

// membershipV2ID is a versioned, bounded identifier derived only from the
// immutable tenant/user pair. Raw URL encoding keeps it in the ID grammar.
func membershipV2ID(tenantID, userID string) string {
	digest := sha256.Sum256([]byte(membershipV2IDDomain + tenantID + "\x00" + userID))
	return membershipV2IDPrefix + base64.RawURLEncoding.EncodeToString(digest[:])
}

func membershipV2Key(tenantID string) string {
	return membershipV2ForwardPrefix + tenantID
}

func membershipV2ByUserKey(userID string) string {
	return membershipV2ReversePrefix + userID
}
