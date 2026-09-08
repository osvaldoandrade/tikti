package repository

import (
	"context"
	"errors"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

var errWorkloadAccountDeletionContract = errors.New("workload account deletion contract mismatch")

const workloadAccountDeletionScript = `
local indexedUserID = redis.call("GET", KEYS[2])
local userV2 = redis.call("HGET", KEYS[1], ARGV[1])
local legacyUser = redis.call("HGET", KEYS[3], ARGV[2])
if not indexedUserID and not userV2 and not legacyUser then
  return "missing"
end
if not indexedUserID or indexedUserID ~= ARGV[1] or not userV2 then
  return "corrupt"
end

local membershipV2 = redis.call("HGET", KEYS[4], ARGV[1])
local membershipV2Reverse = redis.call("SISMEMBER", KEYS[5], ARGV[3])
local legacyMembership = redis.call("HGET", KEYS[6], ARGV[1])
local legacyMembershipReverse = redis.call("SISMEMBER", KEYS[7], ARGV[3])
if not membershipV2 or membershipV2Reverse ~= 1 or not legacyMembership or
   legacyMembershipReverse ~= 1 or legacyMembership ~= membershipV2 then
  return "corrupt"
end

redis.call("HDEL", KEYS[4], ARGV[1])
redis.call("SREM", KEYS[5], ARGV[3])
redis.call("HDEL", KEYS[6], ARGV[1])
redis.call("SREM", KEYS[7], ARGV[3])
redis.call("HDEL", KEYS[1], ARGV[1])
redis.call("DEL", KEYS[2])
redis.call("HDEL", KEYS[3], ARGV[2])
return "deleted"
`

// WorkloadAccountDeletionRepository atomically removes the password identity
// and its exact tenant membership. It is deliberately narrower than the
// general user repository so only the workload-account boundary can use it.
type WorkloadAccountDeletionRepository interface {
	Delete(ctx context.Context, tenantID, userID, email string) error
}

type workloadAccountDeletionRepo struct {
	client *redis.Client
}

func NewWorkloadAccountDeletionRepo(client *redis.Client) WorkloadAccountDeletionRepository {
	return &workloadAccountDeletionRepo{client: client}
}

func (r *workloadAccountDeletionRepo) Delete(ctx context.Context, tenantID, userID, email string) error {
	if !activeTenantIdentity(tenantID) || !canonicalMembershipV2UserID(userID) || email == "" {
		return domain.ErrInvalidArgument
	}
	if r == nil || r.client == nil {
		return errWorkloadAccountDeletionContract
	}
	status, err := r.client.Eval(ctx, workloadAccountDeletionScript, []string{
		usersHashV2,
		userByEmailKeyNS + email,
		legacyUsersHash,
		membershipV2Key(tenantID),
		membershipV2ByUserKey(userID),
		membershipsKey(tenantID),
		membershipsByUserPrefix + userID,
	}, userID, email, tenantID).Text()
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if err != nil {
		return errWorkloadAccountDeletionContract
	}
	switch status {
	case "deleted":
		return nil
	case "missing":
		return domain.ErrNotFound
	default:
		return errWorkloadAccountDeletionContract
	}
}
