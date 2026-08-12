package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	exactMembershipListTenantMax = 10_000
	exactMembershipListPageMax   = 200
	membershipSnapshotDomain     = "tikti-membership-fields-v1\x00"
)

var (
	// ErrExactMembershipListStaleCursor lets a future HTTP adapter map a changed
	// field set to 409 without exposing storage details.
	ErrExactMembershipListStaleCursor = errors.New("exact membership list cursor stale")
	membershipSnapshotScript          = redis.NewScript(`
local count = redis.call("HLEN", KEYS[1])
if count > tonumber(ARGV[1]) then
  return redis.error_reply("membership snapshot exceeds limit")
end
return redis.call("HKEYS", KEYS[1])`)
)

// ExactMembershipListReader enumerates one active tenant without changing the
// legacy HSCAN repository or resolving role definitions and permissions.
type ExactMembershipListReader interface {
	ListExact(ctx context.Context, tenantID, pageToken string, pageSize int) (*domain.MembershipIdentitiesPage, error)
}

type exactMembershipListReader struct {
	client  *redis.Client
	tenants ExactTenantRepository
	users   ExactUserBatchRepository
	tokens  *exactMembershipPageTokenCodec
}

func NewExactMembershipListReader(client *redis.Client, tenants ExactTenantRepository, users ExactUserBatchRepository, tokenKey []byte) (ExactMembershipListReader, error) {
	if client == nil || tenants == nil || users == nil {
		return nil, domain.ErrInvalidArgument
	}
	tokens, err := newExactMembershipPageTokenCodec(tokenKey)
	if err != nil {
		return nil, err
	}
	return &exactMembershipListReader{client: client, tenants: tenants, users: users, tokens: tokens}, nil
}

func (r *exactMembershipListReader) ListExact(ctx context.Context, tenantID, encodedToken string, pageSize int) (*domain.MembershipIdentitiesPage, error) {
	if !canonicalTenantIdentity(tenantID) {
		return nil, domain.ErrInvalidTenant
	}
	if pageSize < 1 || pageSize > exactMembershipListPageMax {
		return nil, domain.ErrInvalidArgument
	}
	if r == nil || r.client == nil || r.tenants == nil || r.users == nil || r.tokens == nil {
		return nil, errStoredMembershipReadContract
	}
	token, err := r.tokens.decode(encodedToken, tenantID, pageSize)
	if err != nil {
		return nil, err
	}
	tenant, err := r.tenants.GetExact(ctx, tenantID)
	if err != nil || tenant == nil || tenant.Id != tenantID || tenant.Status != domain.TenantStatusActive {
		return nil, errStoredMembershipReadContract
	}
	fields, digest, err := r.snapshot(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	start := 0
	if token != nil {
		if token.Digest != digest {
			return nil, ErrExactMembershipListStaleCursor
		}
		start = sort.SearchStrings(fields, token.After)
		if start >= len(fields) || fields[start] != token.After {
			return nil, domain.ErrInvalidArgument
		}
		start++
		if start == len(fields) {
			return nil, domain.ErrInvalidArgument
		}
	}
	end := start + pageSize
	if end > len(fields) {
		end = len(fields)
	}
	ids := fields[start:end]
	items, err := r.readPage(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	next := ""
	if end < len(fields) {
		next, err = r.tokens.encode(exactMembershipPageToken{
			Version: exactMembershipPageTokenVersion, Tenant: tenantID, Digest: digest,
			After: ids[len(ids)-1], PageSize: pageSize,
		})
		if err != nil {
			return nil, errStoredMembershipReadContract
		}
	}
	return &domain.MembershipIdentitiesPage{Memberships: items, NextPageToken: next}, nil
}

func (r *exactMembershipListReader) snapshot(ctx context.Context, tenantID string) ([]string, string, error) {
	fields, err := membershipSnapshotScript.Eval(ctx, r.client, []string{membershipsKey(tenantID)}, exactMembershipListTenantMax).StringSlice()
	if err != nil || len(fields) > exactMembershipListTenantMax {
		return nil, "", errStoredMembershipReadContract
	}
	for _, userID := range fields {
		if !canonicalUserIdentity(userID) {
			return nil, "", errStoredMembershipReadContract
		}
	}
	sort.Strings(fields)
	hash := sha256.New()
	_, _ = hash.Write([]byte(membershipSnapshotDomain))
	for _, userID := range fields {
		_, _ = hash.Write([]byte(userID))
		_, _ = hash.Write([]byte{0})
	}
	return fields, hex.EncodeToString(hash.Sum(nil)), nil
}

func (r *exactMembershipListReader) readPage(ctx context.Context, tenantID string, userIDs []string) ([]domain.MembershipIdentity, error) {
	items := make([]domain.MembershipIdentity, len(userIDs))
	if len(userIDs) == 0 {
		return items, nil
	}
	values, err := r.client.HMGet(ctx, membershipsKey(tenantID), userIDs...).Result()
	if err != nil || len(values) != len(userIDs) {
		return nil, errStoredMembershipReadContract
	}
	memberships := make([]domain.Membership, len(values))
	for index, raw := range values {
		value, ok := raw.(string)
		membership, valid := decodeExactMembership(value)
		if !ok || !valid || membership.TenantId != tenantID || membership.UserId != userIDs[index] ||
			!canonicalUserIdentity(membership.Id) || membership.CreatedAt.IsZero() {
			return nil, errStoredMembershipReadContract
		}
		membership.Roles, valid = canonicalMembershipAssignments(membership.Roles)
		if !valid {
			return nil, errStoredMembershipReadContract
		}
		memberships[index] = membership
	}
	pipeline := r.client.Pipeline()
	reverse := make([]*redis.BoolCmd, len(userIDs))
	for index, userID := range userIDs {
		reverse[index] = pipeline.SIsMember(ctx, membershipsByUserPrefix+userID, tenantID)
	}
	_, err = pipeline.Exec(ctx)
	_ = pipeline.Close()
	if err != nil {
		return nil, errStoredMembershipReadContract
	}
	for index := range memberships {
		if !reverse[index].Val() {
			return nil, errStoredMembershipReadContract
		}
	}
	users, err := r.users.GetManyExact(ctx, userIDs)
	if err != nil || len(users) != len(userIDs) {
		return nil, errStoredMembershipReadContract
	}
	for index, membership := range memberships {
		if users[index].Id != userIDs[index] {
			return nil, errStoredMembershipReadContract
		}
		items[index] = domain.MembershipIdentity{
			Id: membership.Id, TenantId: tenantID, UserId: membership.UserId,
			Roles: membership.Roles, CreatedAt: membership.CreatedAt, User: users[index],
		}
	}
	return items, nil
}

// Values are read-committed per page; only the membership field-set is bound
// to the cursor. Reverse-only orphans are not enumerable from this schema and
// require the rollout census/reconciler before global enablement.
