package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// ExactMembershipReader composes one fail-closed membership without exposing
// the stored user document or changing any legacy repository behavior.
type ExactMembershipReader interface {
	GetExact(ctx context.Context, tenantID, userID string) (*domain.MembershipIdentity, error)
}

type exactMembershipReader struct {
	client  *redis.Client
	tenants ExactTenantRepository
	users   ExactUserRepository
}

var (
	errStoredMembershipReadContract = errors.New("stored membership read contract mismatch")
	exactMembershipFields           = fields("id", "tenantId", "userId", "roles", "createdAt")
)

func NewExactMembershipReader(client *redis.Client, tenants ExactTenantRepository, users ExactUserRepository) ExactMembershipReader {
	return &exactMembershipReader{client: client, tenants: tenants, users: users}
}

func (r *exactMembershipReader) GetExact(ctx context.Context, tenantID, userID string) (*domain.MembershipIdentity, error) {
	if !canonicalTenantIdentity(tenantID) {
		return nil, domain.ErrInvalidTenant
	}
	if userID == "." || userID == ".." || !canonicalUserIdentity(userID) {
		return nil, domain.ErrInvalidArgument
	}
	if r == nil || r.client == nil || r.tenants == nil || r.users == nil {
		return nil, errStoredMembershipReadContract
	}
	value, err := r.client.HGet(ctx, membershipsKey(tenantID), userID).Result()
	forward := err != redis.Nil
	if err != nil && err != redis.Nil {
		return nil, errStoredMembershipReadContract
	}
	reverse, err := r.client.SIsMember(ctx, membershipsByUserPrefix+userID, tenantID).Result()
	if err != nil {
		return nil, errStoredMembershipReadContract
	}
	if !forward && !reverse {
		return nil, nil
	}
	if forward != reverse {
		return nil, errStoredMembershipReadContract
	}
	membership, ok := decodeExactMembership(value)
	if !ok || membership.TenantId != tenantID || membership.UserId != userID ||
		!canonicalUserIdentity(membership.Id) || membership.CreatedAt.IsZero() {
		return nil, errStoredMembershipReadContract
	}
	roles, ok := canonicalMembershipAssignments(membership.Roles)
	if !ok {
		return nil, errStoredMembershipReadContract
	}
	tenant, err := r.tenants.GetExact(ctx, tenantID)
	if err != nil || tenant == nil || tenant.Id != tenantID {
		return nil, errStoredMembershipReadContract
	}
	user, err := r.users.GetExact(ctx, userID)
	if err != nil || user == nil || user.Id != userID {
		return nil, errStoredMembershipReadContract
	}
	return &domain.MembershipIdentity{
		Id:        membership.Id,
		TenantId:  membership.TenantId,
		UserId:    membership.UserId,
		User:      *user,
		Roles:     roles,
		CreatedAt: membership.CreatedAt,
	}, nil
}

// Assignments are names only. Authorization callers must resolve every name
// through ExactRoleRepository and fail closed on a missing or corrupt role.
func canonicalMembershipAssignments(values []string) ([]string, bool) {
	if len(values) > 500 {
		return nil, false
	}
	out := append([]string{}, values...)
	sort.Strings(out)
	for index, value := range out {
		if !canonicalMembershipRoleName(value) || index > 0 && out[index-1] == value {
			return nil, false
		}
	}
	return out, true
}

func canonicalMembershipRoleName(value string) bool {
	if len(value) < 1 || len(value) > 128 || !roleNameEdge(value[0]) || !roleNameEdge(value[len(value)-1]) {
		return false
	}
	for _, character := range []byte(value) {
		if !roleNameEdge(character) && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func roleNameEdge(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func decodeExactMembership(value string) (domain.Membership, bool) {
	var membership domain.Membership
	if value == "" || !validJSONUnicode(value) {
		return membership, false
	}
	decoder := json.NewDecoder(bytes.NewBufferString(value))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return membership, false
	}
	seen := make(map[string]struct{}, len(exactMembershipFields))
	for decoder.More() {
		field, err := decoder.Token()
		name, ok := field.(string)
		if err != nil || !ok {
			return membership, false
		}
		if _, ok = exactMembershipFields[name]; !ok {
			return membership, false
		}
		if _, duplicate := seen[name]; duplicate {
			return membership, false
		}
		seen[name] = struct{}{}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil || name != "roles" && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return membership, false
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(seen) != len(exactMembershipFields) {
		return membership, false
	}
	if _, err = decoder.Token(); err != io.EOF || json.Unmarshal([]byte(value), &membership) != nil {
		return membership, false
	}
	if membership.Roles == nil {
		membership.Roles = []string{}
	}
	return membership, true
}
