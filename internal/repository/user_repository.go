package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// UserRepository defines persistence operations for users and OOB codes.
type UserRepository interface {
	CreateUser(ctx context.Context, user *domain.User) error
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
	UpdateUser(ctx context.Context, user *domain.User) error
	DeleteByEmail(ctx context.Context, email string) error
	SetStatus(ctx context.Context, email string, status domain.UserStatus) (*domain.User, error)
	IncrementTokenVersion(ctx context.Context, email string) (int, *domain.User, error)
	SaveOobCode(ctx context.Context, code, email, reqType string) error
	ConsumeOobCode(ctx context.Context, code string, expectedReqType string) (string, error)
	UpsertFromSAML(ctx context.Context, tid, externalSubject, email, name string, roles []string, mergeStrategy domain.MergeStrategy) (domain.User, bool, error)
}

// UserIDRepository is the subject-based authority used by signed sessions.
// It also covers tenant-local federated principals that intentionally do not
// participate in the global email directory.
type UserIDRepository interface {
	FindByID(context.Context, string) (*domain.User, error)
	IncrementTokenVersionByID(context.Context, string) (int, *domain.User, error)
}

// redisRepo is a Redis-backed implementation of UserRepository.
type redisRepo struct {
	client *redis.Client
}

const (
	usersHashV2        = "users_v2"
	legacyUsersHash    = "users"
	userByEmailKeyNS   = "userByEmail:"
	legacyOobHash      = "oobs"
	oobKeyPrefix       = "oob:"
	samlSubjectKeyNS   = "samlSubject:"
	federatedUsersHash = "saml_users_v2"
)

var createFederatedUserScript = redis.NewScript(`
local existing = redis.call("GET", KEYS[1])
if existing and existing ~= false then return existing end
if redis.call("HEXISTS", KEYS[2], ARGV[1]) == 1 then return "collision" end
redis.call("HSET", KEYS[2], ARGV[1], ARGV[2])
redis.call("SET", KEYS[1], ARGV[1])
return ARGV[1]
`)

// NewRedisRepo instantiates a repository using the provided Redis client.
func NewRedisRepo(rdb *redis.Client) UserRepository {
	return &redisRepo{client: rdb}
}

var consumeOobCodeScript = redis.NewScript(`
local reqType = redis.call("HGET", KEYS[1], "reqType")
if not reqType or reqType == false then
  return ""
end
if reqType ~= ARGV[1] then
  return ""
end
local exp = redis.call("HGET", KEYS[1], "expiresAt")
if exp and exp ~= false then
  local now = tonumber(ARGV[2])
  local expNum = tonumber(exp)
  if now and expNum and expNum < now then
    redis.call("DEL", KEYS[1])
    return ""
  end
end
local email = redis.call("HGET", KEYS[1], "email")
if not email or email == false then
  redis.call("DEL", KEYS[1])
  return ""
end
redis.call("DEL", KEYS[1])
return email
`)

// CreateUser serializes and stores a user document under the users hash.
func (r *redisRepo) CreateUser(ctx context.Context, user *domain.User) error {
	_, err := NewIdentityDirectoryRepository(r.client).CreateDirectoryUser(ctx, user)
	return err
}

// FindByEmail retrieves a stored user by email, returning nil when absent.
func (r *redisRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	email = normalizeDirectoryEmail(email)
	if email == "" {
		return nil, nil
	}
	if userID, err := r.client.Get(ctx, userByEmailKeyNS+email).Result(); err == nil && userID != "" {
		val, err := r.client.HGet(ctx, usersHashV2, userID).Result()
		if err == redis.Nil {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if val == "" {
			return nil, nil
		}
		var u domain.User
		if e := json.Unmarshal([]byte(val), &u); e != nil {
			return nil, e
		}
		if u.Password == "" && u.AuthSource != domain.AuthSourceSAML {
			return nil, domain.ErrNotFound
		}
		return &u, nil
	}

	val, err := r.client.HGet(ctx, legacyUsersHash, email).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if val == "" {
		return nil, nil
	}
	var u domain.User
	if e := json.Unmarshal([]byte(val), &u); e != nil {
		return nil, e
	}
	if u.Password == "" && u.AuthSource != domain.AuthSourceSAML {
		return nil, domain.ErrNotFound
	}
	// Best-effort migration to v2 layout.
	if u.Id != "" {
		// #nosec G117 -- persisted User.Password contains only a one-way password hash.
		if data, err := json.Marshal(&u); err == nil {
			_ = r.client.HSet(ctx, usersHashV2, u.Id, data).Err()
			_ = r.client.Set(ctx, userByEmailKeyNS+email, u.Id, 0).Err()
		}
	}
	return &u, nil
}

func (r *redisRepo) FindByID(ctx context.Context, userID string) (*domain.User, error) {
	if !canonicalUserIdentity(userID) {
		return nil, domain.ErrInvalidArgument
	}
	for _, key := range []string{usersHashV2, federatedUsersHash} {
		raw, err := r.client.HGet(ctx, key, userID).Result()
		if err == redis.Nil || raw == "" {
			continue
		}
		if err != nil {
			return nil, err
		}
		var user domain.User
		if json.Unmarshal([]byte(raw), &user) != nil || user.Id != userID {
			return nil, domain.ErrDirectoryInvariant
		}
		return &user, nil
	}
	return nil, nil
}

// UpdateUser overwrites the stored user JSON for the provided user.
func (r *redisRepo) UpdateUser(ctx context.Context, user *domain.User) error {
	if user != nil {
		federated, err := r.client.HExists(ctx, federatedUsersHash, user.Id).Result()
		if err != nil {
			return err
		}
		if federated {
			return r.updateFederatedUser(ctx, user)
		}
	}
	_, err := NewIdentityDirectoryRepository(r.client).UpdateDirectoryUser(ctx, user)
	return err
}

func (r *redisRepo) updateFederatedUser(ctx context.Context, user *domain.User) error {
	canonical, err := canonicalFederatedUser(user)
	if err != nil {
		return err
	}
	nextRevision := canonical.Revision + 1
	err = r.client.Watch(ctx, func(tx *redis.Tx) error {
		raw, readErr := tx.HGet(ctx, federatedUsersHash, canonical.Id).Result()
		if readErr == redis.Nil || raw == "" {
			return domain.ErrNotFound
		}
		if readErr != nil {
			return readErr
		}
		var stored domain.User
		if json.Unmarshal([]byte(raw), &stored) != nil {
			return domain.ErrDirectoryInvariant
		}
		current, canonicalErr := canonicalFederatedUser(&stored)
		if canonicalErr != nil || current.Id != canonical.Id || current.Revision != canonical.Revision {
			if canonicalErr == nil && current.Id == canonical.Id {
				return domain.ErrVersionConflict
			}
			return domain.ErrDirectoryInvariant
		}
		if current.CompanyId == nil || canonical.CompanyId == nil || *current.CompanyId != *canonical.CompanyId ||
			current.ExternalSubject != canonical.ExternalSubject ||
			canonical.TokenVersion < current.TokenVersion {
			return domain.ErrDirectoryInvariant
		}
		canonical.Revision = nextRevision
		// #nosec G117 -- persisted User.Password contains only a one-way password hash.
		payload, marshalErr := json.Marshal(canonical)
		if marshalErr != nil {
			return domain.ErrInvalidArgument
		}
		_, writeErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.HSet(ctx, federatedUsersHash, canonical.Id, payload)
			return nil
		})
		return writeErr
	}, federatedUsersHash)
	if err == redis.TxFailedErr {
		return domain.ErrVersionConflict
	}
	if err == nil {
		user.Revision = nextRevision
	}
	return err
}

// DeleteByEmail removes a user entry from Redis by email.
func (r *redisRepo) DeleteByEmail(ctx context.Context, email string) error {
	email = normalizeDirectoryEmail(email)
	if email == "" {
		return nil
	}
	for attempt := 0; attempt < directoryMaximumRetries; attempt++ {
		userID, err := r.client.Get(ctx, userByEmailKeyNS+email).Result()
		if err == redis.Nil {
			return r.client.HDel(ctx, legacyUsersHash, email).Err()
		}
		if err != nil {
			return err
		}
		if !canonicalUserIdentity(userID) {
			return domain.ErrDirectoryInvariant
		}
		groups, err := r.client.SMembers(ctx, userGroupsKey(userID)).Result()
		if err != nil || len(groups) > directoryMaximumRelationships {
			return domain.ErrDirectoryInvariant
		}
		tenants, err := r.client.SMembers(ctx, principalTenantsKey(domain.AccessPrincipalUser, userID)).Result()
		if err != nil || len(tenants) > directoryMaximumRelationships {
			return domain.ErrDirectoryInvariant
		}
		watchKeys := []string{
			usersHashV2,
			userByEmailKeyNS + email,
			directoryUserEmailIndex,
			userGroupsKey(userID),
			principalTenantsKey(domain.AccessPrincipalUser, userID),
			directoryGroupsHash,
		}
		for _, groupID := range groups {
			watchKeys = append(watchKeys, groupMembersKey(groupID))
		}
		for _, tenantID := range tenants {
			watchKeys = append(watchKeys, assignmentsKey(tenantID))
		}
		err = r.client.Watch(ctx, func(tx *redis.Tx) error {
			currentID, readErr := tx.Get(ctx, userByEmailKeyNS+email).Result()
			if readErr == redis.Nil {
				return nil
			}
			if readErr != nil {
				return readErr
			}
			if currentID != userID {
				return redis.TxFailedErr
			}
			raw, readErr := tx.HGet(ctx, usersHashV2, userID).Result()
			if readErr != nil {
				return domain.ErrDirectoryInvariant
			}
			var stored domain.User
			if json.Unmarshal([]byte(raw), &stored) != nil {
				return domain.ErrDirectoryInvariant
			}
			current, canonicalErr := canonicalDirectoryStorageUser(&stored)
			if canonicalErr != nil || current.Id != userID || current.Email != email {
				return domain.ErrDirectoryInvariant
			}
			currentGroups, readErr := tx.SMembers(ctx, userGroupsKey(userID)).Result()
			if readErr != nil || len(currentGroups) > directoryMaximumRelationships {
				return domain.ErrDirectoryInvariant
			}
			currentTenants, readErr := tx.SMembers(ctx, principalTenantsKey(domain.AccessPrincipalUser, userID)).Result()
			if readErr != nil || len(currentTenants) > directoryMaximumRelationships {
				return domain.ErrDirectoryInvariant
			}
			updatedGroups := make(map[string][]byte, len(currentGroups))
			for _, groupID := range currentGroups {
				groupRaw, groupErr := tx.HGet(ctx, directoryGroupsHash, groupID).Result()
				if groupErr != nil {
					return domain.ErrDirectoryInvariant
				}
				group, decodeErr := decodeGroup(groupRaw, groupID)
				if decodeErr != nil {
					return decodeErr
				}
				group.Version++
				group.UpdatedAt = time.Now().UTC()
				payload, marshalErr := json.Marshal(group)
				if marshalErr != nil {
					return domain.ErrDirectoryInvariant
				}
				updatedGroups[groupID] = payload
			}
			_, writeErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HDel(ctx, usersHashV2, userID)
				pipe.Del(ctx, userByEmailKeyNS+email, userGroupsKey(userID), principalTenantsKey(domain.AccessPrincipalUser, userID))
				pipe.ZRem(ctx, directoryUserEmailIndex, directoryUserIndexMember(email, userID))
				pipe.HDel(ctx, legacyUsersHash, email)
				if current.CompanyId != nil && current.ExternalSubject != "" {
					pipe.Del(ctx, samlSubjectKey(*current.CompanyId, current.ExternalSubject))
				}
				for groupID, payload := range updatedGroups {
					pipe.SRem(ctx, groupMembersKey(groupID), userID)
					pipe.HSet(ctx, directoryGroupsHash, groupID, payload)
				}
				for _, tenantID := range currentTenants {
					pipe.HDel(ctx, assignmentsKey(tenantID), assignmentField(domain.AccessPrincipalUser, userID))
				}
				return nil
			})
			return writeErr
		}, watchKeys...)
		if err == nil {
			return nil
		}
		if err != redis.TxFailedErr {
			return err
		}
	}
	return errDirectoryRetry
}

func (r *redisRepo) SetStatus(ctx context.Context, email string, status domain.UserStatus) (*domain.User, error) {
	u, err := r.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, domain.ErrNotFound
	}
	// Every administrative status write is also a monotonic session
	// revocation. Otherwise ACTIVE -> SUSPENDED -> ACTIVE would revive tokens
	// carrying the unchanged version. UpdateUser commits the status/version pair
	// with the current revision as an optimistic CAS.
	if u.TokenVersion < 0 {
		u.TokenVersion = 0
	}
	u.TokenVersion++
	u.Status = status
	if err := r.UpdateUser(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (r *redisRepo) IncrementTokenVersion(ctx context.Context, email string) (int, *domain.User, error) {
	u, err := r.FindByEmail(ctx, email)
	if err != nil {
		return 0, nil, err
	}
	if u == nil {
		return 0, nil, domain.ErrNotFound
	}
	if u.TokenVersion < 0 {
		u.TokenVersion = 0
	}
	u.TokenVersion++
	if err := r.UpdateUser(ctx, u); err != nil {
		return 0, nil, err
	}
	return u.TokenVersion, u, nil
}

func (r *redisRepo) IncrementTokenVersionByID(ctx context.Context, userID string) (int, *domain.User, error) {
	for attempt := 0; attempt < directoryMaximumRetries; attempt++ {
		user, err := r.FindByID(ctx, userID)
		if err != nil {
			return 0, nil, err
		}
		if user == nil {
			return 0, nil, domain.ErrNotFound
		}
		if user.TokenVersion < 0 {
			user.TokenVersion = 0
		}
		user.TokenVersion++
		if err := r.UpdateUser(ctx, user); err != nil {
			if errors.Is(err, domain.ErrVersionConflict) {
				continue
			}
			return 0, nil, err
		}
		return user.TokenVersion, user, nil
	}
	return 0, nil, errDirectoryRetry
}

// SaveOobCode stores a time-bounded payload keyed by the generated OOB code.
func (r *redisRepo) SaveOobCode(ctx context.Context, code, email, reqType string) error {
	code = strings.TrimSpace(code)
	email = strings.TrimSpace(email)
	reqType = strings.TrimSpace(reqType)
	if code == "" || email == "" || reqType == "" {
		return domain.ErrInvalidArgument
	}

	key := oobKey(code)
	expiresAt := time.Now().Add(15 * time.Minute).Unix()

	if err := r.client.HSet(ctx, key, map[string]interface{}{
		"email":     email,
		"reqType":   reqType,
		"expiresAt": expiresAt,
	}).Err(); err != nil {
		return err
	}
	return r.client.Expire(ctx, key, 15*time.Minute).Err()
}

// ConsumeOobCode validates and atomically consumes an OOB code of the expected type, returning its email.
func (r *redisRepo) ConsumeOobCode(ctx context.Context, code string, expectedReqType string) (string, error) {
	code = strings.TrimSpace(code)
	expectedReqType = strings.TrimSpace(expectedReqType)
	if code == "" || expectedReqType == "" {
		return "", domain.ErrInvalidOob
	}

	key := oobKey(code)
	now := strconv.FormatInt(time.Now().Unix(), 10)
	result, err := consumeOobCodeScript.Run(ctx, r.client, []string{key}, expectedReqType, now).Result()
	if err != nil {
		return "", err
	}
	if email := coerceString(result); email != "" {
		return email, nil
	}

	// Fallback for legacy codes stored in the global hash ("oobs") for a short post-deploy window.
	return r.consumeLegacyOobCode(ctx, code, expectedReqType)
}

// samlSubjectKey builds the Redis key used to index users by (tenant, externalSubject).
func samlSubjectKey(tid, externalSubject string) string {
	return samlSubjectKeyNS + tid + ":" + externalSubject
}

// findByExternalSubject looks up a user by the SAML (tenant, externalSubject) pair.
func (r *redisRepo) findByExternalSubject(ctx context.Context, tid, externalSubject string) (*domain.User, error) {
	userID, err := r.client.Get(ctx, samlSubjectKey(tid, externalSubject)).Result()
	if err == redis.Nil || userID == "" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r.FindByID(ctx, userID)
}

// UpsertFromSAML creates or updates a tenant-local principal from a SAML
// assertion. The immutable authority key is (tid, externalSubject); an asserted
// email is presentation data and is never proof that the IdP controls an
// existing password or global-directory principal.
func (r *redisRepo) UpsertFromSAML(ctx context.Context, tid, externalSubject, email, name string, roles []string, mergeStrategy domain.MergeStrategy) (domain.User, bool, error) {
	if tid == "" || externalSubject == "" || email == "" {
		return domain.User{}, false, domain.ErrInvalidArgument
	}

	// Case 1: Existing SAML user by external subject. A concurrent SLO/token
	// revocation wins through the Revision CAS; retrying preserves its newer
	// tokenVersion instead of resurrecting an old session.
	for attempt := 0; attempt < directoryMaximumRetries; attempt++ {
		existing, err := r.findByExternalSubject(ctx, tid, externalSubject)
		if err != nil {
			return domain.User{}, false, err
		}
		if existing == nil {
			break
		}
		existing.Email = email
		currentRole := existing.Role
		existing.Role = r.existingTenantScopedSAMLRole(ctx, tid, existing, roles)
		if existing.Role != currentRole {
			// Role changes from a fresh assertion are authoritative and revoke
			// every bearer minted from the prior role, including home tokens
			// whose claims do not carry the tenant assignment array.
			existing.TokenVersion++
		}
		existing.AuthSource = domain.AuthSourceSAML
		existing.ExternalSubject = externalSubject
		existing.CompanyId = stringPointer(tid)
		if err := r.UpdateUser(ctx, existing); err != nil {
			if errors.Is(err, domain.ErrVersionConflict) {
				continue
			}
			return domain.User{}, false, err
		}
		return *existing, false, nil
	}

	// Case 2: Create a tenant-local federated principal. It deliberately does
	// not enter the global email directory: a tenant-controlled IdP assertion
	// is not proof that it owns a reusable global email identity.
	role := tenantScopedSAMLRole(roles)
	companyID := tid
	u := domain.User{
		Id:              uuid.NewString(),
		Email:           email,
		Role:            role,
		Status:          domain.UserStatusActive,
		CreatedAt:       time.Now(),
		AuthSource:      domain.AuthSourceSAML,
		ExternalSubject: externalSubject,
		CompanyId:       &companyID,
	}
	canonical, err := canonicalFederatedUser(&u)
	if err != nil {
		return domain.User{}, false, err
	}
	// #nosec G117 -- federated users carry no password; this is the canonical storage record.
	raw, err := json.Marshal(canonical)
	if err != nil {
		return domain.User{}, false, domain.ErrInvalidArgument
	}
	storedID, err := createFederatedUserScript.Run(
		ctx, r.client, []string{samlSubjectKey(tid, externalSubject), federatedUsersHash},
		canonical.Id, string(raw),
	).Text()
	if err != nil || storedID == "collision" {
		if err != nil {
			return domain.User{}, false, err
		}
		return domain.User{}, false, domain.ErrDirectoryInvariant
	}
	if storedID != canonical.Id {
		existing, findErr := r.FindByID(ctx, storedID)
		if findErr != nil || existing == nil {
			return domain.User{}, false, domain.ErrDirectoryInvariant
		}
		return *existing, false, nil
	}
	return *canonical, true, nil
}

func canonicalFederatedUser(input *domain.User) (*domain.User, error) {
	if input == nil || !canonicalUserIdentity(input.Id) || input.AuthSource != domain.AuthSourceSAML ||
		!validExternalSubject(input.ExternalSubject) || input.CompanyId == nil || !activeTenantIdentity(*input.CompanyId) ||
		!canonicalEmail(input.Email) || !validUserStatus(input.Status) || input.TokenVersion < 0 {
		return nil, domain.ErrInvalidArgument
	}
	copy := *input
	copy.Password = ""
	copy.PasswordChangeRequired = false
	copy.Email = normalizeDirectoryEmail(copy.Email)
	return &copy, nil
}

func tenantScopedSAMLRole(roles []string) domain.UserRole {
	if len(roles) > 0 {
		switch domain.UserRole(strings.TrimSpace(roles[0])) {
		case domain.RoleAdmin, domain.RoleCompanyAdmin:
			return domain.RoleCompanyAdmin
		}
	}
	return domain.RoleCompanyEmployee
}

func existingTenantScopedSAMLRole(existing domain.UserRole, asserted []string) domain.UserRole {
	if len(asserted) > 0 {
		return tenantScopedSAMLRole(asserted)
	}
	// Absence of the optional roles attribute is not a revocation signal.
	// Preserve only tenant-local administration and collapse legacy platform
	// ADMIN records to COMPANY_ADMIN at the SAML trust boundary.
	switch existing {
	case domain.RoleAdmin, domain.RoleCompanyAdmin:
		return domain.RoleCompanyAdmin
	default:
		return domain.RoleCompanyEmployee
	}
}

func (r *redisRepo) existingTenantScopedSAMLRole(
	ctx context.Context,
	tenantID string,
	user *domain.User,
	asserted []string,
) domain.UserRole {
	if user == nil {
		return domain.RoleCompanyEmployee
	}
	role := existingTenantScopedSAMLRole(user.Role, asserted)
	if len(asserted) > 0 || role == domain.RoleCompanyAdmin || r == nil || r.client == nil {
		return role
	}

	// v0.2.98 could persist COMPANY_EMPLOYEE when an IdP omitted its optional
	// roles attribute. Recover only from an intact, tenant-local membership that
	// explicitly assigned the built-in administration role. The matching reverse
	// index prevents a unilateral forward record from becoming elevation input.
	raw, err := r.client.HGet(ctx, membershipsKey(tenantID), user.Id).Result()
	if err != nil || raw == "" {
		return role
	}
	reverse, err := r.client.SIsMember(ctx, membershipsByUserPrefix+user.Id, tenantID).Result()
	if err != nil || !reverse {
		return role
	}
	membership, valid := decodeExactMembership(raw)
	if !valid || membership.TenantId != tenantID || membership.UserId != user.Id ||
		!canonicalUserIdentity(membership.Id) || membership.CreatedAt.IsZero() {
		return role
	}
	assignments, valid := canonicalMembershipAssignments(membership.Roles)
	if !valid {
		return role
	}
	for _, assignment := range assignments {
		switch domain.UserRole(assignment) {
		case domain.RoleAdmin, domain.RoleCompanyAdmin:
			return domain.RoleCompanyAdmin
		}
	}
	return role
}

func stringPointer(value string) *string {
	return &value
}

func oobKey(code string) string {
	return oobKeyPrefix + code
}

func coerceString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return ""
	}
}

type legacyOobPayload struct {
	Email     string `json:"email"`
	ReqType   string `json:"reqType"`
	ExpiresAt int64  `json:"expiresAt"`
}

func (r *redisRepo) consumeLegacyOobCode(ctx context.Context, code string, expectedReqType string) (string, error) {
	val, err := r.client.HGet(ctx, legacyOobHash, code).Result()
	if err == redis.Nil {
		return "", domain.ErrInvalidOob
	}
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(val) == "" {
		return "", domain.ErrInvalidOob
	}

	var payload legacyOobPayload
	if e := json.Unmarshal([]byte(val), &payload); e != nil {
		return "", e
	}
	if payload.ExpiresAt > 0 && time.Now().Unix() > payload.ExpiresAt {
		_ = r.client.HDel(ctx, legacyOobHash, code).Err()
		return "", domain.ErrInvalidOob
	}
	if strings.TrimSpace(payload.ReqType) != expectedReqType {
		// Do not delete on type mismatch so the code can still be consumed by the correct endpoint.
		return "", domain.ErrInvalidOob
	}
	if strings.TrimSpace(payload.Email) == "" {
		_ = r.client.HDel(ctx, legacyOobHash, code).Err()
		return "", domain.ErrInvalidOob
	}
	if err := r.client.HDel(ctx, legacyOobHash, code).Err(); err != nil {
		return "", err
	}
	return payload.Email, nil
}
