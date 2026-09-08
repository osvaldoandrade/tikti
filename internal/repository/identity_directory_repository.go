package repository

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	directoryUserEmailIndex       = "identity:v2:directory:users:email"
	directoryGroupsHash           = "identity:v2:directory:groups"
	directoryGroupNameIndex       = "identity:v2:directory:groups:name:"
	directoryGroupOrderIndex      = "identity:v2:directory:groups:order"
	directoryGroupMembersPrefix   = "identity:v2:directory:groups:members:"
	directoryUserGroupsPrefix     = "identity:v2:directory:users:groups:"
	directoryAssignmentsPrefix    = "identity:v2:access:assignments:"
	directoryPrincipalPrefix      = "identity:v2:access:principal:"
	directoryBackfillMarker       = "identity:v2:backfill:complete"
	directoryBackfillLock         = "identity:v2:backfill:owner"
	directoryBackfillVersion      = "v1"
	directoryBackfillLeaseTTL     = 30 * time.Second
	directoryBackfillLeaseRenewal = 10 * time.Second
	directoryMaximumUsers         = 100_000
	directoryMaximumGroups        = 10_000
	directoryMaximumAssignments   = 10_000
	directoryMaximumBackfillItems = 100_000
	directoryMaximumRelationships = 500
	directoryMaximumRoles         = 100
	directoryMaximumPageSize      = 200
	directoryMaximumRetries       = 8
	authenticationAttemptPrefix   = "identity:v2:auth:attempt:"
)

var errDirectoryRetry = errors.New("identity directory transaction retry exhausted")

var renewDirectoryBackfillLeaseScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) ~= ARGV[1] then return 0 end
redis.call("PEXPIRE", KEYS[1], ARGV[2])
return 1
`)

var releaseDirectoryBackfillLeaseScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) ~= ARGV[1] then return 0 end
return redis.call("DEL", KEYS[1])
`)

var completeDirectoryBackfillScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) ~= ARGV[1] then return 0 end
redis.call("SET", KEYS[2], ARGV[2])
redis.call("DEL", KEYS[1])
return 1
`)

type AuthenticationAttemptLimiter interface {
	AllowAuthenticationAttempt(context.Context, string, string, int, time.Duration) (bool, error)
}

// IdentityDirectoryRepository is the single runtime authority for directory
// projections, global groups and mutable tenant access assignments.
type IdentityDirectoryRepository interface {
	AuthenticationAttemptLimiter
	CreateDirectoryUser(context.Context, *domain.User) (*domain.DirectoryUser, error)
	UpdateDirectoryUser(context.Context, *domain.User) (*domain.DirectoryUser, error)
	ConsumeTemporaryPassword(context.Context, string, string, int, string) error
	GetDirectoryUser(context.Context, string) (*domain.DirectoryUser, error)
	FindDirectoryUserByEmail(context.Context, string) (*domain.DirectoryUser, error)
	ListDirectoryUsers(context.Context, string, string, int) (*domain.DirectoryUserPage, error)
	ListTenantDirectoryUsers(context.Context, string, string, string, int) (*domain.DirectoryUserPage, error)

	CreateGroup(context.Context, string, string) (*domain.IdentityGroup, error)
	GetGroup(context.Context, string) (*domain.IdentityGroup, error)
	GetGroupDetail(context.Context, string) (*domain.IdentityGroupDetail, error)
	ListGroups(context.Context, string, string, int) (*domain.IdentityGroupPage, error)
	PatchGroup(context.Context, string, domain.IdentityGroupPatchReq, string) (*domain.IdentityGroup, error)
	DeleteGroup(context.Context, string, string) (bool, error)
	PutGroupMember(context.Context, string, string, string) (*domain.IdentityGroup, bool, error)
	DeleteGroupMember(context.Context, string, string, string) (*domain.IdentityGroup, bool, error)

	PutAccessAssignment(context.Context, string, domain.AccessPrincipalType, string, []string, string) (*domain.AccessAssignment, bool, error)
	GetAccessAssignment(context.Context, string, domain.AccessPrincipalType, string) (*domain.AccessAssignment, error)
	DeleteAccessAssignment(context.Context, string, domain.AccessPrincipalType, string, string) (bool, error)
	ListAccessAssignments(context.Context, string, string, int) (*domain.AccessAssignmentPage, error)
	GetEffectiveUserAccess(context.Context, string) (*domain.DirectoryUserAccess, error)
	GetEffectiveTenantRoles(context.Context, string, string) ([]string, []domain.AccessProvenance, error)
	ListEffectiveTenantIDs(context.Context, string, int) ([]string, bool, error)

	Backfill(context.Context) (*domain.IdentityBackfillResult, error)
}

var authenticationAttemptScript = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then redis.call("PEXPIRE", KEYS[1], ARGV[1]) end
return count
`)

// AllowAuthenticationAttempt enforces a distributed authentication throttle.
// The Redis key contains only a SHA-256 digest of the server-owned bucket and
// canonical subject, so counters cannot become a secondary identity index.
func (r *identityDirectoryRepo) AllowAuthenticationAttempt(
	ctx context.Context,
	bucket string,
	subject string,
	limit int,
	window time.Duration,
) (bool, error) {
	bucket = strings.TrimSpace(bucket)
	subject = strings.TrimSpace(subject)
	if r == nil || r.client == nil || !validAuthenticationBucket(bucket) || subject == "" || len(subject) > 2048 || limit < 1 || window < time.Millisecond {
		return false, domain.ErrInvalidArgument
	}
	digest := sha256.Sum256([]byte(bucket + "\x00" + subject))
	key := authenticationAttemptPrefix + hex.EncodeToString(digest[:])
	count, err := authenticationAttemptScript.Run(ctx, r.client, []string{key}, window.Milliseconds()).Int64()
	if err != nil {
		return false, err
	}
	return count <= int64(limit), nil
}

func validAuthenticationBucket(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != ':' {
			return false
		}
	}
	return true
}

type identityDirectoryRepo struct{ client *redis.Client }

func NewIdentityDirectoryRepository(client *redis.Client) IdentityDirectoryRepository {
	return &identityDirectoryRepo{client: client}
}

var createDirectoryUserScript = redis.NewScript(`
local owner = redis.call("GET", KEYS[2])
if owner and owner ~= ARGV[1] then return "duplicate" end
local existing = redis.call("HGET", KEYS[1], ARGV[1])
if existing and existing ~= ARGV[3] then return "id-conflict" end
redis.call("HSET", KEYS[1], ARGV[1], ARGV[3])
redis.call("SET", KEYS[2], ARGV[1])
redis.call("ZADD", KEYS[3], 0, ARGV[4])
return "ok"
`)

func (r *identityDirectoryRepo) CreateDirectoryUser(ctx context.Context, input *domain.User) (*domain.DirectoryUser, error) {
	user, err := canonicalDirectoryStorageUser(input)
	if err != nil || r == nil || r.client == nil {
		return nil, domain.ErrInvalidArgument
	}
	// New records always start from the server-owned initial revision.
	user.Revision = 0
	// #nosec G117 -- persisted User.Password contains only a bcrypt hash produced before this boundary.
	payload, err := json.Marshal(user)
	if err != nil {
		return nil, domain.ErrInvalidArgument
	}
	status, err := createDirectoryUserScript.Run(ctx, r.client, []string{
		usersHashV2, userByEmailKeyNS + user.Email, directoryUserEmailIndex,
	}, user.Id, user.Email, string(payload), directoryUserIndexMember(user.Email, user.Id)).Text()
	if err != nil {
		return nil, err
	}
	switch status {
	case "duplicate":
		return nil, domain.ErrEmailExists
	case "id-conflict":
		return nil, domain.ErrDirectoryInvariant
	case "ok":
		return directoryUserProjection(user), nil
	default:
		return nil, domain.ErrDirectoryInvariant
	}
}

func (r *identityDirectoryRepo) UpdateDirectoryUser(ctx context.Context, input *domain.User) (*domain.DirectoryUser, error) {
	user, err := canonicalDirectoryStorageUser(input)
	if err != nil || r == nil || r.client == nil {
		return nil, domain.ErrInvalidArgument
	}
	for attempt := 0; attempt < directoryMaximumRetries; attempt++ {
		var committed *domain.User
		previousRaw, readErr := r.client.HGet(ctx, usersHashV2, user.Id).Result()
		if readErr == redis.Nil {
			return nil, domain.ErrNotFound
		}
		if readErr != nil {
			return nil, readErr
		}
		var observed domain.User
		if json.Unmarshal([]byte(previousRaw), &observed) != nil {
			return nil, domain.ErrDirectoryInvariant
		}
		observedCanonical, canonicalErr := canonicalDirectoryStorageUser(&observed)
		if canonicalErr != nil || observedCanonical.Id != user.Id {
			return nil, domain.ErrDirectoryInvariant
		}
		previousEmail := observedCanonical.Email
		err = r.client.Watch(ctx, func(tx *redis.Tx) error {
			raw, readErr := tx.HGet(ctx, usersHashV2, user.Id).Result()
			if readErr == redis.Nil {
				return domain.ErrNotFound
			}
			if readErr != nil {
				return readErr
			}
			var previous domain.User
			if json.Unmarshal([]byte(raw), &previous) != nil {
				return domain.ErrDirectoryInvariant
			}
			currentCanonical, currentErr := canonicalDirectoryStorageUser(&previous)
			if currentErr != nil || currentCanonical.Id != user.Id {
				return domain.ErrDirectoryInvariant
			}
			if currentCanonical.Revision != user.Revision {
				return domain.ErrVersionConflict
			}
			if currentCanonical.Email != previousEmail {
				return redis.TxFailedErr
			}
			if previousEmail != user.Email {
				owner, ownerErr := tx.Get(ctx, userByEmailKeyNS+user.Email).Result()
				if ownerErr != nil && ownerErr != redis.Nil {
					return ownerErr
				}
				if ownerErr == nil && owner != user.Id {
					return domain.ErrEmailExists
				}
			}
			updated := *user
			updated.Revision = currentCanonical.Revision + 1
			// #nosec G117 -- persisted User.Password contains only a one-way password hash.
			payload, marshalErr := json.Marshal(&updated)
			if marshalErr != nil {
				return domain.ErrInvalidArgument
			}
			_, writeErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, usersHashV2, user.Id, payload)
				pipe.Set(ctx, userByEmailKeyNS+user.Email, user.Id, 0)
				pipe.ZAdd(ctx, directoryUserEmailIndex, &redis.Z{Member: directoryUserIndexMember(user.Email, user.Id)})
				if previousEmail != user.Email {
					pipe.Del(ctx, userByEmailKeyNS+previousEmail)
					pipe.ZRem(ctx, directoryUserEmailIndex, directoryUserIndexMember(previousEmail, user.Id))
				}
				return nil
			})
			if writeErr == nil {
				committed = &updated
			}
			return writeErr
		}, usersHashV2, userByEmailKeyNS+previousEmail, userByEmailKeyNS+user.Email, directoryUserEmailIndex)
		if err == nil {
			*input = *committed
			return directoryUserProjection(committed), nil
		}
		if err != redis.TxFailedErr {
			return nil, err
		}
	}
	return nil, errDirectoryRetry
}

// ConsumeTemporaryPassword atomically replaces the one-time password state.
// The expected hash and token version come from the credential check performed
// by the service; a concurrent winner makes every later attempt invalid.
func (r *identityDirectoryRepo) ConsumeTemporaryPassword(
	ctx context.Context,
	userID string,
	expectedPasswordHash string,
	expectedTokenVersion int,
	replacementPasswordHash string,
) error {
	if r == nil || r.client == nil || !canonicalUserIdentity(userID) ||
		strings.TrimSpace(expectedPasswordHash) == "" || expectedTokenVersion < 0 ||
		strings.TrimSpace(replacementPasswordHash) == "" {
		return domain.ErrInvalidArgument
	}
	for attempt := 0; attempt < directoryMaximumRetries; attempt++ {
		err := r.client.Watch(ctx, func(tx *redis.Tx) error {
			raw, readErr := tx.HGet(ctx, usersHashV2, userID).Result()
			if readErr == redis.Nil {
				return domain.ErrInvalidCreds
			}
			if readErr != nil {
				return readErr
			}
			var stored domain.User
			if json.Unmarshal([]byte(raw), &stored) != nil {
				return domain.ErrDirectoryInvariant
			}
			current, canonicalErr := canonicalDirectoryStorageUser(&stored)
			if canonicalErr != nil || current.Id != userID {
				return domain.ErrDirectoryInvariant
			}
			if current.Status != domain.UserStatusActive || current.AuthSource != domain.AuthSourcePassword ||
				!current.PasswordChangeRequired || current.Password != expectedPasswordHash ||
				current.TokenVersion != expectedTokenVersion {
				return domain.ErrInvalidCreds
			}
			current.Password = replacementPasswordHash
			current.PasswordChangeRequired = false
			current.TokenVersion++
			current.Revision++
			// #nosec G117 -- temporary plaintext is never stored; both values are bcrypt hashes.
			payload, marshalErr := json.Marshal(current)
			if marshalErr != nil {
				return domain.ErrDirectoryInvariant
			}
			_, writeErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, usersHashV2, userID, payload)
				return nil
			})
			return writeErr
		}, usersHashV2)
		if err == nil {
			return nil
		}
		if err != redis.TxFailedErr {
			return err
		}
	}
	return errDirectoryRetry
}

func (r *identityDirectoryRepo) GetDirectoryUser(ctx context.Context, userID string) (*domain.DirectoryUser, error) {
	user, err := r.readStorageUser(ctx, userID)
	if err != nil || user == nil {
		return nil, err
	}
	return directoryUserProjection(user), nil
}

func (r *identityDirectoryRepo) FindDirectoryUserByEmail(ctx context.Context, email string) (*domain.DirectoryUser, error) {
	email = normalizeDirectoryEmail(email)
	if email == "" || r == nil || r.client == nil {
		return nil, domain.ErrInvalidArgument
	}
	userID, err := r.client.Get(ctx, userByEmailKeyNS+email).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	user, err := r.readStorageUser(ctx, userID)
	if err != nil || user == nil || user.Email != email {
		if err == nil {
			err = domain.ErrDirectoryInvariant
		}
		return nil, err
	}
	return directoryUserProjection(user), nil
}

func (r *identityDirectoryRepo) ListDirectoryUsers(ctx context.Context, search, token string, limit int) (*domain.DirectoryUserPage, error) {
	if r == nil || r.client == nil || limit < 1 || limit > directoryMaximumPageSize {
		return nil, domain.ErrInvalidArgument
	}
	search = normalizeDirectorySearch(search)
	if search == "!invalid!" {
		return nil, domain.ErrInvalidArgument
	}
	after, err := decodeDirectoryCursor(token, "users", search)
	if err != nil {
		return nil, err
	}
	minimum := "-"
	if search != "" {
		minimum = "[" + search
	}
	if after != "" {
		minimum = "(" + after
	}
	maximum := "+"
	if search != "" {
		maximum = "[" + search + "\xff"
	}
	members, err := r.client.ZRangeByLex(ctx, directoryUserEmailIndex, &redis.ZRangeBy{
		Min: minimum, Max: maximum, Offset: 0, Count: int64(limit + 1),
	}).Result()
	if err != nil {
		return nil, err
	}
	page := &domain.DirectoryUserPage{Users: make([]domain.DirectoryUser, 0, minInt(limit, len(members)))}
	visible := members
	if len(visible) > limit {
		visible = visible[:limit]
	}
	for _, member := range visible {
		email, userID, ok := parseDirectoryUserIndexMember(member)
		if !ok {
			return nil, domain.ErrDirectoryInvariant
		}
		user, readErr := r.readStorageUser(ctx, userID)
		if readErr != nil || user == nil || user.Email != email {
			return nil, domain.ErrDirectoryInvariant
		}
		page.Users = append(page.Users, *directoryUserProjection(user))
	}
	if len(members) > limit {
		page.NextPageToken, err = encodeDirectoryCursor("users", search, visible[len(visible)-1])
		if err != nil {
			return nil, domain.ErrDirectoryInvariant
		}
	}
	return page, nil
}

// ListTenantDirectoryUsers builds pagination exclusively from principals with
// effective access to the target tenant. Its cursor may therefore contain only
// an already-visible member; it never carries a global directory position.
func (r *identityDirectoryRepo) ListTenantDirectoryUsers(ctx context.Context, tenantID, search, token string, limit int) (*domain.DirectoryUserPage, error) {
	if r == nil || r.client == nil || !canonicalTenantIdentity(tenantID) || limit < 1 || limit > directoryMaximumPageSize {
		return nil, domain.ErrInvalidArgument
	}
	search = normalizeDirectorySearch(search)
	if search == "!invalid!" {
		return nil, domain.ErrInvalidArgument
	}
	after, err := decodeDirectoryCursor(token, "tenant-users", tenantID+"\x00"+search)
	if err != nil {
		return nil, err
	}
	values, err := r.client.HGetAll(ctx, assignmentsKey(tenantID)).Result()
	if err != nil || len(values) > directoryMaximumAssignments {
		return nil, domain.ErrDirectoryInvariant
	}
	userIDs := make(map[string]struct{})
	for field, raw := range values {
		principalType, principalID, ok := parseAssignmentField(field)
		if !ok {
			return nil, domain.ErrDirectoryInvariant
		}
		if _, decodeErr := decodeAssignment(raw, tenantID, principalType, principalID); decodeErr != nil {
			return nil, decodeErr
		}
		switch principalType {
		case domain.AccessPrincipalUser:
			userIDs[principalID] = struct{}{}
		case domain.AccessPrincipalGroup:
			group, groupErr := r.GetGroup(ctx, principalID)
			if groupErr != nil || group == nil {
				if groupErr == nil {
					groupErr = domain.ErrDirectoryInvariant
				}
				return nil, groupErr
			}
			if group.Status != domain.IdentityGroupStatusActive {
				continue
			}
			members, memberErr := r.client.SMembers(ctx, groupMembersKey(principalID)).Result()
			if memberErr != nil || len(members) > directoryMaximumRelationships {
				return nil, domain.ErrDirectoryInvariant
			}
			for _, userID := range members {
				if !canonicalUserIdentity(userID) {
					return nil, domain.ErrDirectoryInvariant
				}
				userIDs[userID] = struct{}{}
			}
		}
		if len(userIDs) > directoryMaximumUsers {
			return nil, domain.ErrDirectoryInvariant
		}
	}
	members := make([]string, 0, len(userIDs))
	users := make(map[string]*domain.User, len(userIDs))
	for userID := range userIDs {
		user, readErr := r.readStorageUser(ctx, userID)
		if readErr != nil || user == nil {
			if readErr == nil {
				readErr = domain.ErrDirectoryInvariant
			}
			return nil, readErr
		}
		if search != "" && !strings.HasPrefix(user.Email, search) {
			continue
		}
		member := directoryUserIndexMember(user.Email, user.Id)
		members = append(members, member)
		users[member] = user
	}
	sort.Strings(members)
	start := sort.SearchStrings(members, after)
	if after != "" && start < len(members) && members[start] == after {
		start++
	}
	end := minInt(start+limit, len(members))
	page := &domain.DirectoryUserPage{Users: make([]domain.DirectoryUser, 0, end-start)}
	for _, member := range members[start:end] {
		page.Users = append(page.Users, *directoryUserProjection(users[member]))
	}
	if end < len(members) {
		page.NextPageToken, err = encodeDirectoryCursor("tenant-users", tenantID+"\x00"+search, members[end-1])
		if err != nil {
			return nil, domain.ErrDirectoryInvariant
		}
	}
	return page, nil
}

func (r *identityDirectoryRepo) readStorageUser(ctx context.Context, userID string) (*domain.User, error) {
	if r == nil || r.client == nil || !canonicalUserIdentity(userID) {
		return nil, domain.ErrInvalidArgument
	}
	raw, err := r.client.HGet(ctx, usersHashV2, userID).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var user domain.User
	if json.Unmarshal([]byte(raw), &user) != nil || user.Id != userID {
		return nil, domain.ErrDirectoryInvariant
	}
	canonical, err := canonicalDirectoryStorageUser(&user)
	if err != nil || canonical.Id != userID {
		return nil, domain.ErrDirectoryInvariant
	}
	return canonical, nil
}

func canonicalDirectoryStorageUser(input *domain.User) (*domain.User, error) {
	if input == nil || !canonicalUserIdentity(input.Id) || input.Revision < 0 {
		return nil, domain.ErrInvalidArgument
	}
	email := normalizeDirectoryEmail(input.Email)
	if email == "" {
		return nil, domain.ErrInvalidArgument
	}
	authSource := input.AuthSource
	if authSource == "" {
		authSource = domain.AuthSourcePassword
	}
	if authSource != domain.AuthSourcePassword && authSource != domain.AuthSourceSAML {
		return nil, domain.ErrInvalidArgument
	}
	if authSource == domain.AuthSourcePassword && strings.TrimSpace(input.Password) == "" ||
		authSource == domain.AuthSourceSAML && !validExternalSubject(input.ExternalSubject) {
		return nil, domain.ErrInvalidArgument
	}
	copy := *input
	if copy.CreatedAt.IsZero() {
		copy.CreatedAt = time.Now().UTC()
	}
	if copy.Status == "" {
		copy.Status = domain.UserStatusActive
	}
	if !validUserStatus(copy.Status) {
		return nil, domain.ErrInvalidArgument
	}
	if copy.Role == "" {
		copy.Role = domain.RoleCompanyEmployee
	}
	copy.Email, copy.AuthSource = email, authSource
	if copy.AuthSource == domain.AuthSourceSAML {
		// SAML is the sole credential authority after conversion. Historical
		// password hashes must never remain usable as a parallel login path.
		copy.Password = ""
		copy.PasswordChangeRequired = false
	}
	return &copy, nil
}

func directoryUserProjection(user *domain.User) *domain.DirectoryUser {
	if user == nil {
		return nil
	}
	projection := &domain.DirectoryUser{
		ID: user.Id, Email: user.Email, Status: user.Status, AuthSource: user.AuthSource,
		PasswordChangeRequired: user.PasswordChangeRequired, CreatedAt: user.CreatedAt,
	}
	if user.CompanyId != nil {
		projection.HomeTenantID = strings.TrimSpace(*user.CompanyId)
	}
	return projection
}

func normalizeDirectoryEmail(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if !canonicalEmail(value) {
		return ""
	}
	return value
}

func normalizeDirectorySearch(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if len(value) > 254 || !utf8.ValidString(value) {
		return "!invalid!"
	}
	for _, char := range value {
		if char < '!' || char > '~' || unicode.IsControl(char) {
			return "!invalid!"
		}
	}
	return value
}

func directoryUserIndexMember(email, userID string) string { return email + "\x00" + userID }

func parseDirectoryUserIndexMember(value string) (string, string, bool) {
	index := strings.LastIndexByte(value, 0)
	if index < 1 || index == len(value)-1 {
		return "", "", false
	}
	email, userID := value[:index], value[index+1:]
	return email, userID, normalizeDirectoryEmail(email) == email && canonicalUserIdentity(userID)
}

func (r *identityDirectoryRepo) CreateGroup(ctx context.Context, name, description string) (*domain.IdentityGroup, error) {
	name, description, err := canonicalGroupFields(name, description)
	if err != nil || r == nil || r.client == nil {
		return nil, domain.ErrInvalidArgument
	}
	now := time.Now().UTC()
	group := &domain.IdentityGroup{ID: "grp_" + uuid.NewString(), Name: name, Description: description, Status: domain.IdentityGroupStatusActive, Version: 1, CreatedAt: now, UpdatedAt: now}
	payload, _ := json.Marshal(group)
	nameKey := groupNameKey(name)
	created, err := r.client.SetNX(ctx, nameKey, group.ID, 0).Result()
	if err != nil {
		return nil, err
	}
	if !created {
		return nil, domain.ErrGroupExists
	}
	_, err = r.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.HSet(ctx, directoryGroupsHash, group.ID, payload)
		pipe.ZAdd(ctx, directoryGroupOrderIndex, &redis.Z{Member: groupIndexMember(name, group.ID)})
		return nil
	})
	if err != nil {
		_ = r.client.Del(ctx, nameKey).Err()
		return nil, err
	}
	return group, nil
}

func (r *identityDirectoryRepo) GetGroup(ctx context.Context, groupID string) (*domain.IdentityGroup, error) {
	if r == nil || r.client == nil || !canonicalGroupID(groupID) {
		return nil, domain.ErrInvalidArgument
	}
	raw, err := r.client.HGet(ctx, directoryGroupsHash, groupID).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	group, err := decodeGroup(raw, groupID)
	if err != nil {
		return nil, err
	}
	count, err := r.client.SCard(ctx, groupMembersKey(groupID)).Result()
	if err != nil || count > directoryMaximumRelationships {
		return nil, domain.ErrDirectoryInvariant
	}
	group.MemberCount = int(count)
	return group, nil
}

func (r *identityDirectoryRepo) GetGroupDetail(ctx context.Context, groupID string) (*domain.IdentityGroupDetail, error) {
	group, err := r.GetGroup(ctx, groupID)
	if err != nil || group == nil {
		return nil, err
	}
	memberIDs, err := r.client.SMembers(ctx, groupMembersKey(groupID)).Result()
	if err != nil || len(memberIDs) > directoryMaximumRelationships || len(memberIDs) != group.MemberCount {
		return nil, domain.ErrDirectoryInvariant
	}
	detail := &domain.IdentityGroupDetail{IdentityGroup: *group, Members: make([]domain.DirectoryUser, 0, len(memberIDs))}
	for _, userID := range memberIDs {
		user, readErr := r.readStorageUser(ctx, userID)
		if readErr != nil || user == nil {
			return nil, domain.ErrDirectoryInvariant
		}
		detail.Members = append(detail.Members, *directoryUserProjection(user))
	}
	sort.Slice(detail.Members, func(left, right int) bool {
		if detail.Members[left].Email == detail.Members[right].Email {
			return detail.Members[left].ID < detail.Members[right].ID
		}
		return detail.Members[left].Email < detail.Members[right].Email
	})
	return detail, nil
}

func (r *identityDirectoryRepo) ListGroups(ctx context.Context, search, token string, limit int) (*domain.IdentityGroupPage, error) {
	if r == nil || r.client == nil || limit < 1 || limit > directoryMaximumPageSize {
		return nil, domain.ErrInvalidArgument
	}
	search = strings.ToLower(strings.TrimSpace(search))
	if search != "" && !validIdentityText(search, 128) {
		return nil, domain.ErrInvalidArgument
	}
	after, err := decodeDirectoryCursor(token, "groups", search)
	if err != nil {
		return nil, err
	}
	minimum, maximum := "-", "+"
	if search != "" {
		minimum, maximum = "["+search, "["+search+"\xff"
	}
	if after != "" {
		minimum = "(" + after
	}
	members, err := r.client.ZRangeByLex(ctx, directoryGroupOrderIndex, &redis.ZRangeBy{Min: minimum, Max: maximum, Count: int64(limit + 1)}).Result()
	if err != nil {
		return nil, err
	}
	page := &domain.IdentityGroupPage{Groups: make([]domain.IdentityGroup, 0, minInt(limit, len(members)))}
	visible := members
	if len(visible) > limit {
		visible = visible[:limit]
	}
	for _, member := range visible {
		_, groupID, ok := parseGroupIndexMember(member)
		if !ok {
			return nil, domain.ErrDirectoryInvariant
		}
		group, readErr := r.GetGroup(ctx, groupID)
		if readErr != nil || group == nil {
			return nil, domain.ErrDirectoryInvariant
		}
		page.Groups = append(page.Groups, *group)
	}
	if len(members) > limit {
		page.NextPageToken, err = encodeDirectoryCursor("groups", search, visible[len(visible)-1])
		if err != nil {
			return nil, domain.ErrDirectoryInvariant
		}
	}
	return page, nil
}

func (r *identityDirectoryRepo) PatchGroup(ctx context.Context, groupID string, patch domain.IdentityGroupPatchReq, ifMatch string) (*domain.IdentityGroup, error) {
	if !canonicalGroupID(groupID) || r == nil || r.client == nil {
		return nil, domain.ErrInvalidArgument
	}
	watchKeys := []string{directoryGroupsHash, directoryGroupOrderIndex}
	if patch.Name != nil {
		if name, _, err := canonicalGroupFields(*patch.Name, ""); err == nil {
			watchKeys = append(watchKeys, groupNameKey(name))
		}
	}
	for attempt := 0; attempt < directoryMaximumRetries; attempt++ {
		var result *domain.IdentityGroup
		err := r.client.Watch(ctx, func(tx *redis.Tx) error {
			raw, err := tx.HGet(ctx, directoryGroupsHash, groupID).Result()
			if err == redis.Nil {
				return domain.ErrNotFound
			}
			if err != nil {
				return err
			}
			current, err := decodeGroup(raw, groupID)
			if err != nil {
				return err
			}
			updated := *current
			if patch.Name != nil {
				updated.Name = *patch.Name
			}
			if patch.Description != nil {
				updated.Description = *patch.Description
			}
			if patch.Status != nil {
				updated.Status = *patch.Status
			}
			updated.Name, updated.Description, err = canonicalGroupFields(updated.Name, updated.Description)
			if err != nil || updated.Status != domain.IdentityGroupStatusActive && updated.Status != domain.IdentityGroupStatusDisabled {
				return domain.ErrInvalidArgument
			}
			if updated.Name == current.Name && updated.Description == current.Description && updated.Status == current.Status {
				result = current
				return nil
			}
			if !matchesVersion(ifMatch, current.Version) {
				return domain.ErrVersionConflict
			}
			if updated.Name != current.Name {
				owner, ownerErr := tx.Get(ctx, groupNameKey(updated.Name)).Result()
				if ownerErr != nil && ownerErr != redis.Nil {
					return ownerErr
				}
				if ownerErr == nil && owner != groupID {
					return domain.ErrVersionConflict
				}
			}
			updated.Version++
			updated.UpdatedAt = time.Now().UTC()
			payload, _ := json.Marshal(&updated)
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, directoryGroupsHash, groupID, payload)
				if updated.Name != current.Name {
					pipe.Del(ctx, groupNameKey(current.Name))
					pipe.Set(ctx, groupNameKey(updated.Name), groupID, 0)
					pipe.ZRem(ctx, directoryGroupOrderIndex, groupIndexMember(current.Name, groupID))
					pipe.ZAdd(ctx, directoryGroupOrderIndex, &redis.Z{Member: groupIndexMember(updated.Name, groupID)})
				}
				return nil
			})
			result = &updated
			return err
		}, watchKeys...)
		if err == nil {
			count := r.client.SCard(ctx, groupMembersKey(groupID)).Val()
			result.MemberCount = int(count)
			return result, nil
		}
		if err != redis.TxFailedErr {
			return nil, err
		}
	}
	return nil, errDirectoryRetry
}

func (r *identityDirectoryRepo) DeleteGroup(ctx context.Context, groupID, ifMatch string) (bool, error) {
	if !canonicalGroupID(groupID) || r == nil || r.client == nil {
		return false, domain.ErrInvalidArgument
	}
	for attempt := 0; attempt < directoryMaximumRetries; attempt++ {
		deleted := false
		err := r.client.Watch(ctx, func(tx *redis.Tx) error {
			raw, readErr := tx.HGet(ctx, directoryGroupsHash, groupID).Result()
			if readErr == redis.Nil {
				return nil
			}
			if readErr != nil {
				return readErr
			}
			group, decodeErr := decodeGroup(raw, groupID)
			if decodeErr != nil {
				return decodeErr
			}
			if !matchesVersion(ifMatch, group.Version) {
				return domain.ErrVersionConflict
			}
			members, membersErr := tx.SMembers(ctx, groupMembersKey(groupID)).Result()
			if membersErr != nil || len(members) > directoryMaximumRelationships {
				return domain.ErrDirectoryInvariant
			}
			tenants, tenantsErr := tx.SMembers(ctx, principalTenantsKey(domain.AccessPrincipalGroup, groupID)).Result()
			if tenantsErr != nil || len(tenants) > directoryMaximumRelationships {
				return domain.ErrDirectoryInvariant
			}
			_, writeErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HDel(ctx, directoryGroupsHash, groupID)
				pipe.Del(ctx, groupNameKey(group.Name), groupMembersKey(groupID), principalTenantsKey(domain.AccessPrincipalGroup, groupID))
				pipe.ZRem(ctx, directoryGroupOrderIndex, groupIndexMember(group.Name, groupID))
				for _, userID := range members {
					pipe.SRem(ctx, userGroupsKey(userID), groupID)
				}
				for _, tenantID := range tenants {
					pipe.HDel(ctx, assignmentsKey(tenantID), assignmentField(domain.AccessPrincipalGroup, groupID))
				}
				return nil
			})
			deleted = writeErr == nil
			return writeErr
		}, directoryGroupsHash, directoryGroupOrderIndex, groupMembersKey(groupID), principalTenantsKey(domain.AccessPrincipalGroup, groupID))
		if err == nil {
			return deleted, nil
		}
		if err != redis.TxFailedErr {
			return false, err
		}
	}
	return false, errDirectoryRetry
}

func (r *identityDirectoryRepo) PutGroupMember(ctx context.Context, groupID, userID, ifMatch string) (*domain.IdentityGroup, bool, error) {
	return r.changeGroupMember(ctx, groupID, userID, ifMatch, true)
}

func (r *identityDirectoryRepo) DeleteGroupMember(ctx context.Context, groupID, userID, ifMatch string) (*domain.IdentityGroup, bool, error) {
	return r.changeGroupMember(ctx, groupID, userID, ifMatch, false)
}

func (r *identityDirectoryRepo) changeGroupMember(ctx context.Context, groupID, userID, ifMatch string, add bool) (*domain.IdentityGroup, bool, error) {
	if !canonicalGroupID(groupID) || !canonicalUserIdentity(userID) || r == nil || r.client == nil {
		return nil, false, domain.ErrInvalidArgument
	}
	for attempt := 0; attempt < directoryMaximumRetries; attempt++ {
		var result *domain.IdentityGroup
		changed := false
		err := r.client.Watch(ctx, func(tx *redis.Tx) error {
			if add {
				userRaw, userErr := tx.HGet(ctx, usersHashV2, userID).Result()
				if userErr == redis.Nil {
					return domain.ErrNotFound
				}
				if userErr != nil {
					return userErr
				}
				var stored domain.User
				if json.Unmarshal([]byte(userRaw), &stored) != nil {
					return domain.ErrDirectoryInvariant
				}
				canonical, canonicalErr := canonicalDirectoryStorageUser(&stored)
				if canonicalErr != nil || canonical.Id != userID {
					return domain.ErrDirectoryInvariant
				}
			}
			raw, err := tx.HGet(ctx, directoryGroupsHash, groupID).Result()
			if err == redis.Nil {
				return domain.ErrNotFound
			}
			if err != nil {
				return err
			}
			group, err := decodeGroup(raw, groupID)
			if err != nil {
				return err
			}
			exists, err := tx.SIsMember(ctx, groupMembersKey(groupID), userID).Result()
			if err != nil {
				return err
			}
			if exists == add {
				result = group
				return nil
			}
			if !matchesVersion(ifMatch, group.Version) {
				return domain.ErrVersionConflict
			}
			if add {
				count, countErr := tx.SCard(ctx, groupMembersKey(groupID)).Result()
				if countErr != nil || count >= directoryMaximumRelationships {
					return domain.ErrDirectoryInvariant
				}
			}
			group.Version++
			group.UpdatedAt = time.Now().UTC()
			payload, _ := json.Marshal(group)
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, directoryGroupsHash, groupID, payload)
				if add {
					pipe.SAdd(ctx, groupMembersKey(groupID), userID)
					pipe.SAdd(ctx, userGroupsKey(userID), groupID)
				} else {
					pipe.SRem(ctx, groupMembersKey(groupID), userID)
					pipe.SRem(ctx, userGroupsKey(userID), groupID)
				}
				return nil
			})
			result, changed = group, true
			return err
		}, usersHashV2, directoryGroupsHash, groupMembersKey(groupID), userGroupsKey(userID))
		if err == nil {
			result.MemberCount = int(r.client.SCard(ctx, groupMembersKey(groupID)).Val())
			return result, changed, nil
		}
		if err != redis.TxFailedErr {
			return nil, false, err
		}
	}
	return nil, false, errDirectoryRetry
}

func (r *identityDirectoryRepo) PutAccessAssignment(ctx context.Context, tenantID string, principalType domain.AccessPrincipalType, principalID string, roles []string, ifMatch string) (*domain.AccessAssignment, bool, error) {
	roles, err := canonicalDirectoryRoles(roles)
	if err != nil || !canonicalTenantIdentity(tenantID) || !canonicalPrincipal(principalType, principalID) || r == nil || r.client == nil {
		return nil, false, domain.ErrInvalidArgument
	}
	key, field, reverse := assignmentsKey(tenantID), assignmentField(principalType, principalID), principalTenantsKey(principalType, principalID)
	principalAuthorityKey := usersHashV2
	if principalType == domain.AccessPrincipalGroup {
		principalAuthorityKey = directoryGroupsHash
	}
	for attempt := 0; attempt < directoryMaximumRetries; attempt++ {
		var result *domain.AccessAssignment
		created := false
		err = r.client.Watch(ctx, func(tx *redis.Tx) error {
			if principalType == domain.AccessPrincipalUser {
				userRaw, userErr := tx.HGet(ctx, usersHashV2, principalID).Result()
				if userErr == redis.Nil {
					return domain.ErrNotFound
				}
				if userErr != nil {
					return userErr
				}
				var stored domain.User
				if json.Unmarshal([]byte(userRaw), &stored) != nil {
					return domain.ErrDirectoryInvariant
				}
				canonical, canonicalErr := canonicalDirectoryStorageUser(&stored)
				if canonicalErr != nil || canonical.Id != principalID {
					return domain.ErrDirectoryInvariant
				}
				if canonical.AuthSource == domain.AuthSourceSAML && (canonical.CompanyId == nil || *canonical.CompanyId != tenantID) {
					return domain.ErrInvalidTenant
				}
			} else {
				groupRaw, groupErr := tx.HGet(ctx, directoryGroupsHash, principalID).Result()
				if groupErr == redis.Nil {
					return domain.ErrNotFound
				}
				if groupErr != nil {
					return groupErr
				}
				if _, decodeErr := decodeGroup(groupRaw, principalID); decodeErr != nil {
					return decodeErr
				}
			}
			raw, readErr := tx.HGet(ctx, key, field).Result()
			now := time.Now().UTC()
			if readErr == redis.Nil {
				if ifMatch != "" && ifMatch != "*" {
					return domain.ErrVersionConflict
				}
				result = &domain.AccessAssignment{TenantID: tenantID, PrincipalType: principalType, PrincipalID: principalID, Roles: roles, Version: 1, CreatedAt: now, UpdatedAt: now}
				created = true
			} else if readErr != nil {
				return readErr
			} else {
				current, decodeErr := decodeAssignment(raw, tenantID, principalType, principalID)
				if decodeErr != nil {
					return decodeErr
				}
				if slicesEqual(current.Roles, roles) {
					result = current
					return nil
				}
				if !matchesVersion(ifMatch, current.Version) {
					return domain.ErrVersionConflict
				}
				current.Roles, current.Version, current.UpdatedAt = roles, current.Version+1, now
				result = current
			}
			payload, _ := json.Marshal(result)
			_, writeErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HSet(ctx, key, field, payload)
				pipe.SAdd(ctx, reverse, tenantID)
				return nil
			})
			return writeErr
		}, principalAuthorityKey, key, reverse)
		if err == nil {
			return result, created, nil
		}
		if err != redis.TxFailedErr {
			return nil, false, err
		}
	}
	return nil, false, errDirectoryRetry
}

func (r *identityDirectoryRepo) DeleteAccessAssignment(ctx context.Context, tenantID string, principalType domain.AccessPrincipalType, principalID, ifMatch string) (bool, error) {
	if !canonicalTenantIdentity(tenantID) || !canonicalPrincipal(principalType, principalID) || r == nil || r.client == nil {
		return false, domain.ErrInvalidArgument
	}
	key, field, reverse := assignmentsKey(tenantID), assignmentField(principalType, principalID), principalTenantsKey(principalType, principalID)
	for attempt := 0; attempt < directoryMaximumRetries; attempt++ {
		deleted := false
		err := r.client.Watch(ctx, func(tx *redis.Tx) error {
			raw, readErr := tx.HGet(ctx, key, field).Result()
			if readErr == redis.Nil {
				return nil
			}
			if readErr != nil {
				return readErr
			}
			current, decodeErr := decodeAssignment(raw, tenantID, principalType, principalID)
			if decodeErr != nil {
				return decodeErr
			}
			if !matchesVersion(ifMatch, current.Version) {
				return domain.ErrVersionConflict
			}
			_, writeErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.HDel(ctx, key, field)
				pipe.SRem(ctx, reverse, tenantID)
				return nil
			})
			deleted = writeErr == nil
			return writeErr
		}, key, reverse)
		if err == nil {
			return deleted, nil
		}
		if err != redis.TxFailedErr {
			return false, err
		}
	}
	return false, errDirectoryRetry
}

func (r *identityDirectoryRepo) GetAccessAssignment(ctx context.Context, tenantID string, principalType domain.AccessPrincipalType, principalID string) (*domain.AccessAssignment, error) {
	if !canonicalTenantIdentity(tenantID) || !canonicalPrincipal(principalType, principalID) || r == nil || r.client == nil {
		return nil, domain.ErrInvalidArgument
	}
	return r.readAssignment(ctx, tenantID, principalType, principalID)
}

func (r *identityDirectoryRepo) ListAccessAssignments(ctx context.Context, tenantID, token string, limit int) (*domain.AccessAssignmentPage, error) {
	if r == nil || r.client == nil || !canonicalTenantIdentity(tenantID) || limit < 1 || limit > directoryMaximumPageSize {
		return nil, domain.ErrInvalidArgument
	}
	after, err := decodeDirectoryCursor(token, "assignments", tenantID)
	if err != nil {
		return nil, err
	}
	key := assignmentsKey(tenantID)
	count, err := r.client.HLen(ctx, key).Result()
	if err != nil || count > directoryMaximumAssignments {
		return nil, domain.ErrDirectoryInvariant
	}
	values, err := r.client.HGetAll(ctx, key).Result()
	if err != nil || len(values) > directoryMaximumAssignments {
		return nil, domain.ErrDirectoryInvariant
	}
	fields := make([]string, 0, len(values))
	for field := range values {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	start := sort.SearchStrings(fields, after)
	if after != "" && start < len(fields) && fields[start] == after {
		start++
	}
	end := minInt(start+limit, len(fields))
	page := &domain.AccessAssignmentPage{Assignments: make([]domain.AccessAssignment, 0, end-start)}
	for _, field := range fields[start:end] {
		principalType, principalID, ok := parseAssignmentField(field)
		if !ok {
			return nil, domain.ErrDirectoryInvariant
		}
		item, decodeErr := decodeAssignment(values[field], tenantID, principalType, principalID)
		if decodeErr != nil {
			return nil, decodeErr
		}
		page.Assignments = append(page.Assignments, *item)
	}
	if end < len(fields) {
		page.NextPageToken, err = encodeDirectoryCursor("assignments", tenantID, fields[end-1])
		if err != nil {
			return nil, domain.ErrDirectoryInvariant
		}
	}
	return page, nil
}

func (r *identityDirectoryRepo) GetEffectiveUserAccess(ctx context.Context, userID string) (*domain.DirectoryUserAccess, error) {
	user, err := r.GetDirectoryUser(ctx, userID)
	if err != nil || user == nil {
		if err == nil {
			err = domain.ErrNotFound
		}
		return nil, err
	}
	tenantIDs, exceeded, err := r.ListEffectiveTenantIDs(ctx, userID, directoryMaximumRelationships)
	if err != nil || exceeded {
		return nil, domain.ErrDirectoryInvariant
	}
	result := &domain.DirectoryUserAccess{User: *user, Tenants: make([]domain.EffectiveTenantAccess, 0, len(tenantIDs))}
	for _, tenantID := range tenantIDs {
		roles, provenance, readErr := r.GetEffectiveTenantRoles(ctx, userID, tenantID)
		if readErr != nil {
			return nil, readErr
		}
		if len(roles) > 0 {
			result.Tenants = append(result.Tenants, domain.EffectiveTenantAccess{TenantID: tenantID, Roles: roles, Provenance: provenance})
		}
	}
	return result, nil
}

func (r *identityDirectoryRepo) ListEffectiveTenantIDs(ctx context.Context, userID string, maximum int) ([]string, bool, error) {
	if !canonicalUserIdentity(userID) || maximum < 1 || maximum > directoryMaximumRelationships || r == nil || r.client == nil {
		return nil, false, domain.ErrInvalidArgument
	}
	user, err := r.GetDirectoryUser(ctx, userID)
	if err != nil || user == nil {
		if err == nil {
			err = domain.ErrNotFound
		}
		return nil, false, err
	}
	tenants, err := r.client.SMembers(ctx, principalTenantsKey(domain.AccessPrincipalUser, userID)).Result()
	if err != nil {
		return nil, false, err
	}
	groups, err := r.client.SMembers(ctx, userGroupsKey(userID)).Result()
	if err != nil || len(groups) > directoryMaximumRelationships {
		return nil, false, domain.ErrDirectoryInvariant
	}
	set := make(map[string]struct{}, len(tenants))
	for _, tenantID := range tenants {
		if !canonicalTenantIdentity(tenantID) {
			return nil, false, domain.ErrDirectoryInvariant
		}
		set[tenantID] = struct{}{}
	}
	for _, groupID := range groups {
		group, readErr := r.GetGroup(ctx, groupID)
		if readErr != nil || group == nil {
			return nil, false, domain.ErrDirectoryInvariant
		}
		if group.Status != domain.IdentityGroupStatusActive {
			continue
		}
		groupTenants, readErr := r.client.SMembers(ctx, principalTenantsKey(domain.AccessPrincipalGroup, groupID)).Result()
		if readErr != nil || len(groupTenants) > directoryMaximumRelationships {
			return nil, false, domain.ErrDirectoryInvariant
		}
		for _, tenantID := range groupTenants {
			if !canonicalTenantIdentity(tenantID) {
				return nil, false, domain.ErrDirectoryInvariant
			}
			set[tenantID] = struct{}{}
		}
		if len(set) > maximum {
			return nil, true, nil
		}
	}
	result := make([]string, 0, len(set))
	for tenantID := range set {
		if user.AuthSource == domain.AuthSourceSAML && user.HomeTenantID != tenantID {
			continue
		}
		result = append(result, tenantID)
	}
	sort.Strings(result)
	return result, len(result) > maximum, nil
}

func (r *identityDirectoryRepo) GetEffectiveTenantRoles(ctx context.Context, userID, tenantID string) ([]string, []domain.AccessProvenance, error) {
	if !canonicalUserIdentity(userID) || !canonicalTenantIdentity(tenantID) || r == nil || r.client == nil {
		return nil, nil, domain.ErrInvalidArgument
	}
	user, err := r.GetDirectoryUser(ctx, userID)
	if err != nil || user == nil {
		if err == nil {
			err = domain.ErrNotFound
		}
		return nil, nil, err
	}
	if user.AuthSource == domain.AuthSourceSAML && user.HomeTenantID != tenantID {
		return []string{}, []domain.AccessProvenance{}, nil
	}
	roleSet := map[string]struct{}{}
	provenance := []domain.AccessProvenance{}
	if direct, err := r.readAssignment(ctx, tenantID, domain.AccessPrincipalUser, userID); err != nil {
		return nil, nil, err
	} else if direct != nil {
		for _, role := range direct.Roles {
			roleSet[role] = struct{}{}
		}
		provenance = append(provenance, domain.AccessProvenance{Type: "DIRECT", Roles: append([]string(nil), direct.Roles...), AssignmentVersion: direct.Version})
	}
	groups, err := r.client.SMembers(ctx, userGroupsKey(userID)).Result()
	if err != nil || len(groups) > directoryMaximumRelationships {
		return nil, nil, domain.ErrDirectoryInvariant
	}
	sort.Strings(groups)
	for _, groupID := range groups {
		group, readErr := r.GetGroup(ctx, groupID)
		if readErr != nil || group == nil {
			return nil, nil, domain.ErrDirectoryInvariant
		}
		if group.Status != domain.IdentityGroupStatusActive {
			continue
		}
		assignment, readErr := r.readAssignment(ctx, tenantID, domain.AccessPrincipalGroup, groupID)
		if readErr != nil {
			return nil, nil, readErr
		}
		if assignment == nil {
			continue
		}
		for _, role := range assignment.Roles {
			roleSet[role] = struct{}{}
		}
		provenance = append(provenance, domain.AccessProvenance{Type: "GROUP", Roles: append([]string(nil), assignment.Roles...), AssignmentVersion: assignment.Version, GroupID: group.ID, GroupName: group.Name})
	}
	roles := make([]string, 0, len(roleSet))
	for role := range roleSet {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles, provenance, nil
}

func (r *identityDirectoryRepo) readAssignment(ctx context.Context, tenantID string, principalType domain.AccessPrincipalType, principalID string) (*domain.AccessAssignment, error) {
	raw, err := r.client.HGet(ctx, assignmentsKey(tenantID), assignmentField(principalType, principalID)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeAssignment(raw, tenantID, principalType, principalID)
}

func (r *identityDirectoryRepo) Backfill(ctx context.Context) (*domain.IdentityBackfillResult, error) {
	if r == nil || r.client == nil {
		return nil, domain.ErrDirectoryInvariant
	}
	complete, err := r.directoryBackfillComplete(ctx)
	if err != nil {
		return nil, err
	}
	if complete {
		// Legacy membership writers are removed before this marker can be
		// committed. From this point on, canonical assignments (including an
		// intentional absence after DELETE) are the only authority.
		return &domain.IdentityBackfillResult{}, nil
	}

	owner := uuid.NewString()
	acquired, err := r.client.SetNX(ctx, directoryBackfillLock, owner, directoryBackfillLeaseTTL).Result()
	if err != nil {
		return nil, err
	}
	if !acquired {
		// Close the marker/lock race: the owner may have completed immediately
		// after our first marker read.
		complete, markerErr := r.directoryBackfillComplete(ctx)
		if markerErr != nil {
			return nil, markerErr
		}
		if complete {
			return &domain.IdentityBackfillResult{}, nil
		}
		return nil, domain.ErrDirectoryBackfillInProgress
	}

	leaseCtx, cancelLease := context.WithCancel(ctx)
	leaseDone := make(chan struct{})
	go r.renewDirectoryBackfillLease(leaseCtx, cancelLease, leaseDone, owner)
	releaseLease := true
	defer func() {
		cancelLease()
		<-leaseDone
		if releaseLease {
			releaseCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _ = releaseDirectoryBackfillLeaseScript.Run(
				releaseCtx, r.client, []string{directoryBackfillLock}, owner,
			).Result()
		}
	}()

	users, err := r.backfillUsers(leaseCtx)
	if err != nil {
		return nil, err
	}
	assignments, err := r.backfillAssignments(leaseCtx)
	if err != nil {
		return nil, err
	}
	committed, err := completeDirectoryBackfillScript.Run(
		leaseCtx,
		r.client,
		[]string{directoryBackfillLock, directoryBackfillMarker},
		owner,
		directoryBackfillVersion,
	).Int()
	if err != nil {
		return nil, err
	}
	if committed != 1 {
		return nil, domain.ErrDirectoryBackfillInProgress
	}
	releaseLease = false
	return &domain.IdentityBackfillResult{UsersIndexed: users, AssignmentsCopied: assignments}, nil
}

func (r *identityDirectoryRepo) directoryBackfillComplete(ctx context.Context) (bool, error) {
	marker, err := r.client.Get(ctx, directoryBackfillMarker).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if marker != directoryBackfillVersion {
		return false, domain.ErrDirectoryInvariant
	}
	return true, nil
}

func (r *identityDirectoryRepo) renewDirectoryBackfillLease(
	ctx context.Context,
	cancel context.CancelFunc,
	done chan<- struct{},
	owner string,
) {
	defer close(done)
	ticker := time.NewTicker(directoryBackfillLeaseRenewal)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renewed, err := renewDirectoryBackfillLeaseScript.Run(
				ctx,
				r.client,
				[]string{directoryBackfillLock},
				owner,
				directoryBackfillLeaseTTL.Milliseconds(),
			).Int()
			if err != nil || renewed != 1 {
				cancel()
				return
			}
		}
	}
}

func (r *identityDirectoryRepo) backfillUsers(ctx context.Context) (int, error) {
	v2, err := scanHashBounded(ctx, r.client, usersHashV2, directoryMaximumUsers)
	if err != nil {
		return 0, err
	}
	legacy, err := scanHashBounded(ctx, r.client, legacyUsersHash, directoryMaximumUsers)
	if err != nil {
		return 0, err
	}
	byID := map[string]*domain.User{}
	byEmail := map[string]string{}
	consume := func(raw string, prefer bool) error {
		var user domain.User
		if json.Unmarshal([]byte(raw), &user) != nil {
			return domain.ErrDirectoryInvariant
		}
		canonical, canonicalErr := canonicalDirectoryStorageUser(&user)
		if canonicalErr != nil {
			return domain.ErrDirectoryInvariant
		}
		if _, exists := byID[canonical.Id]; exists && !prefer {
			return nil
		}
		if owner, exists := byEmail[canonical.Email]; exists && owner != canonical.Id {
			return domain.ErrDirectoryInvariant
		}
		byEmail[canonical.Email] = canonical.Id
		byID[canonical.Id] = canonical
		return nil
	}
	for _, raw := range v2 {
		if err = consume(raw, true); err != nil {
			return 0, err
		}
	}
	for _, raw := range legacy {
		if err = consume(raw, false); err != nil {
			return 0, err
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		user := byID[id]
		// #nosec G117 -- backfill rewrites the existing one-way hash, never plaintext.
		payload, _ := json.Marshal(user)
		owner, getErr := r.client.Get(ctx, userByEmailKeyNS+user.Email).Result()
		if getErr != nil && getErr != redis.Nil || getErr == nil && owner != id {
			return 0, domain.ErrDirectoryInvariant
		}
		_, err = r.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.HSet(ctx, usersHashV2, id, payload)
			pipe.Set(ctx, userByEmailKeyNS+user.Email, id, 0)
			pipe.ZAdd(ctx, directoryUserEmailIndex, &redis.Z{Member: directoryUserIndexMember(user.Email, id)})
			return nil
		})
		if err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

func (r *identityDirectoryRepo) backfillAssignments(ctx context.Context) (int, error) {
	keys, err := scanKeysBounded(ctx, r.client, "memberships:*", directoryMaximumAssignments*2)
	if err != nil {
		return 0, err
	}
	type pair struct{ tenant, user string }
	type candidate struct {
		roles []string
		v2    bool
	}
	values := map[pair]candidate{}
	for _, key := range keys {
		tenantID := ""
		isV2 := false
		switch {
		case strings.HasPrefix(key, membershipV2ForwardPrefix):
			tenantID = strings.TrimPrefix(key, membershipV2ForwardPrefix)
			isV2 = true
		case strings.HasPrefix(key, "memberships:") && !strings.HasPrefix(key, "memberships:v2:"):
			tenantID = strings.TrimPrefix(key, "memberships:")
		default:
			continue
		}
		if !canonicalTenantIdentity(tenantID) {
			return 0, domain.ErrDirectoryInvariant
		}
		memberships, scanErr := scanHashBounded(ctx, r.client, key, directoryMaximumAssignments)
		if scanErr != nil {
			return 0, scanErr
		}
		for userID, raw := range memberships {
			var membership domain.Membership
			if json.Unmarshal([]byte(raw), &membership) != nil || membership.TenantId != tenantID || membership.UserId != userID {
				return 0, domain.ErrDirectoryInvariant
			}
			roles, roleErr := canonicalDirectoryRoles(membership.Roles)
			if roleErr != nil {
				return 0, domain.ErrDirectoryInvariant
			}
			pairKey := pair{tenantID, userID}
			if prior, exists := values[pairKey]; exists {
				switch {
				case prior.v2 && !isV2:
					continue
				case prior.v2 == isV2 && !slicesEqual(prior.roles, roles):
					return 0, domain.ErrDirectoryInvariant
				}
			}
			values[pairKey] = candidate{roles: roles, v2: isV2}
			if len(values) > directoryMaximumBackfillItems {
				return 0, domain.ErrDirectoryInvariant
			}
		}
	}
	pairs := make([]pair, 0, len(values))
	for key := range values {
		pairs = append(pairs, key)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].tenant == pairs[j].tenant {
			return pairs[i].user < pairs[j].user
		}
		return pairs[i].tenant < pairs[j].tenant
	})
	for _, key := range pairs {
		existing, readErr := r.GetAccessAssignment(ctx, key.tenant, domain.AccessPrincipalUser, key.user)
		if readErr != nil {
			return 0, readErr
		}
		// Once a direct assignment has been projected into V2 it is authoritative.
		// Replaying the migration must never overwrite an administrator's later
		// update with stale legacy membership roles.
		if existing != nil {
			continue
		}
		if _, _, err = r.PutAccessAssignment(ctx, key.tenant, domain.AccessPrincipalUser, key.user, values[key].roles, ""); err != nil {
			return 0, err
		}
	}
	return len(pairs), nil
}

func scanHashBounded(ctx context.Context, client *redis.Client, key string, maximum int) (map[string]string, error) {
	result := map[string]string{}
	var cursor uint64
	for {
		values, next, err := client.HScan(ctx, key, cursor, "", 256).Result()
		if err != nil {
			return nil, err
		}
		if len(values)%2 != 0 {
			return nil, domain.ErrDirectoryInvariant
		}
		for index := 0; index < len(values); index += 2 {
			result[values[index]] = values[index+1]
			if len(result) > maximum {
				return nil, domain.ErrDirectoryInvariant
			}
		}
		cursor = next
		if cursor == 0 {
			return result, nil
		}
		if err = ctx.Err(); err != nil {
			return nil, err
		}
	}
}

func scanKeysBounded(ctx context.Context, client *redis.Client, pattern string, maximum int) ([]string, error) {
	result := []string{}
	var cursor uint64
	for {
		keys, next, err := client.Scan(ctx, cursor, pattern, 256).Result()
		if err != nil {
			return nil, err
		}
		result = append(result, keys...)
		if len(result) > maximum {
			return nil, domain.ErrDirectoryInvariant
		}
		cursor = next
		if cursor == 0 {
			sort.Strings(result)
			return result, nil
		}
		if err = ctx.Err(); err != nil {
			return nil, err
		}
	}
}

func canonicalGroupFields(name, description string) (string, string, error) {
	name, description = strings.TrimSpace(name), strings.TrimSpace(description)
	if !validIdentityText(name, 128) || description != "" && !validIdentityText(description, 512) {
		return "", "", domain.ErrInvalidArgument
	}
	return name, description, nil
}

func canonicalGroupID(value string) bool {
	return strings.HasPrefix(value, "grp_") && canonicalUserIdentity(value)
}

func decodeGroup(raw, expectedID string) (*domain.IdentityGroup, error) {
	var group domain.IdentityGroup
	if json.Unmarshal([]byte(raw), &group) != nil || group.ID != expectedID || !canonicalGroupID(group.ID) || group.Version < 1 || group.CreatedAt.IsZero() || group.UpdatedAt.IsZero() || group.Status != domain.IdentityGroupStatusActive && group.Status != domain.IdentityGroupStatusDisabled {
		return nil, domain.ErrDirectoryInvariant
	}
	name, description, err := canonicalGroupFields(group.Name, group.Description)
	if err != nil || name != group.Name || description != group.Description {
		return nil, domain.ErrDirectoryInvariant
	}
	return &group, nil
}

func groupNameKey(name string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(name)))
	return directoryGroupNameIndex + hex.EncodeToString(sum[:])
}
func groupIndexMember(name, id string) string { return strings.ToLower(name) + "\x00" + id }
func parseGroupIndexMember(value string) (string, string, bool) {
	index := strings.LastIndexByte(value, 0)
	if index < 1 || index == len(value)-1 {
		return "", "", false
	}
	return value[:index], value[index+1:], canonicalGroupID(value[index+1:])
}
func groupMembersKey(groupID string) string { return directoryGroupMembersPrefix + groupID }
func userGroupsKey(userID string) string    { return directoryUserGroupsPrefix + userID }

func canonicalDirectoryRoles(values []string) ([]string, error) {
	if len(values) < 1 || len(values) > directoryMaximumRoles {
		return nil, domain.ErrInvalidArgument
	}
	result := append([]string(nil), values...)
	for index := range result {
		result[index] = strings.TrimSpace(result[index])
		if !canonicalMembershipRoleName(result[index]) {
			return nil, domain.ErrInvalidArgument
		}
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, domain.ErrInvalidArgument
		}
	}
	return result, nil
}

func canonicalPrincipal(kind domain.AccessPrincipalType, id string) bool {
	switch kind {
	case domain.AccessPrincipalUser:
		return canonicalUserIdentity(id)
	case domain.AccessPrincipalGroup:
		return canonicalGroupID(id)
	default:
		return false
	}
}
func assignmentsKey(tenantID string) string { return directoryAssignmentsPrefix + tenantID }
func assignmentField(kind domain.AccessPrincipalType, id string) string {
	return strings.ToLower(string(kind)) + ":" + id
}
func principalTenantsKey(kind domain.AccessPrincipalType, id string) string {
	return directoryPrincipalPrefix + strings.ToLower(string(kind)) + ":" + id + ":tenants"
}
func parseAssignmentField(value string) (domain.AccessPrincipalType, string, bool) {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	kind := domain.AccessPrincipalType(strings.ToUpper(parts[0]))
	return kind, parts[1], canonicalPrincipal(kind, parts[1])
}

func decodeAssignment(raw, tenantID string, kind domain.AccessPrincipalType, principalID string) (*domain.AccessAssignment, error) {
	var assignment domain.AccessAssignment
	if json.Unmarshal([]byte(raw), &assignment) != nil || assignment.TenantID != tenantID || assignment.PrincipalType != kind || assignment.PrincipalID != principalID || assignment.Version < 1 || assignment.CreatedAt.IsZero() || assignment.UpdatedAt.IsZero() {
		return nil, domain.ErrDirectoryInvariant
	}
	roles, err := canonicalDirectoryRoles(assignment.Roles)
	if err != nil || !slicesEqual(roles, assignment.Roles) {
		return nil, domain.ErrDirectoryInvariant
	}
	return &assignment, nil
}

func matchesVersion(value string, version int64) bool {
	return value == "*" || value == IdentityETag(version)
}
func IdentityETag(version int64) string { return "\"" + strconv.FormatInt(version, 10) + "\"" }
func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

type directoryCursor struct {
	Version            int `json:"v"`
	Kind, Scope, After string
}

func encodeDirectoryCursor(kind, scope, after string) (string, error) {
	raw, err := json.Marshal(directoryCursor{Version: 1, Kind: kind, Scope: scope, After: after})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func decodeDirectoryCursor(encoded, kind, scope string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	if len(encoded) > 1024 {
		return "", domain.ErrInvalidArgument
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", domain.ErrInvalidArgument
	}
	var cursor directoryCursor
	if json.Unmarshal(raw, &cursor) != nil || cursor.Version != 1 || cursor.Kind != kind || cursor.Scope != scope || cursor.After == "" {
		return "", domain.ErrInvalidArgument
	}
	return cursor.After, nil
}
func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
