package repository

import (
	"context"
	"encoding/json"
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
	GetAllUsers(ctx context.Context) ([]*domain.User, error)
	UpsertFromSAML(ctx context.Context, tid, externalSubject, email, name string, roles []string, mergeStrategy domain.MergeStrategy) (domain.User, bool, error)
}

// redisRepo is a Redis-backed implementation of UserRepository.
type redisRepo struct {
	client *redis.Client
}

const (
	usersHashV2             = "users_v2"
	legacyUsersHash         = "users"
	userByEmailKeyNS        = "userByEmail:"
	legacyOobHash           = "oobs"
	oobKeyPrefix            = "oob:"
	samlSubjectKeyNS        = "samlSubject:"
)

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
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}
	if user.Email == "" {
		return domain.ErrInvalidArgument
	}
	existing, _ := r.FindByEmail(ctx, user.Email)
	if existing != nil {
		return domain.ErrEmailExists
	}
	if user.Id == "" {
		return domain.ErrInvalidArgument
	}
	if err := r.client.HSet(ctx, usersHashV2, user.Id, data).Err(); err != nil {
		return err
	}
	if err := r.client.Set(ctx, userByEmailKeyNS+user.Email, user.Id, 0).Err(); err != nil {
		_ = r.client.HDel(ctx, usersHashV2, user.Id).Err()
		return err
	}
	return nil
}

// FindByEmail retrieves a stored user by email, returning nil when absent.
func (r *redisRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
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
		if data, err := json.Marshal(&u); err == nil {
			_ = r.client.HSet(ctx, usersHashV2, u.Id, data).Err()
			_ = r.client.Set(ctx, userByEmailKeyNS+email, u.Id, 0).Err()
		}
	}
	return &u, nil
}

// UpdateUser overwrites the stored user JSON for the provided user.
func (r *redisRepo) UpdateUser(ctx context.Context, user *domain.User) error {
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}
	if user.Id == "" {
		return domain.ErrInvalidArgument
	}
	if err := r.client.HSet(ctx, usersHashV2, user.Id, data).Err(); err != nil {
		return err
	}
	if user.Email != "" {
		_ = r.client.Set(ctx, userByEmailKeyNS+user.Email, user.Id, 0).Err()
	}
	return nil
}

// DeleteByEmail removes a user entry from Redis by email.
func (r *redisRepo) DeleteByEmail(ctx context.Context, email string) error {
	if email == "" {
		return nil
	}
	if userID, err := r.client.Get(ctx, userByEmailKeyNS+email).Result(); err == nil && userID != "" {
		_ = r.client.HDel(ctx, usersHashV2, userID).Err()
		_ = r.client.Del(ctx, userByEmailKeyNS+email).Err()
	}
	_ = r.client.HDel(ctx, legacyUsersHash, email).Err()
	return nil
}

func (r *redisRepo) SetStatus(ctx context.Context, email string, status domain.UserStatus) (*domain.User, error) {
	u, err := r.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, domain.ErrNotFound
	}
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

// GetAllUsers returns all stored users without filtering, primarily for diagnostics.
func (r *redisRepo) GetAllUsers(ctx context.Context) ([]*domain.User, error) {
	vals, err := r.client.HGetAll(ctx, usersHashV2).Result()
	if err != nil {
		return nil, err
	}
	var users []*domain.User
	byEmail := map[string]struct{}{}
	for _, v := range vals {
		var u domain.User
		if e := json.Unmarshal([]byte(v), &u); e != nil {
			return nil, e
		}
		users = append(users, &u)
		if u.Email != "" {
			byEmail[u.Email] = struct{}{}
		}
	}
	legacy, err := r.client.HGetAll(ctx, legacyUsersHash).Result()
	if err != nil {
		return users, nil
	}
	for email, v := range legacy {
		if _, ok := byEmail[email]; ok {
			continue
		}
		var u domain.User
		if e := json.Unmarshal([]byte(v), &u); e != nil {
			return nil, e
		}
		users = append(users, &u)
	}
	return users, nil
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
	val, err := r.client.HGet(ctx, usersHashV2, userID).Result()
	if err == redis.Nil || val == "" {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var u domain.User
	if e := json.Unmarshal([]byte(val), &u); e != nil {
		return nil, e
	}
	return &u, nil
}

// UpsertFromSAML creates or updates a user from a SAML assertion.
// If a user exists with (tid, externalSubject), it is updated and created=false.
// When mergeStrategy is "email" (the default) and a password user exists with
// (tid, email), the user is merged: authSource flips to SAML, externalSubject is
// set, but sub and roles are preserved.
// Otherwise a new user is created and created=true.
func (r *redisRepo) UpsertFromSAML(ctx context.Context, tid, externalSubject, email, name string, roles []string, mergeStrategy domain.MergeStrategy) (domain.User, bool, error) {
	if tid == "" || externalSubject == "" || email == "" {
		return domain.User{}, false, domain.ErrInvalidArgument
	}

	// Treat empty strategy as the default: email.
	if mergeStrategy == "" {
		mergeStrategy = domain.MergeStrategyEmail
	}

	// Case 1: Existing SAML user by external subject.
	existing, err := r.findByExternalSubject(ctx, tid, externalSubject)
	if err != nil {
		return domain.User{}, false, err
	}
	if existing != nil {
		existing.Email = email
		if len(roles) > 0 {
			existing.Role = domain.UserRole(roles[0])
		}
		if err := r.UpdateUser(ctx, existing); err != nil {
			return domain.User{}, false, err
		}
		return *existing, false, nil
	}

	// Case 2: Merge by email — password user with the same email within same tenant.
	// Only active when mergeStrategy is "email".
	if mergeStrategy == domain.MergeStrategyEmail {
		emailUser, err := r.FindByEmail(ctx, email)
		if err != nil && err != domain.ErrNotFound {
			return domain.User{}, false, err
		}
		if emailUser != nil && (emailUser.AuthSource == domain.AuthSourcePassword || emailUser.AuthSource == "") {
			emailUser.AuthSource = domain.AuthSourceSAML
			emailUser.ExternalSubject = externalSubject
			// sub (Id) and roles are intentionally preserved during email merge.
			if err := r.UpdateUser(ctx, emailUser); err != nil {
				return domain.User{}, false, err
			}
			if err := r.client.Set(ctx, samlSubjectKey(tid, externalSubject), emailUser.Id, 0).Err(); err != nil {
				return domain.User{}, false, err
			}
			return *emailUser, false, nil
		}
	}

	// Case 3: Create new SAML user.
	role := domain.RoleCompanyEmployee
	if len(roles) > 0 {
		role = domain.UserRole(roles[0])
	}
	u := domain.User{
		Id:              uuid.NewString(),
		Email:           email,
		Role:            role,
		Status:          domain.UserStatusActive,
		CreatedAt:       time.Now(),
		AuthSource:      domain.AuthSourceSAML,
		ExternalSubject: externalSubject,
	}
	data, err := json.Marshal(&u)
	if err != nil {
		return domain.User{}, false, err
	}
	if err := r.client.HSet(ctx, usersHashV2, u.Id, data).Err(); err != nil {
		return domain.User{}, false, err
	}
	if err := r.client.Set(ctx, userByEmailKeyNS+email, u.Id, 0).Err(); err != nil {
		return domain.User{}, false, err
	}
	if err := r.client.Set(ctx, samlSubjectKey(tid, externalSubject), u.Id, 0).Err(); err != nil {
		return domain.User{}, false, err
	}

	return u, true, nil
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
