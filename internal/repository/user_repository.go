package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
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
	GetEmailByOobCode(ctx context.Context, code string) (string, error)
	DeleteOobCode(ctx context.Context, code string) error
	GetAllUsers(ctx context.Context) ([]*domain.User, error)
}

// redisRepo is a Redis-backed implementation of UserRepository.
type redisRepo struct {
	client *redis.Client
}

const (
	usersHashV2      = "users_v2"
	legacyUsersHash  = "users"
	userByEmailKeyNS = "userByEmail:"
)

// NewRedisRepo instantiates a repository using the provided Redis client.
func NewRedisRepo(rdb *redis.Client) UserRepository {
	return &redisRepo{client: rdb}
}

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
		if u.Password == "" {
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
	if u.Password == "" {
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
	payload := map[string]interface{}{
		"email":     email,
		"reqType":   reqType,
		"expiresAt": time.Now().Add(15 * time.Minute).Unix(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return r.client.HSet(ctx, "oobs", code, data).Err()
}

// GetEmailByOobCode reads the OOB hash, validates expiration and returns the associated email.
func (r *redisRepo) GetEmailByOobCode(ctx context.Context, code string) (string, error) {
	val, err := r.client.HGet(ctx, "oobs", code).Result()
	if err == redis.Nil {
		return "", domain.ErrInvalidOob
	}
	if err != nil {
		return "", err
	}
	if val == "" {
		return "", domain.ErrInvalidOob
	}
	var payload map[string]interface{}
	if e := json.Unmarshal([]byte(val), &payload); e != nil {
		return "", e
	}
	exp, _ := payload["expiresAt"].(float64)
	if float64(time.Now().Unix()) > exp {
		return "", domain.ErrInvalidOob
	}
	em, _ := payload["email"].(string)
	return em, nil
}

// DeleteOobCode removes the stored OOB record once consumed.
func (r *redisRepo) DeleteOobCode(ctx context.Context, code string) error {
	return r.client.HDel(ctx, "oobs", code).Err()
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
