package repository

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// OOBSubject binds a one-time credential to the original immutable account generation.
type OOBSubject struct {
	UserID       string
	Email        string
	TokenVersion int
}

// SubjectBoundOOBRepository never resolves an old credential through a reused email.
type SubjectBoundOOBRepository interface {
	SaveSubjectOobCode(context.Context, string, OOBSubject, string) error
	ConsumeSubjectOobCode(context.Context, string, string) (OOBSubject, error)
}

var _ SubjectBoundOOBRepository = (*redisRepo)(nil)

const consumeSubjectOobScript = `
local request = redis.call("HGET", KEYS[1], "reqType")
if not request or request ~= ARGV[1] then return {} end
local email = redis.call("HGET", KEYS[1], "email")
local subject = redis.call("HGET", KEYS[1], "userId")
local version = redis.call("HGET", KEYS[1], "tokenVersion")
local expiry = tonumber(redis.call("HGET", KEYS[1], "expiresAt"))
redis.call("DEL", KEYS[1])
if not email or not subject or not version or not expiry or expiry < tonumber(ARGV[2]) then return {} end
return {subject, email, version}
`

func (r *redisRepo) SaveSubjectOobCode(ctx context.Context, code string, subject OOBSubject, request string) error {
	if strings.TrimSpace(code) == "" || !validOOBSubject(subject) || request != "EMAIL_SIGNIN" && request != "PASSWORD_RESET" {
		return domain.ErrInvalidArgument
	}
	key := oobKey(code)
	_, err := r.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.HSet(ctx, key, map[string]interface{}{"email": subject.Email, "userId": subject.UserID, "tokenVersion": subject.TokenVersion, "reqType": request, "expiresAt": time.Now().Add(15 * time.Minute).Unix()})
		pipe.Expire(ctx, key, 15*time.Minute)
		return nil
	})
	return err
}

func (r *redisRepo) ConsumeSubjectOobCode(ctx context.Context, code, request string) (OOBSubject, error) {
	if strings.TrimSpace(code) == "" || request != "EMAIL_SIGNIN" && request != "PASSWORD_RESET" {
		return OOBSubject{}, domain.ErrInvalidOob
	}
	values, err := r.client.Eval(ctx, consumeSubjectOobScript, []string{oobKey(code)}, request, time.Now().Unix()).StringSlice()
	if err != nil {
		return OOBSubject{}, err
	}
	if len(values) != 3 {
		return OOBSubject{}, domain.ErrInvalidOob
	}
	version, err := strconv.Atoi(values[2])
	subject := OOBSubject{UserID: values[0], Email: values[1], TokenVersion: version}
	if err != nil || strconv.Itoa(version) != values[2] || !validOOBSubject(subject) {
		return OOBSubject{}, domain.ErrInvalidOob
	}
	return subject, nil
}

func validOOBSubject(subject OOBSubject) bool {
	return canonicalUserIdentity(subject.UserID) && normalizeDirectoryEmail(subject.Email) == subject.Email && subject.Email != "" && subject.TokenVersion >= 0
}
