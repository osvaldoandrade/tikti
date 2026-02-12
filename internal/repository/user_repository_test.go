package repository

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func newUserRepoForTest(t *testing.T) (*redis.Client, UserRepository) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, NewRedisRepo(rdb)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestNewRedisRepo(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	if repo == nil {
		t.Fatalf("expected repo")
	}
}

func TestUserRepo_CreateUser(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()
	r := repo.(*redisRepo)

	if err := r.CreateUser(ctx, &domain.User{Id: "u1"}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if err := r.CreateUser(ctx, &domain.User{Email: "u1@x.com"}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}

	u := &domain.User{Id: "u1", Email: "u1@x.com", Password: "hash"}
	if err := r.CreateUser(ctx, u); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if err := r.CreateUser(ctx, &domain.User{Id: "u2", Email: "u1@x.com", Password: "hash2"}); err != domain.ErrEmailExists {
		t.Fatalf("expected ErrEmailExists, got %v", err)
	}
}

func TestUserRepo_FindByEmail_NewLayoutAndLegacy(t *testing.T) {
	rdb, repo := newUserRepoForTest(t)
	ctx := context.Background()
	r := repo.(*redisRepo)

	got, err := r.FindByEmail(ctx, "")
	if err != nil || got != nil {
		t.Fatalf("expected nil,nil, got %v %+v", err, got)
	}

	if err := rdb.Set(ctx, userByEmailKeyNS+"u@x.com", "u1", 0).Err(); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := rdb.HSet(ctx, usersHashV2, "u1", "{").Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	if _, err := r.FindByEmail(ctx, "u@x.com"); err == nil {
		t.Fatalf("expected unmarshal error")
	}

	if err := rdb.HSet(ctx, usersHashV2, "u1", mustJSON(t, domain.User{Id: "u1", Email: "u@x.com"})).Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	if _, err := r.FindByEmail(ctx, "u@x.com"); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	if err := rdb.Del(ctx, userByEmailKeyNS+"u@x.com").Err(); err != nil {
		t.Fatalf("del index: %v", err)
	}
	if err := rdb.HDel(ctx, usersHashV2, "u1").Err(); err != nil {
		t.Fatalf("hdel: %v", err)
	}
	legacy := domain.User{Id: "u1", Email: "u@x.com", Password: "hash"}
	if err := rdb.HSet(ctx, legacyUsersHash, "u@x.com", mustJSON(t, legacy)).Err(); err != nil {
		t.Fatalf("hset legacy: %v", err)
	}
	got, err = r.FindByEmail(ctx, "u@x.com")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got == nil || got.Id != "u1" {
		t.Fatalf("unexpected user: %+v", got)
	}
}

func TestUserRepo_UpdateDeleteSetStatusIncrementTokenVersion(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()
	r := repo.(*redisRepo)

	if err := r.UpdateUser(ctx, &domain.User{Email: "x"}); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}

	u := &domain.User{Id: "u1", Email: "u1@x.com", Password: "hash", TokenVersion: -2}
	if err := r.CreateUser(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	u.Status = domain.UserStatusActive
	if err := r.UpdateUser(ctx, u); err != nil {
		t.Fatalf("update: %v", err)
	}

	setResp, err := r.SetStatus(ctx, "u1@x.com", domain.UserStatusSuspended)
	if err != nil {
		t.Fatalf("set status: %v", err)
	}
	if setResp.Status != domain.UserStatusSuspended {
		t.Fatalf("unexpected status: %s", setResp.Status)
	}
	if _, err := r.SetStatus(ctx, "missing@x.com", domain.UserStatusActive); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	ver, got, err := r.IncrementTokenVersion(ctx, "u1@x.com")
	if err != nil {
		t.Fatalf("increment token version: %v", err)
	}
	if ver != 1 || got.TokenVersion != 1 {
		t.Fatalf("unexpected token version: %d %+v", ver, got)
	}
	if _, _, err := r.IncrementTokenVersion(ctx, "missing@x.com"); err != domain.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	if err := r.DeleteByEmail(ctx, ""); err != nil {
		t.Fatalf("delete empty: %v", err)
	}
	if err := r.DeleteByEmail(ctx, "u1@x.com"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got, err := r.FindByEmail(ctx, "u1@x.com"); err != nil || got != nil {
		t.Fatalf("expected removed user, got err=%v user=%+v", err, got)
	}
}

func TestUserRepo_OobHelpersAndConsumption(t *testing.T) {
	rdb, repo := newUserRepoForTest(t)
	ctx := context.Background()
	r := repo.(*redisRepo)

	if got := oobKey("abc"); got != "oob:abc" {
		t.Fatalf("unexpected key: %s", got)
	}
	if got := coerceString("abc"); got != "abc" {
		t.Fatalf("unexpected string coercion: %s", got)
	}
	if got := coerceString([]byte("abc")); got != "abc" {
		t.Fatalf("unexpected bytes coercion: %s", got)
	}
	if got := coerceString(1); got != "" {
		t.Fatalf("unexpected coercion: %q", got)
	}

	if err := r.SaveOobCode(ctx, "", "u@x.com", "EMAIL_SIGNIN"); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if _, err := r.ConsumeOobCode(ctx, "", "EMAIL_SIGNIN"); err != domain.ErrInvalidOob {
		t.Fatalf("expected ErrInvalidOob, got %v", err)
	}

	if err := r.SaveOobCode(ctx, "code-1", "u@x.com", "EMAIL_SIGNIN"); err != nil {
		t.Fatalf("save oob: %v", err)
	}
	email, err := r.ConsumeOobCode(ctx, "code-1", "EMAIL_SIGNIN")
	if err != nil {
		t.Fatalf("consume oob: %v", err)
	}
	if email != "u@x.com" {
		t.Fatalf("unexpected email: %s", email)
	}
	if _, err := r.ConsumeOobCode(ctx, "code-1", "EMAIL_SIGNIN"); err != domain.ErrInvalidOob {
		t.Fatalf("expected consumed code to be invalid")
	}

	if err := r.SaveOobCode(ctx, "code-2", "u@x.com", "EMAIL_SIGNIN"); err != nil {
		t.Fatalf("save oob: %v", err)
	}
	if _, err := r.ConsumeOobCode(ctx, "code-2", "PASSWORD_RESET"); err != domain.ErrInvalidOob {
		t.Fatalf("expected reqType mismatch invalid, got %v", err)
	}

	legacyOK := legacyOobPayload{
		Email:     "legacy@x.com",
		ReqType:   "EMAIL_SIGNIN",
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}
	if err := rdb.HSet(ctx, legacyOobHash, "legacy-code", mustJSON(t, legacyOK)).Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	email, err = r.ConsumeOobCode(ctx, "legacy-code", "EMAIL_SIGNIN")
	if err != nil {
		t.Fatalf("expected legacy consume success, got %v", err)
	}
	if email != "legacy@x.com" {
		t.Fatalf("unexpected email: %s", email)
	}

	if err := rdb.HSet(ctx, legacyOobHash, "legacy-expired", mustJSON(t, legacyOobPayload{
		Email:     "x@x.com",
		ReqType:   "EMAIL_SIGNIN",
		ExpiresAt: time.Now().Add(-time.Minute).Unix(),
	})).Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	if _, err := r.ConsumeOobCode(ctx, "legacy-expired", "EMAIL_SIGNIN"); err != domain.ErrInvalidOob {
		t.Fatalf("expected expired invalid, got %v", err)
	}

	if err := rdb.HSet(ctx, legacyOobHash, "legacy-mismatch", mustJSON(t, legacyOobPayload{
		Email:   "x@x.com",
		ReqType: "PASSWORD_RESET",
	})).Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	if _, err := r.ConsumeOobCode(ctx, "legacy-mismatch", "EMAIL_SIGNIN"); err != domain.ErrInvalidOob {
		t.Fatalf("expected reqType mismatch invalid, got %v", err)
	}
}

func TestUserRepo_GetAllUsers(t *testing.T) {
	rdb, repo := newUserRepoForTest(t)
	ctx := context.Background()
	r := repo.(*redisRepo)

	if err := rdb.HSet(ctx, usersHashV2, "u1", mustJSON(t, domain.User{Id: "u1", Email: "u1@x.com", Password: "h"})).Err(); err != nil {
		t.Fatalf("hset: %v", err)
	}
	// duplicate email in legacy should be skipped.
	if err := rdb.HSet(ctx, legacyUsersHash, "u1@x.com", mustJSON(t, domain.User{Id: "u-legacy", Email: "u1@x.com", Password: "h"})).Err(); err != nil {
		t.Fatalf("hset legacy: %v", err)
	}
	if err := rdb.HSet(ctx, legacyUsersHash, "u2@x.com", mustJSON(t, domain.User{Id: "u2", Email: "u2@x.com", Password: "h"})).Err(); err != nil {
		t.Fatalf("hset legacy2: %v", err)
	}

	users, err := r.GetAllUsers(ctx)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d (%+v)", len(users), users)
	}
}

func TestUserRepo_CreateUser_RollbackWhenEmailIndexFails(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	observer := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = observer.Close() })

	setErr := errors.New("set-fail")
	rdb.AddHook(commandErrorHook{byName: map[string]error{"set": setErr}})

	r := NewRedisRepo(rdb).(*redisRepo)
	ctx := context.Background()
	err = r.CreateUser(ctx, &domain.User{
		Id:       "u1",
		Email:    "u1@x.com",
		Password: "hash",
	})
	if !errors.Is(err, setErr) {
		t.Fatalf("expected set error, got %v", err)
	}

	_, err = observer.HGet(ctx, usersHashV2, "u1").Result()
	if err != redis.Nil {
		t.Fatalf("expected user rollback from hash, got %v", err)
	}
}

func TestUserRepo_FindByEmail_IndexedLookupBranches(t *testing.T) {
	rdb, repo := newUserRepoForTest(t)
	ctx := context.Background()
	r := repo.(*redisRepo)

	if err := rdb.Set(ctx, userByEmailKeyNS+"u@x.com", "u1", 0).Err(); err != nil {
		t.Fatalf("set index: %v", err)
	}

	// Indexed user id exists, but user payload is missing.
	got, err := r.FindByEmail(ctx, "u@x.com")
	if err != nil || got != nil {
		t.Fatalf("expected nil,nil for missing payload, got err=%v user=%+v", err, got)
	}

	if err := rdb.HSet(ctx, usersHashV2, "u1", "").Err(); err != nil {
		t.Fatalf("hset empty: %v", err)
	}
	got, err = r.FindByEmail(ctx, "u@x.com")
	if err != nil || got != nil {
		t.Fatalf("expected nil,nil for empty payload, got err=%v user=%+v", err, got)
	}
}

func TestUserRepo_FindByEmail_IndexedLookupHGetError(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	t.Cleanup(mr.Close)

	seed := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = seed.Close() })
	ctx := context.Background()
	if err := seed.Set(ctx, userByEmailKeyNS+"u@x.com", "u1", 0).Err(); err != nil {
		t.Fatalf("set index: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	hgetErr := errors.New("hget-fail")
	rdb.AddHook(commandErrorHook{byName: map[string]error{"hget": hgetErr}})
	r := NewRedisRepo(rdb).(*redisRepo)

	if _, err := r.FindByEmail(ctx, "u@x.com"); !errors.Is(err, hgetErr) {
		t.Fatalf("expected hget error, got %v", err)
	}
}

func TestUserRepo_ConsumeLegacyOobCode_AdditionalBranches(t *testing.T) {
	rdb, repo := newUserRepoForTest(t)
	ctx := context.Background()
	r := repo.(*redisRepo)

	if _, err := r.consumeLegacyOobCode(ctx, "missing", "EMAIL_SIGNIN"); err != domain.ErrInvalidOob {
		t.Fatalf("expected ErrInvalidOob for missing code, got %v", err)
	}

	if err := rdb.HSet(ctx, legacyOobHash, "blank", " ").Err(); err != nil {
		t.Fatalf("hset blank: %v", err)
	}
	if _, err := r.consumeLegacyOobCode(ctx, "blank", "EMAIL_SIGNIN"); err != domain.ErrInvalidOob {
		t.Fatalf("expected ErrInvalidOob for blank payload, got %v", err)
	}

	if err := rdb.HSet(ctx, legacyOobHash, "invalid-json", "{").Err(); err != nil {
		t.Fatalf("hset invalid json: %v", err)
	}
	if _, err := r.consumeLegacyOobCode(ctx, "invalid-json", "EMAIL_SIGNIN"); err == nil {
		t.Fatalf("expected unmarshal error")
	}

	if err := rdb.HSet(ctx, legacyOobHash, "no-email", mustJSON(t, legacyOobPayload{
		Email:   " ",
		ReqType: "EMAIL_SIGNIN",
	})).Err(); err != nil {
		t.Fatalf("hset no-email: %v", err)
	}
	if _, err := r.consumeLegacyOobCode(ctx, "no-email", "EMAIL_SIGNIN"); err != domain.ErrInvalidOob {
		t.Fatalf("expected ErrInvalidOob for empty email, got %v", err)
	}
	if exists := rdb.HExists(ctx, legacyOobHash, "no-email").Val(); exists {
		t.Fatalf("expected no-email code to be deleted")
	}
}

func TestUserRepo_ConsumeLegacyOobCode_DeleteError(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	t.Cleanup(mr.Close)

	ctx := context.Background()
	seed := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = seed.Close() })
	if err := seed.HSet(ctx, legacyOobHash, "legacy-code", mustJSON(t, legacyOobPayload{
		Email:   "legacy@x.com",
		ReqType: "EMAIL_SIGNIN",
	})).Err(); err != nil {
		t.Fatalf("seed legacy code: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	delErr := errors.New("hdel-fail")
	rdb.AddHook(commandErrorHook{byName: map[string]error{"hdel": delErr}})
	r := NewRedisRepo(rdb).(*redisRepo)

	if _, err := r.consumeLegacyOobCode(ctx, "legacy-code", "EMAIL_SIGNIN"); !errors.Is(err, delErr) {
		t.Fatalf("expected hdel error, got %v", err)
	}
}
