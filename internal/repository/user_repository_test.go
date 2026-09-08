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
	if ver != 2 || got.TokenVersion != 2 {
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

func TestUserRepo_DeleteByEmailRemovesDirectoryRelationshipsAtomically(t *testing.T) {
	rdb, users := newUserRepoForTest(t)
	ctx := context.Background()
	directory := NewIdentityDirectoryRepository(rdb)
	user := &domain.User{
		Id: "user-delete", Email: "delete@example.com", Password: "hash",
		Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive,
		AuthSource: domain.AuthSourceSAML, ExternalSubject: "external-delete",
		CompanyId: testStringPointerRepository("bereia"), CreatedAt: time.Now().UTC(),
	}
	if err := users.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := rdb.Set(ctx, samlSubjectKey("bereia", user.ExternalSubject), user.Id, 0).Err(); err != nil {
		t.Fatal(err)
	}
	group, err := directory.CreateGroup(ctx, "Deletion contract", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = directory.PutGroupMember(ctx, group.ID, user.Id, IdentityETag(group.Version)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = directory.PutAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, user.Id, []string{"reader"}, ""); err != nil {
		t.Fatal(err)
	}

	if err = users.DeleteByEmail(ctx, user.Email); err != nil {
		t.Fatal(err)
	}
	if remaining, readErr := directory.GetDirectoryUser(ctx, user.Id); readErr != nil || remaining != nil {
		t.Fatalf("deleted directory user = %#v, %v", remaining, readErr)
	}
	detail, err := directory.GetGroupDetail(ctx, group.ID)
	if err != nil || detail.MemberCount != 0 || len(detail.Members) != 0 {
		t.Fatalf("group retained deleted user = %#v, %v", detail, err)
	}
	assignments, err := directory.ListAccessAssignments(ctx, "bereia", "", 50)
	if err != nil || len(assignments.Assignments) != 0 {
		t.Fatalf("direct assignment survived user deletion = %#v, %v", assignments, err)
	}
	for _, key := range []string{
		userGroupsKey(user.Id),
		principalTenantsKey(domain.AccessPrincipalUser, user.Id),
		samlSubjectKey("bereia", user.ExternalSubject),
	} {
		if exists := rdb.Exists(ctx, key).Val(); exists != 0 {
			t.Fatalf("deleted user relationship key %q still exists", key)
		}
	}
}

func testStringPointerRepository(value string) *string { return &value }

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
	rdb.AddHook(commandErrorHook{byName: map[string]error{"eval": setErr, "evalsha": setErr}})

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

func TestUpsertFromSAML_Create(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()

	u, created, err := repo.UpsertFromSAML(ctx, "tenant-1", "ext-sub-1", "alice@example.com", "Alice", []string{"ADMIN"}, domain.MergeStrategyEmail)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !created {
		t.Fatalf("expected created=true")
	}
	if u.Email != "alice@example.com" {
		t.Fatalf("unexpected email: %s", u.Email)
	}
	if u.AuthSource != domain.AuthSourceSAML {
		t.Fatalf("expected AuthSourceSAML, got %s", u.AuthSource)
	}
	if u.ExternalSubject != "ext-sub-1" {
		t.Fatalf("expected externalSubject=ext-sub-1, got %s", u.ExternalSubject)
	}
	if u.Role != domain.RoleCompanyAdmin {
		t.Fatalf("tenant SAML role escaped platform boundary: %s", u.Role)
	}
	if u.CompanyId == nil || *u.CompanyId != "tenant-1" {
		t.Fatalf("tenant SAML company = %#v", u.CompanyId)
	}
	if u.Id == "" {
		t.Fatalf("expected non-empty user ID")
	}
}

func TestUpsertFromSAML_UpdateSame(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()

	u1, created1, err := repo.UpsertFromSAML(ctx, "tenant-1", "ext-sub-1", "alice@example.com", "Alice", []string{"ADMIN"}, domain.MergeStrategyEmail)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !created1 {
		t.Fatalf("expected first call to create")
	}

	u2, created2, err := repo.UpsertFromSAML(ctx, "tenant-1", "ext-sub-1", "alice-new@example.com", "Alice New", []string{"COMPANY_ADMIN"}, domain.MergeStrategyEmail)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if created2 {
		t.Fatalf("expected second call to update, not create")
	}
	if u2.Id != u1.Id {
		t.Fatalf("expected same user ID, got %s vs %s", u1.Id, u2.Id)
	}
	if u2.Email != "alice-new@example.com" {
		t.Fatalf("expected updated email, got %s", u2.Email)
	}
	if u2.Role != "COMPANY_ADMIN" {
		t.Fatalf("expected updated role, got %s", u2.Role)
	}
}

func TestUpsertFromSAMLRoleChangeAdvancesTokenVersion(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()
	created, _, err := repo.UpsertFromSAML(
		ctx, "tenant-1", "role-change-subject", "role-change@example.com", "Role Change",
		[]string{"COMPANY_ADMIN"}, domain.MergeStrategyExternalSubject,
	)
	if err != nil || created.Role != domain.RoleCompanyAdmin || created.TokenVersion != 0 {
		t.Fatalf("created user=%#v err=%v", created, err)
	}
	downgraded, wasCreated, err := repo.UpsertFromSAML(
		ctx, "tenant-1", "role-change-subject", "role-change@example.com", "Role Change",
		[]string{"COMPANY_EMPLOYEE"}, domain.MergeStrategyExternalSubject,
	)
	if err != nil || wasCreated || downgraded.Role != domain.RoleCompanyEmployee || downgraded.TokenVersion != 1 {
		t.Fatalf("downgraded user=%#v created=%t err=%v", downgraded, wasCreated, err)
	}
}

func TestFederatedUpsertCannotOverwriteConcurrentTokenRevocation(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()
	created, _, err := repo.UpsertFromSAML(
		ctx, "tenant-1", "external-subject", "user@example.com", "User", nil, domain.MergeStrategyExternalSubject,
	)
	if err != nil {
		t.Fatal(err)
	}
	stale := created
	byID := repo.(UserIDRepository)
	version, revoked, err := byID.IncrementTokenVersionByID(ctx, created.Id)
	if err != nil || version != 1 || revoked.Revision <= stale.Revision {
		t.Fatalf("revocation version=%d user=%#v err=%v", version, revoked, err)
	}
	stale.Email = "stale@example.com"
	if err := repo.UpdateUser(ctx, &stale); !errors.Is(err, domain.ErrVersionConflict) {
		t.Fatalf("stale federated update=%v", err)
	}
	refreshed, wasCreated, err := repo.UpsertFromSAML(
		ctx, "tenant-1", "external-subject", "current@example.com", "User", nil, domain.MergeStrategyExternalSubject,
	)
	if err != nil || wasCreated || refreshed.TokenVersion != 1 || refreshed.Email != "current@example.com" {
		t.Fatalf("retry after revocation: user=%#v created=%t err=%v", refreshed, wasCreated, err)
	}
}

func TestUpsertFromSAML_ExistingAdminSurvivesMissingRoleAttribute(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()

	created, wasCreated, err := repo.UpsertFromSAML(
		ctx, "tenant-1", "ext-sub-1", "admin@example.com", "Admin",
		[]string{"ADMIN"}, domain.MergeStrategyEmail,
	)
	if err != nil || !wasCreated || created.Role != domain.RoleCompanyAdmin {
		t.Fatalf("seed tenant admin: user=%#v created=%t err=%v", created, wasCreated, err)
	}

	updated, wasCreated, err := repo.UpsertFromSAML(
		ctx, "tenant-1", "ext-sub-1", "admin@example.com", "Admin",
		nil, domain.MergeStrategyEmail,
	)
	if err != nil || wasCreated {
		t.Fatalf("refresh tenant admin: user=%#v created=%t err=%v", updated, wasCreated, err)
	}
	if updated.Role != domain.RoleCompanyAdmin {
		t.Fatalf("missing optional SAML roles erased tenant authority: %s", updated.Role)
	}
}

func TestUpsertFromSAML_RecoversPriorDemotionFromExactAdminMembership(t *testing.T) {
	rdb, repo := newUserRepoForTest(t)
	ctx := context.Background()
	tenantID := "tenant-1"

	created, wasCreated, err := repo.UpsertFromSAML(
		ctx, tenantID, "ext-sub-1", "admin@example.com", "Admin",
		[]string{"ADMIN"}, domain.MergeStrategyEmail,
	)
	if err != nil || !wasCreated || created.Role != domain.RoleCompanyAdmin {
		t.Fatalf("seed tenant admin: user=%#v created=%t err=%v", created, wasCreated, err)
	}
	created.Role = domain.RoleCompanyEmployee
	if err := repo.UpdateUser(ctx, &created); err != nil {
		t.Fatalf("persist prior regression: %v", err)
	}
	if err := NewMembershipRepo(rdb).Create(ctx, &domain.Membership{
		Id: "membership-admin", TenantId: tenantID, UserId: created.Id,
		Roles: []string{"ADMIN"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create exact admin membership: %v", err)
	}

	recovered, wasCreated, err := repo.UpsertFromSAML(
		ctx, tenantID, "ext-sub-1", "admin@example.com", "Admin",
		nil, domain.MergeStrategyEmail,
	)
	if err != nil || wasCreated || recovered.Role != domain.RoleCompanyAdmin {
		t.Fatalf("recover tenant admin: user=%#v created=%t err=%v", recovered, wasCreated, err)
	}
}

func TestUpsertFromSAML_ExplicitEmployeeRoleOverridesAdminMembership(t *testing.T) {
	rdb, repo := newUserRepoForTest(t)
	ctx := context.Background()
	tenantID := "tenant-1"

	created, _, err := repo.UpsertFromSAML(
		ctx, tenantID, "ext-sub-1", "admin@example.com", "Admin",
		nil, domain.MergeStrategyEmail,
	)
	if err != nil {
		t.Fatalf("seed SAML user: %v", err)
	}
	if err := NewMembershipRepo(rdb).Create(ctx, &domain.Membership{
		Id: "membership-admin", TenantId: tenantID, UserId: created.Id,
		Roles: []string{"ADMIN"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create exact admin membership: %v", err)
	}

	updated, _, err := repo.UpsertFromSAML(
		ctx, tenantID, "ext-sub-1", "admin@example.com", "Admin",
		[]string{"COMPANY_EMPLOYEE"}, domain.MergeStrategyEmail,
	)
	if err != nil || updated.Role != domain.RoleCompanyEmployee {
		t.Fatalf("explicit employee assertion was not authoritative: user=%#v err=%v", updated, err)
	}
}

func TestUpsertFromSAML_DoesNotRecoverFromUnilateralAdminMembership(t *testing.T) {
	rdb, repo := newUserRepoForTest(t)
	ctx := context.Background()
	tenantID := "tenant-1"

	created, _, err := repo.UpsertFromSAML(
		ctx, tenantID, "ext-sub-1", "admin@example.com", "Admin",
		nil, domain.MergeStrategyEmail,
	)
	if err != nil {
		t.Fatalf("seed SAML user: %v", err)
	}
	unilateral := domain.Membership{
		Id: "membership-admin", TenantId: tenantID, UserId: created.Id,
		Roles: []string{"ADMIN"}, CreatedAt: time.Now(),
	}
	if err := rdb.HSet(ctx, membershipsKey(tenantID), created.Id, mustJSON(t, unilateral)).Err(); err != nil {
		t.Fatalf("seed unilateral membership: %v", err)
	}

	updated, _, err := repo.UpsertFromSAML(
		ctx, tenantID, "ext-sub-1", "admin@example.com", "Admin",
		nil, domain.MergeStrategyEmail,
	)
	if err != nil || updated.Role != domain.RoleCompanyEmployee {
		t.Fatalf("unilateral membership elevated SAML user: user=%#v err=%v", updated, err)
	}
}

func TestUpsertFromSAML_EmailStrategyCannotTakeOverPasswordUser(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()

	// Create a password user first.
	pwUser := &domain.User{
		Id:         "pw-user-1",
		Email:      "bob@example.com",
		Password:   "hashed-password",
		Role:       domain.RoleCompanyEmployee,
		Status:     domain.UserStatusActive,
		AuthSource: domain.AuthSourcePassword,
		CreatedAt:  time.Now(),
	}
	pwTenant := "tenant-1"
	pwUser.CompanyId = &pwTenant
	if err := repo.CreateUser(ctx, pwUser); err != nil {
		t.Fatalf("create password user: %v", err)
	}

	// The legacy email strategy is inert: an assertion creates an isolated
	// tenant-local subject and cannot take over the password account.
	u, created, err := repo.UpsertFromSAML(ctx, "tenant-1", "ext-sub-bob", "bob@example.com", "Bob", []string{"ADMIN"}, domain.MergeStrategyEmail)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if !created {
		t.Fatalf("expected isolated SAML principal")
	}
	if u.Id == "pw-user-1" {
		t.Fatalf("SAML assertion took over password subject")
	}
	if u.AuthSource != domain.AuthSourceSAML {
		t.Fatalf("expected AuthSourceSAML after merge, got %s", u.AuthSource)
	}
	if u.ExternalSubject != "ext-sub-bob" {
		t.Fatalf("expected externalSubject set after merge, got %s", u.ExternalSubject)
	}
	stored, findErr := repo.FindByEmail(ctx, pwUser.Email)
	if findErr != nil || stored == nil || stored.Id != pwUser.Id || stored.AuthSource != domain.AuthSourcePassword || stored.Password != pwUser.Password {
		t.Fatalf("password principal changed: user=%#v err=%v", stored, findErr)
	}
}

func TestUpsertFromSAML_LegacyAdminEmailDoesNotTransferAuthority(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()
	tenantID := "tenant-1"

	legacyAdmin := &domain.User{
		Id: "legacy-admin", Email: "legacy-admin@example.com", Password: "hashed-password",
		Role: domain.RoleAdmin, Status: domain.UserStatusActive,
		AuthSource: domain.AuthSourcePassword, CompanyId: &tenantID, CreatedAt: time.Now(),
	}
	if err := repo.CreateUser(ctx, legacyAdmin); err != nil {
		t.Fatalf("create legacy admin: %v", err)
	}

	federated, created, err := repo.UpsertFromSAML(
		ctx, tenantID, "ext-legacy-admin", legacyAdmin.Email, "Legacy Admin",
		nil, domain.MergeStrategyEmail,
	)
	if err != nil || !created {
		t.Fatalf("isolate legacy admin email: user=%#v created=%t err=%v", federated, created, err)
	}
	if federated.Id == legacyAdmin.Id || federated.Role != domain.RoleCompanyEmployee || federated.AuthSource != domain.AuthSourceSAML {
		t.Fatalf("legacy authority transferred to assertion: %#v", federated)
	}
	stored, findErr := repo.FindByEmail(ctx, legacyAdmin.Email)
	if findErr != nil || stored == nil || stored.Id != legacyAdmin.Id || stored.Role != domain.RoleAdmin || stored.AuthSource != domain.AuthSourcePassword {
		t.Fatalf("legacy password principal changed: user=%#v err=%v", stored, findErr)
	}
}

func TestUpsertFromSAML_NoMergeCrossTenant(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()

	// Create user in tenant-1.
	u1, created1, err := repo.UpsertFromSAML(ctx, "tenant-1", "ext-sub-1", "carol@example.com", "Carol", nil, domain.MergeStrategyEmail)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !created1 {
		t.Fatalf("expected first call to create")
	}

	// Same external subject but different tenant creates a new user.
	u2, created2, err := repo.UpsertFromSAML(ctx, "tenant-2", "ext-sub-1", "carol2@example.com", "Carol 2", nil, domain.MergeStrategyEmail)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if !created2 {
		t.Fatalf("expected second call to create (different tenant)")
	}
	if u1.Id == u2.Id {
		t.Fatalf("expected distinct user IDs for different tenants")
	}
}

func TestExistingPasswordFlow_Unaffected(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()

	// Create a standard password user.
	pwUser := &domain.User{
		Id:        "pw-user-2",
		Email:     "dave@example.com",
		Password:  "hashed-password",
		Role:      domain.RoleCompanyEmployee,
		Status:    domain.UserStatusActive,
		CreatedAt: time.Now(),
	}
	if err := repo.CreateUser(ctx, pwUser); err != nil {
		t.Fatalf("create: %v", err)
	}

	// FindByEmail still works for password users.
	found, err := repo.FindByEmail(ctx, "dave@example.com")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if found == nil {
		t.Fatalf("expected to find password user")
	}
	if found.Id != "pw-user-2" {
		t.Fatalf("unexpected user id: %s", found.Id)
	}

	// AuthSource defaults to empty string which is equivalent to password.
	if found.AuthSource != "" && found.AuthSource != domain.AuthSourcePassword {
		t.Fatalf("expected default auth source (password or empty), got %s", found.AuthSource)
	}

	// Update and status operations still work.
	pwUser.Status = domain.UserStatusSuspended
	if err := repo.UpdateUser(ctx, pwUser); err != nil {
		t.Fatalf("update: %v", err)
	}

	updated, err := repo.FindByEmail(ctx, "dave@example.com")
	if err != nil {
		t.Fatalf("find after update: %v", err)
	}
	if updated.Status != domain.UserStatusSuspended {
		t.Fatalf("expected suspended status, got %s", updated.Status)
	}
}

func TestMerge_Email_ValueRemainsSubjectOnly(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()

	// Seed a password-based user.
	pwUser := &domain.User{
		Id:         "pw-merge-1",
		Email:      "merge@example.com",
		Password:   "hashed",
		Role:       domain.RoleCompanyEmployee,
		Status:     domain.UserStatusActive,
		AuthSource: domain.AuthSourcePassword,
		CreatedAt:  time.Now(),
	}
	pwTenant := "t1"
	pwUser.CompanyId = &pwTenant
	if err := repo.CreateUser(ctx, pwUser); err != nil {
		t.Fatalf("create password user: %v", err)
	}

	// Even the legacy email value resolves only by external subject.
	u, created, err := repo.UpsertFromSAML(ctx, "t1", "saml-sub-1", "merge@example.com", "Merge User", []string{"ADMIN"}, domain.MergeStrategyEmail)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if !created || u.Id == pwUser.Id {
		t.Fatalf("password subject was merged: created=%t id=%s", created, u.Id)
	}
	if u.AuthSource != domain.AuthSourceSAML {
		t.Fatalf("authSource should flip to saml, got %s", u.AuthSource)
	}
	if u.Password != "" || u.PasswordChangeRequired {
		t.Fatalf("SAML merge retained password credential: password=%q temporary=%t", u.Password, u.PasswordChangeRequired)
	}
	if u.TokenVersion != 0 {
		t.Fatalf("new federated tokenVersion = %d, want 0", u.TokenVersion)
	}
	stored, err := repo.FindByEmail(ctx, "merge@example.com")
	if err != nil || stored == nil || stored.Id != pwUser.Id || stored.Password != "hashed" || stored.AuthSource != domain.AuthSourcePassword {
		t.Fatalf("password principal changed: %#v, %v", stored, err)
	}
	if u.ExternalSubject != "saml-sub-1" {
		t.Fatalf("externalSubject should be set, got %s", u.ExternalSubject)
	}
	if u.Role != domain.RoleCompanyAdmin {
		t.Fatalf("role should be bounded to COMPANY_ADMIN, got %s", u.Role)
	}
}

func TestMerge_None_CreatesTenantLocalPrincipalWithoutClaimingDirectoryEmail(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()

	// Seed a password-based user.
	pwUser := &domain.User{
		Id:         "pw-dup-1",
		Email:      "dup@example.com",
		Password:   "hashed",
		Role:       domain.RoleCompanyEmployee,
		Status:     domain.UserStatusActive,
		AuthSource: domain.AuthSourcePassword,
		CreatedAt:  time.Now(),
	}
	pwTenant := "t1"
	pwUser.CompanyId = &pwTenant
	if err := repo.CreateUser(ctx, pwUser); err != nil {
		t.Fatalf("create password user: %v", err)
	}

	// A tenant-controlled assertion may create a tenant-local principal, but it
	// cannot replace or reserve the reusable global email identity.
	federated, created, err := repo.UpsertFromSAML(ctx, "t1", "saml-sub-dup", "DUP@example.com", "Dup User", []string{"ADMIN"}, domain.MergeStrategyNone)
	if err != nil || !created || federated.Id == pwUser.Id {
		t.Fatalf("tenant-local identity created=%t user=%#v error=%v", created, federated, err)
	}
	stored, findErr := repo.FindByEmail(ctx, "dup@example.com")
	if findErr != nil || stored.Id != "pw-dup-1" || stored.AuthSource != domain.AuthSourcePassword {
		t.Fatalf("canonical identity changed: user=%#v error=%v", stored, findErr)
	}
	byID, ok := repo.(UserIDRepository)
	if !ok {
		t.Fatal("subject-based repository unavailable")
	}
	resolved, findErr := byID.FindByID(ctx, federated.Id)
	if findErr != nil || resolved == nil || resolved.CompanyId == nil || *resolved.CompanyId != "t1" {
		t.Fatalf("tenant-local principal = %#v, %v", resolved, findErr)
	}
}

func TestMerge_ExternalSubject_Matches(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()

	// Create a SAML user first via email strategy.
	u1, created1, err := repo.UpsertFromSAML(ctx, "t1", "ext-prior", "prior@example.com", "Prior", []string{"ADMIN"}, domain.MergeStrategyEmail)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !created1 {
		t.Fatalf("expected first call to create")
	}

	// Second call with externalSubject strategy and same (tid, externalSubject)
	// should match via externalSubject (Case 1) and update.
	u2, created2, err := repo.UpsertFromSAML(ctx, "t1", "ext-prior", "prior-new@example.com", "Prior Updated", []string{"COMPANY_ADMIN"}, domain.MergeStrategyExternalSubject)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if created2 {
		t.Fatalf("expected update (created=false) when externalSubject matches")
	}
	if u2.Id != u1.Id {
		t.Fatalf("expected same user ID, got %s vs %s", u1.Id, u2.Id)
	}
	if u2.Email != "prior-new@example.com" {
		t.Fatalf("expected updated email, got %s", u2.Email)
	}
}

func TestMerge_EmailCannotReuseExistingSubject(t *testing.T) {
	_, repo := newUserRepoForTest(t)
	ctx := context.Background()

	// Seed a password user.
	pwUser := &domain.User{
		Id:         "preserve-sub-1",
		Email:      "preserve@example.com",
		Password:   "hashed",
		Role:       domain.RoleCompanyAdmin,
		Status:     domain.UserStatusActive,
		AuthSource: domain.AuthSourcePassword,
		CreatedAt:  time.Now(),
	}
	pwTenant := "t1"
	pwUser.CompanyId = &pwTenant
	if err := repo.CreateUser(ctx, pwUser); err != nil {
		t.Fatalf("create password user: %v", err)
	}

	// The asserted email must not reuse the existing sub (Id).
	u, created, err := repo.UpsertFromSAML(ctx, "t1", "ext-preserve", "preserve@example.com", "Preserve", []string{"ADMIN"}, domain.MergeStrategyEmail)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if !created || u.Id == "preserve-sub-1" {
		t.Fatalf("assertion reused password sub: created=%t id=%s", created, u.Id)
	}
}
