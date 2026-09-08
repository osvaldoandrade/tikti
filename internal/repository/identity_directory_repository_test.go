package repository

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func newIdentityDirectoryForTest(t *testing.T) (*redis.Client, IdentityDirectoryRepository) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client, NewIdentityDirectoryRepository(client)
}

func TestAuthenticationAttemptLimiterUsesOpaqueIndependentExpiringBuckets(t *testing.T) {
	client, repo := newIdentityDirectoryForTest(t)
	ctx := context.Background()
	const subject = "Sensitive.User@example.com"
	window := 2 * time.Minute

	for attempt := 1; attempt <= 3; attempt++ {
		allowed, err := repo.AllowAuthenticationAttempt(ctx, "password:email", subject, 2, window)
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		if allowed != (attempt <= 2) {
			t.Fatalf("attempt %d allowed=%v", attempt, allowed)
		}
	}
	for _, input := range []struct{ bucket, subject string }{
		{bucket: "password:ip", subject: subject},
		{bucket: "password:email", subject: "other@example.com"},
	} {
		allowed, err := repo.AllowAuthenticationAttempt(ctx, input.bucket, input.subject, 2, window)
		if err != nil || !allowed {
			t.Fatalf("independent bucket %+v allowed=%v err=%v", input, allowed, err)
		}
	}

	keys, err := client.Keys(ctx, authenticationAttemptPrefix+"*").Result()
	if err != nil || len(keys) != 3 {
		t.Fatalf("rate limit keys=%v err=%v", keys, err)
	}
	for _, key := range keys {
		if strings.Contains(strings.ToLower(key), "sensitive") || strings.Contains(strings.ToLower(key), "example.com") || strings.Contains(key, "password") {
			t.Fatalf("rate limit key exposes bucket or subject: %q", key)
		}
		ttl, ttlErr := client.PTTL(ctx, key).Result()
		if ttlErr != nil || ttl <= 0 || ttl > window {
			t.Fatalf("rate limit TTL for %q = %v, %v", key, ttl, ttlErr)
		}
	}
}

func TestAuthenticationAttemptLimiterDoesNotDependOnRedisScriptCache(t *testing.T) {
	client, repo := newIdentityDirectoryForTest(t)
	hook := &rejectEvalSHAHook{}
	client.AddHook(hook)

	allowed, err := repo.AllowAuthenticationAttempt(
		context.Background(), "saml:login:ip", "203.0.113.10", 10, time.Minute,
	)
	if err != nil || !allowed {
		t.Fatalf("authentication attempt without script cache allowed=%v err=%v", allowed, err)
	}
	if hook.calls != 0 {
		t.Fatalf("authentication attempt issued %d EVALSHA commands", hook.calls)
	}
}

func TestIdentityDirectoryUserIndexIsBoundedSafeAndNormalized(t *testing.T) {
	client, repo := newIdentityDirectoryForTest(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	user := &domain.User{
		Id: "user-1", Email: "admin@example.com", Password: "$2a$10$hash", Role: domain.RoleCompanyEmployee,
		Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, TokenVersion: 17,
		ExternalSubject: "must-never-leak", PasswordChangeRequired: true, CreatedAt: now,
	}
	created, err := repo.CreateDirectoryUser(context.Background(), user)
	if err != nil || created.ID != user.Id || created.Email != user.Email || !created.PasswordChangeRequired {
		t.Fatalf("create = %#v, %v", created, err)
	}
	encoded, _ := json.Marshal(created)
	for _, secret := range []string{"\"password\":", "tokenVersion", "externalSubject", "$2a$10$hash", "must-never-leak"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("safe projection leaked %q: %s", secret, encoded)
		}
	}
	if _, err = repo.CreateDirectoryUser(context.Background(), &domain.User{
		Id: "user-2", Email: "ADMIN@example.com", Password: "other-hash", Role: domain.RoleCompanyEmployee,
		Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: now,
	}); !errors.Is(err, domain.ErrEmailExists) {
		t.Fatalf("normalized duplicate = %v", err)
	}
	page, err := repo.ListDirectoryUsers(context.Background(), "admin@", "", 1)
	if err != nil || len(page.Users) != 1 || page.Users[0].ID != "user-1" || page.NextPageToken != "" {
		t.Fatalf("page = %#v, %v", page, err)
	}
	if count := client.HLen(context.Background(), membershipsKey("default")).Val(); count != 0 {
		t.Fatalf("directory creation wrote default membership: %d", count)
	}
}

func TestUpdateDirectoryUserRejectsStaleSecuritySnapshot(t *testing.T) {
	client, repo := newIdentityDirectoryForTest(t)
	ctx := context.Background()
	user := &domain.User{
		Id: "user-cas", Email: "cas@example.com", Password: "old-hash",
		Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive,
		AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now().UTC(),
	}
	if _, err := repo.CreateDirectoryUser(ctx, user); err != nil {
		t.Fatalf("create: %v", err)
	}

	stale := *user
	securityUpdate := *user
	securityUpdate.Status = domain.UserStatusSuspended
	securityUpdate.TokenVersion++
	if _, err := repo.UpdateDirectoryUser(ctx, &securityUpdate); err != nil {
		t.Fatalf("security update: %v", err)
	}
	if securityUpdate.Revision != 1 {
		t.Fatalf("security update revision = %d, want 1", securityUpdate.Revision)
	}

	stale.Password = "replacement-hash"
	stale.PasswordChangeRequired = false
	stale.TokenVersion++
	if _, err := repo.UpdateDirectoryUser(ctx, &stale); !errors.Is(err, domain.ErrVersionConflict) {
		t.Fatalf("stale password update error = %v, want ErrVersionConflict", err)
	}

	raw, err := client.HGet(ctx, usersHashV2, user.Id).Result()
	if err != nil {
		t.Fatalf("read stored user: %v", err)
	}
	var stored domain.User
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		t.Fatalf("decode stored user: %v", err)
	}
	if stored.Status != domain.UserStatusSuspended || stored.TokenVersion != 1 ||
		stored.Password != "old-hash" || stored.Revision != 1 {
		t.Fatalf("stale write reverted security state: %#v", stored)
	}
}

func TestTenantDirectoryPaginationNeverCarriesForeignPrincipalPII(t *testing.T) {
	_, repo := newIdentityDirectoryForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, user := range []*domain.User{
		{Id: "user-a", Email: "a-authorized@example.com", Password: "hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: now},
		{Id: "user-hidden", Email: "b-hidden@example.com", Password: "hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: now},
		{Id: "user-c", Email: "c-authorized@example.com", Password: "hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: now},
	} {
		if _, err := repo.CreateDirectoryUser(ctx, user); err != nil {
			t.Fatal(err)
		}
	}
	for _, userID := range []string{"user-a", "user-c"} {
		if _, _, err := repo.PutAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, userID, []string{"reader"}, ""); err != nil {
			t.Fatal(err)
		}
	}
	first, err := repo.ListTenantDirectoryUsers(ctx, "bereia", "", "", 1)
	if err != nil || len(first.Users) != 1 || first.Users[0].ID != "user-a" || first.NextPageToken == "" {
		t.Fatalf("first tenant page = %#v, %v", first, err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(first.NextPageToken)
	if err != nil || strings.Contains(string(raw), "b-hidden@example.com") || strings.Contains(string(raw), "user-hidden") {
		t.Fatalf("tenant cursor leaked a foreign principal: %q, %v", raw, err)
	}
	second, err := repo.ListTenantDirectoryUsers(ctx, "bereia", "", first.NextPageToken, 1)
	if err != nil || len(second.Users) != 1 || second.Users[0].ID != "user-c" || second.NextPageToken != "" {
		t.Fatalf("second tenant page = %#v, %v", second, err)
	}
}

func TestIdentityDirectoryAssignmentsUseETagAndRecomputeUnion(t *testing.T) {
	_, repo := newIdentityDirectoryForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, user := range []*domain.User{
		{Id: "user-1", Email: "one@example.com", Password: "hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: now},
		{Id: "user-2", Email: "two@example.com", Password: "hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: now},
	} {
		if _, err := repo.CreateDirectoryUser(ctx, user); err != nil {
			t.Fatal(err)
		}
	}
	group, err := repo.CreateGroup(ctx, "Engineering", "builders")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.CreateGroup(ctx, "engineering", "duplicate"); !errors.Is(err, domain.ErrGroupExists) {
		t.Fatalf("duplicate group name = %v", err)
	}
	group, changed, err := repo.PutGroupMember(ctx, group.ID, "user-1", "\"1\"")
	if err != nil || !changed || group.Version != 2 {
		t.Fatalf("member = %#v %v %v", group, changed, err)
	}
	detail, err := repo.GetGroupDetail(ctx, group.ID)
	if err != nil || detail.MemberCount != 1 || len(detail.Members) != 1 || detail.Members[0].ID != "user-1" {
		t.Fatalf("group detail = %#v, %v", detail, err)
	}
	detailJSON, _ := json.Marshal(detail)
	for _, forbidden := range []string{"\"password\":", "tokenVersion", "externalSubject", "hash"} {
		if strings.Contains(string(detailJSON), forbidden) {
			t.Fatalf("group member projection leaked %q: %s", forbidden, detailJSON)
		}
	}
	group, changed, err = repo.DeleteGroupMember(ctx, group.ID, "user-1", "\"2\"")
	if err != nil || !changed || group.Version != 3 || group.MemberCount != 0 {
		t.Fatalf("remove member = %#v %v %v", group, changed, err)
	}
	group, changed, err = repo.DeleteGroupMember(ctx, group.ID, "user-1", "\"1\"")
	if err != nil || changed || group.Version != 3 {
		t.Fatalf("idempotent member removal = %#v %v %v", group, changed, err)
	}
	group, changed, err = repo.PutGroupMember(ctx, group.ID, "user-1", "\"3\"")
	if err != nil || !changed || group.Version != 4 {
		t.Fatalf("restore member = %#v %v %v", group, changed, err)
	}

	direct, created, err := repo.PutAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, "user-1", []string{"reader"}, "")
	if err != nil || !created || direct.Version != 1 {
		t.Fatalf("direct = %#v %v %v", direct, created, err)
	}
	if _, _, err = repo.PutAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, "user-1", []string{"admin"}, "\"9\""); !errors.Is(err, domain.ErrVersionConflict) {
		t.Fatalf("stale update = %v", err)
	}
	updated, created, err := repo.PutAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, "user-1", []string{"admin"}, "\"1\"")
	if err != nil || created || updated.Version != 2 {
		t.Fatalf("update = %#v %v %v", updated, created, err)
	}
	if replay, _, err := repo.PutAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, "user-1", []string{"admin"}, ""); err != nil || replay.Version != 2 {
		t.Fatalf("idempotent replay = %#v %v", replay, err)
	}
	wildcard, _, err := repo.PutAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, "user-2", []string{"reader"}, "")
	if err != nil || wildcard.Version != 1 {
		t.Fatalf("wildcard seed = %#v %v", wildcard, err)
	}
	wildcard, _, err = repo.PutAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, "user-2", []string{"admin"}, "*")
	if err != nil || wildcard.Version != 2 {
		t.Fatalf("wildcard replacement = %#v %v", wildcard, err)
	}
	if deleted, deleteErr := repo.DeleteAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, "user-2", "*"); deleteErr != nil || !deleted {
		t.Fatalf("wildcard cleanup = %v %v", deleted, deleteErr)
	}
	groupGrant, _, err := repo.PutAccessAssignment(ctx, "bereia", domain.AccessPrincipalGroup, group.ID, []string{"reader"}, "")
	if err != nil {
		t.Fatal(err)
	}

	access, err := repo.GetEffectiveUserAccess(ctx, "user-1")
	if err != nil || len(access.Tenants) != 1 || !slices.Equal(access.Tenants[0].Roles, []string{"admin", "reader"}) || len(access.Tenants[0].Provenance) != 2 {
		t.Fatalf("union = %#v, %v", access, err)
	}
	if _, err = repo.DeleteAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, "user-1", "\"1\""); !errors.Is(err, domain.ErrVersionConflict) {
		t.Fatalf("stale delete = %v", err)
	}
	if deleted, err := repo.DeleteAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, "user-1", "\"2\""); err != nil || !deleted {
		t.Fatalf("delete = %v %v", deleted, err)
	}
	access, err = repo.GetEffectiveUserAccess(ctx, "user-1")
	if err != nil || !slices.Equal(access.Tenants[0].Roles, []string{"reader"}) || access.Tenants[0].Provenance[0].AssignmentVersion != groupGrant.Version {
		t.Fatalf("after revoke = %#v, %v", access, err)
	}
	disabled := domain.IdentityGroupStatusDisabled
	group, err = repo.PatchGroup(ctx, group.ID, domain.IdentityGroupPatchReq{Status: &disabled}, "\"4\"")
	if err != nil || group.Version != 5 {
		t.Fatalf("disable = %#v %v", group, err)
	}
	access, err = repo.GetEffectiveUserAccess(ctx, "user-1")
	if err != nil || len(access.Tenants) != 0 {
		t.Fatalf("disabled access = %#v, %v", access, err)
	}
	if deleted, deleteErr := repo.DeleteGroup(ctx, group.ID, "\"5\""); deleteErr != nil || !deleted {
		t.Fatalf("delete group = %v %v", deleted, deleteErr)
	}
	if deleted, deleteErr := repo.DeleteGroup(ctx, group.ID, "*"); deleteErr != nil || deleted {
		t.Fatalf("idempotent group delete = %v %v", deleted, deleteErr)
	}
	assignments, err := repo.ListAccessAssignments(ctx, "bereia", "", 50)
	if err != nil || len(assignments.Assignments) != 0 {
		t.Fatalf("group deletion left assignments = %#v, %v", assignments, err)
	}
}

func TestIdentityDirectoryBackfillReplaysLegacyAndV2Duplicates(t *testing.T) {
	client, repo := newIdentityDirectoryForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	user := domain.User{Id: "user-1", Email: "User@Example.com", Password: "hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, CreatedAt: now}
	userRaw, _ := json.Marshal(user)
	legacyMembership := domain.Membership{Id: "membership-1", TenantId: "bereia", UserId: user.Id, Roles: []string{"legacy-reader"}, CreatedAt: now}
	legacyMembershipRaw, _ := json.Marshal(legacyMembership)
	v2Membership := legacyMembership
	v2Membership.Roles = []string{"reader"}
	v2MembershipRaw, _ := json.Marshal(v2Membership)
	if err := client.HSet(ctx, legacyUsersHash, user.Email, userRaw).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.HSet(ctx, membershipsKey("bereia"), user.Id, legacyMembershipRaw).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.SAdd(ctx, membershipsByUserPrefix+user.Id, "bereia").Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.HSet(ctx, membershipV2Key("bereia"), user.Id, v2MembershipRaw).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.SAdd(ctx, membershipV2ByUserKey(user.Id), "bereia").Err(); err != nil {
		t.Fatal(err)
	}

	first, err := repo.Backfill(ctx)
	if err != nil || first.UsersIndexed != 1 || first.AssignmentsCopied != 1 {
		t.Fatalf("first = %#v, %v", first, err)
	}
	updated, _, err := repo.PutAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, user.Id, []string{"writer"}, `"1"`)
	if err != nil || updated.Version != 2 {
		t.Fatalf("canonical update = %#v, %v", updated, err)
	}
	second, err := repo.Backfill(ctx)
	if err != nil || second.UsersIndexed != 0 || second.AssignmentsCopied != 0 {
		t.Fatalf("replay = %#v, %v", second, err)
	}
	page, err := repo.ListAccessAssignments(ctx, "bereia", "", 50)
	if err != nil || len(page.Assignments) != 1 || page.Assignments[0].PrincipalID != user.Id || !slices.Equal(page.Assignments[0].Roles, []string{"writer"}) || page.Assignments[0].Version != 2 {
		t.Fatalf("assignments = %#v, %v", page, err)
	}
	if deleted, deleteErr := repo.DeleteAccessAssignment(ctx, "bereia", domain.AccessPrincipalUser, user.Id, `"2"`); deleteErr != nil || !deleted {
		t.Fatalf("canonical revoke = %v, %v", deleted, deleteErr)
	}
	if _, err = repo.Backfill(ctx); err != nil {
		t.Fatalf("replay after canonical revoke = %v", err)
	}
	page, err = repo.ListAccessAssignments(ctx, "bereia", "", 50)
	if err != nil || len(page.Assignments) != 0 {
		t.Fatalf("replay resurrected revoked access = %#v, %v", page, err)
	}
}

func TestIdentityDirectoryBackfillSkipsForeignSAMLMembershipWithoutDeletingLegacyData(t *testing.T) {
	client, repo := newIdentityDirectoryForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	homeTenantID := "bereia"
	user := domain.User{
		Id: "saml-user-1", Email: "saml-user@example.com", Role: domain.RoleCompanyEmployee,
		Status: domain.UserStatusActive, CreatedAt: now, AuthSource: domain.AuthSourceSAML,
		ExternalSubject: "saml-subject-1", CompanyId: &homeTenantID,
	}
	userRaw, _ := json.Marshal(user)
	if err := client.HSet(ctx, legacyUsersHash, user.Email, userRaw).Err(); err != nil {
		t.Fatal(err)
	}
	for _, tenantID := range []string{homeTenantID, "default"} {
		membership := domain.Membership{
			Id: "membership-" + tenantID, TenantId: tenantID, UserId: user.Id,
			Roles: []string{"reader"}, CreatedAt: now,
		}
		raw, _ := json.Marshal(membership)
		if err := client.HSet(ctx, membershipsKey(tenantID), user.Id, raw).Err(); err != nil {
			t.Fatal(err)
		}
	}

	result, err := repo.Backfill(ctx)
	if err != nil || result.UsersIndexed != 1 || result.AssignmentsCopied != 1 {
		t.Fatalf("backfill = %#v, %v", result, err)
	}
	home, err := repo.GetAccessAssignment(ctx, homeTenantID, domain.AccessPrincipalUser, user.Id)
	if err != nil || home == nil || !slices.Equal(home.Roles, []string{"reader"}) {
		t.Fatalf("home assignment = %#v, %v", home, err)
	}
	foreign, err := repo.GetAccessAssignment(ctx, "default", domain.AccessPrincipalUser, user.Id)
	if err != nil || foreign != nil {
		t.Fatalf("foreign assignment = %#v, %v", foreign, err)
	}
	if !client.HExists(ctx, membershipsKey("default"), user.Id).Val() {
		t.Fatal("backfill deleted the legacy foreign membership")
	}
}

func TestIdentityDirectoryBackfillResumesAfterInterruptedBatch(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	for index, email := range []string{"one@example.com", "two@example.com"} {
		userID := "user-" + string(rune('1'+index))
		user := domain.User{Id: userID, Email: email, Password: "hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: now}
		userRaw, _ := json.Marshal(user)
		membership := domain.Membership{Id: "membership-" + userID, TenantId: "bereia", UserId: userID, Roles: []string{"reader"}, CreatedAt: now}
		membershipRaw, _ := json.Marshal(membership)
		if err := client.HSet(ctx, legacyUsersHash, email, userRaw).Err(); err != nil {
			t.Fatal(err)
		}
		if err := client.HSet(ctx, membershipsKey("bereia"), userID, membershipRaw).Err(); err != nil {
			t.Fatal(err)
		}
	}
	hook := &interruptDirectoryPipelineHook{active: true, interruptAt: 2}
	client.AddHook(hook)
	repo := NewIdentityDirectoryRepository(client)
	if result, err := repo.Backfill(ctx); !errors.Is(err, errBackfillInterrupted) || result != nil {
		t.Fatalf("interrupted backfill = %#v, %v", result, err)
	}
	if marked := client.Exists(ctx, directoryBackfillMarker).Val(); marked != 0 {
		t.Fatalf("interrupted backfill wrote completion marker: %d", marked)
	}
	hook.active = false
	result, err := repo.Backfill(ctx)
	if err != nil || result.UsersIndexed != 2 || result.AssignmentsCopied != 2 {
		t.Fatalf("resumed backfill = %#v, %v", result, err)
	}
	page, err := repo.ListAccessAssignments(ctx, "bereia", "", 50)
	if err != nil || len(page.Assignments) != 2 || client.Get(ctx, directoryBackfillMarker).Val() != "v1" {
		t.Fatalf("resumed state = %#v, %v", page, err)
	}
}

func TestIdentityDirectoryBackfillHasSingleDistributedOwner(t *testing.T) {
	server := miniredis.RunT(t)
	ownerClient := redis.NewClient(&redis.Options{Addr: server.Addr()})
	contenderClient := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = ownerClient.Close()
		_ = contenderClient.Close()
	})
	ctx := context.Background()
	user := domain.User{
		Id: "user-lock", Email: "lock@example.com", Password: "hash",
		Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive,
		AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now().UTC(),
	}
	raw, _ := json.Marshal(user)
	if err := ownerClient.HSet(ctx, legacyUsersHash, user.Email, raw).Err(); err != nil {
		t.Fatal(err)
	}

	hook := &pauseFirstHScanHook{entered: make(chan struct{}), release: make(chan struct{})}
	ownerClient.AddHook(hook)
	ownerRepo := NewIdentityDirectoryRepository(ownerClient)
	contenderRepo := NewIdentityDirectoryRepository(contenderClient)
	ownerResult := make(chan error, 1)
	go func() {
		_, err := ownerRepo.Backfill(ctx)
		ownerResult <- err
	}()
	<-hook.entered

	if result, err := contenderRepo.Backfill(ctx); result != nil || !errors.Is(err, domain.ErrDirectoryBackfillInProgress) {
		t.Fatalf("concurrent contender = %#v, %v; want single-owner rejection", result, err)
	}
	close(hook.release)
	if err := <-ownerResult; err != nil {
		t.Fatalf("owner backfill: %v", err)
	}
	if result, err := contenderRepo.Backfill(ctx); err != nil || result == nil ||
		result.UsersIndexed != 0 || result.AssignmentsCopied != 0 {
		t.Fatalf("post-cutover replay = %#v, %v", result, err)
	}
}

func TestIdentityDirectoryBackfillDoesNotDependOnRedisScriptCache(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	user := domain.User{
		Id: "user-no-script-cache", Email: "no-script-cache@example.com", Password: "hash",
		Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive,
		AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now().UTC(),
	}
	raw, _ := json.Marshal(user)
	if err := client.HSet(ctx, legacyUsersHash, user.Email, raw).Err(); err != nil {
		t.Fatal(err)
	}
	hook := &rejectEvalSHAHook{}
	client.AddHook(hook)

	result, err := NewIdentityDirectoryRepository(client).Backfill(ctx)
	if err != nil || result == nil || result.UsersIndexed != 1 {
		t.Fatalf("backfill without script cache = %#v, %v", result, err)
	}
	if hook.calls != 0 {
		t.Fatalf("backfill issued %d EVALSHA commands", hook.calls)
	}
}

var errBackfillInterrupted = errors.New("backfill interrupted")

type interruptDirectoryPipelineHook struct {
	active      bool
	calls       int
	interruptAt int
}

type pauseFirstHScanHook struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

type rejectEvalSHAHook struct{ calls int }

func (h *rejectEvalSHAHook) BeforeProcess(ctx context.Context, command redis.Cmder) (context.Context, error) {
	if command.Name() == "evalsha" {
		h.calls++
		return ctx, errors.New("ERR NOSCRIPT No matching script. Please use EVAL")
	}
	return ctx, nil
}

func (*rejectEvalSHAHook) AfterProcess(context.Context, redis.Cmder) error { return nil }
func (*rejectEvalSHAHook) BeforeProcessPipeline(ctx context.Context, _ []redis.Cmder) (context.Context, error) {
	return ctx, nil
}
func (*rejectEvalSHAHook) AfterProcessPipeline(context.Context, []redis.Cmder) error { return nil }

func (h *pauseFirstHScanHook) BeforeProcess(ctx context.Context, command redis.Cmder) (context.Context, error) {
	if command.Name() == "hscan" {
		h.once.Do(func() {
			close(h.entered)
			<-h.release
		})
	}
	return ctx, nil
}

func (*pauseFirstHScanHook) AfterProcess(context.Context, redis.Cmder) error { return nil }
func (*pauseFirstHScanHook) BeforeProcessPipeline(ctx context.Context, _ []redis.Cmder) (context.Context, error) {
	return ctx, nil
}
func (*pauseFirstHScanHook) AfterProcessPipeline(context.Context, []redis.Cmder) error { return nil }

func (h *interruptDirectoryPipelineHook) BeforeProcess(ctx context.Context, _ redis.Cmder) (context.Context, error) {
	return ctx, nil
}
func (h *interruptDirectoryPipelineHook) AfterProcess(context.Context, redis.Cmder) error { return nil }
func (h *interruptDirectoryPipelineHook) BeforeProcessPipeline(ctx context.Context, _ []redis.Cmder) (context.Context, error) {
	if h.active {
		h.calls++
		if h.calls == h.interruptAt {
			return ctx, errBackfillInterrupted
		}
	}
	return ctx, nil
}
func (h *interruptDirectoryPipelineHook) AfterProcessPipeline(context.Context, []redis.Cmder) error {
	return nil
}
