package repository

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
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

var errBackfillInterrupted = errors.New("backfill interrupted")

type interruptDirectoryPipelineHook struct {
	active      bool
	calls       int
	interruptAt int
}

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
