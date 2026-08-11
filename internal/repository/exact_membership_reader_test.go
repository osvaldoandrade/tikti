package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func newExactMembershipReaderForTest(t *testing.T) (*redis.Client, ExactMembershipReader, MembershipRepository) {
	t.Helper()
	client, memberships := newMembershipRepoForTest(t)
	tenants := NewTenantRepo(client).(ExactTenantRepository)
	users := NewRedisRepo(client).(ExactUserRepository)
	return client, NewExactMembershipReader(client, tenants, users), memberships
}

func seedExactTenant(t *testing.T, client *redis.Client, tenantID string) {
	t.Helper()
	tenant := domain.Tenant{Id: tenantID, Slug: tenantID, Name: "Tenant " + tenantID, Status: domain.TenantStatusDisabled, CreatedAt: exactIdentityTime}
	if err := client.HSet(context.Background(), tenantsHash, tenantID, mustJSON(t, tenant)).Err(); err != nil {
		t.Fatal(err)
	}
}

func seedExactUser(t *testing.T, client *redis.Client, userID, email string) {
	t.Helper()
	company := "private-company-canary"
	user := domain.User{
		Id: userID, Email: email, Password: "private-hash-canary", CompanyId: &company,
		Role: domain.RoleAdmin, Status: domain.UserStatusSuspended, AuthSource: domain.AuthSourcePassword, CreatedAt: exactIdentityTime,
	}
	ctx := context.Background()
	if err := client.HSet(ctx, usersHashV2, userID, mustJSON(t, user)).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.Set(ctx, userByEmailKeyNS+email, userID, 0).Err(); err != nil {
		t.Fatal(err)
	}
}

func TestExactMembershipReader_ComposesRequestedPairWithoutBleed(t *testing.T) {
	client, reader, memberships := newExactMembershipReaderForTest(t)
	ctx := context.Background()
	seedExactTenant(t, client, "bereia")
	seedExactTenant(t, client, "storifly")
	seedExactUser(t, client, "user-1", "Case@Example.COM")
	for _, membership := range []*domain.Membership{
		{Id: "membership-bereia", TenantId: "bereia", UserId: "user-1", Roles: []string{"writer", "reader"}, CreatedAt: exactIdentityTime},
		{Id: "membership-storifly", TenantId: "storifly", UserId: "user-1", Roles: []string{"storifly-admin"}, CreatedAt: exactIdentityTime},
	} {
		if err := memberships.Create(ctx, membership); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.HSet(ctx, membershipsKey("storifly"), "user-1", "{").Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.Set(ctx, rolesKey("bereia"), "role definitions must not be read", 0).Err(); err != nil {
		t.Fatal(err)
	}
	stored, _ := client.HGet(ctx, membershipsKey("bereia"), "user-1").Result()
	got, err := reader.GetExact(ctx, "bereia", "user-1")
	if err != nil || got == nil || got.Id != "membership-bereia" || got.TenantId != "bereia" || got.UserId != "user-1" {
		t.Fatalf("exact membership = %+v, %v", got, err)
	}
	if strings.Join(got.Roles, ",") != "reader,writer" || got.User.Status != domain.UserStatusSuspended {
		t.Fatalf("unexpected composed values: %+v", got)
	}
	projection, _ := json.Marshal(got)
	for _, secret := range []string{"private-hash-canary", "private-company-canary", `"password":`, `"role":`, "companyId", "permissions"} {
		if strings.Contains(string(projection), secret) {
			t.Fatalf("unsafe projection contains %q: %s", secret, projection)
		}
	}
	after, _ := client.HGet(ctx, membershipsKey("bereia"), "user-1").Result()
	if after != stored {
		t.Fatal("exact read mutated membership storage")
	}
	if other, err := reader.GetExact(ctx, "storifly", "user-1"); other != nil || !errors.Is(err, errStoredMembershipReadContract) {
		t.Fatalf("corrupt other tenant = %+v, %v", other, err)
	}
}

func TestExactMembershipReader_LegacyNullRolesAreZeroPrivilege(t *testing.T) {
	client, reader, _ := newExactMembershipReaderForTest(t)
	ctx := context.Background()
	seedExactTenant(t, client, "bereia")
	seedExactUser(t, client, "user-1", "user@example.com")
	membership := domain.Membership{Id: "membership-1", TenantId: "bereia", UserId: "user-1", Roles: nil, CreatedAt: exactIdentityTime}
	raw := mustJSON(t, membership)
	if !strings.Contains(raw, `"roles":null`) {
		t.Fatalf("fixture does not contain null roles: %s", raw)
	}
	if err := client.HSet(ctx, membershipsKey("bereia"), "user-1", raw).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.SAdd(ctx, membershipsByUserPrefix+"user-1", "bereia").Err(); err != nil {
		t.Fatal(err)
	}
	got, err := reader.GetExact(ctx, "bereia", "user-1")
	if err != nil || got == nil || got.Roles == nil || len(got.Roles) != 0 {
		t.Fatalf("legacy null roles = %+v, %v", got, err)
	}
	encoded, _ := json.Marshal(got)
	if !strings.Contains(string(encoded), `"roles":[]`) {
		t.Fatalf("zero-privilege projection = %s", encoded)
	}
	stored, _ := client.HGet(ctx, membershipsKey("bereia"), "user-1").Result()
	if stored != raw {
		t.Fatal("legacy roles were repaired in storage")
	}
}

func TestExactMembershipReader_MissingAndBilateralIndex(t *testing.T) {
	client, reader, _ := newExactMembershipReaderForTest(t)
	ctx := context.Background()
	missing, err := reader.GetExact(ctx, "bereia", "user-1")
	if err != nil || missing != nil {
		t.Fatalf("missing = %+v, %v", missing, err)
	}
	valid := domain.Membership{Id: "membership-1", TenantId: "bereia", UserId: "user-1", Roles: []string{}, CreatedAt: exactIdentityTime}
	if err := client.HSet(ctx, membershipsKey("bereia"), "user-1", mustJSON(t, valid)).Err(); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.GetExact(ctx, "bereia", "user-1"); got != nil || !errors.Is(err, errStoredMembershipReadContract) {
		t.Fatalf("forward orphan = %+v, %v", got, err)
	}
	if err := client.HDel(ctx, membershipsKey("bereia"), "user-1").Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.SAdd(ctx, membershipsByUserPrefix+"user-1", "bereia").Err(); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.GetExact(ctx, "bereia", "user-1"); got != nil || !errors.Is(err, errStoredMembershipReadContract) {
		t.Fatalf("reverse orphan = %+v, %v", got, err)
	}
}

func TestExactMembershipReader_RejectsStoredContractViolations(t *testing.T) {
	base := domain.Membership{Id: "membership-1", TenantId: "bereia", UserId: "user-1", Roles: []string{"reader"}, CreatedAt: exactIdentityTime}
	baseRaw := mustJSON(t, base)
	encode := func(change func(*domain.Membership)) string {
		copy := base
		change(&copy)
		return mustJSON(t, copy)
	}
	roles501 := make([]string, 501)
	for index := range roles501 {
		roles501[index] = "role" + strings.Repeat("x", index/100) + string(rune('A'+index%26)) + string(rune('0'+index%10))
	}
	tests := []struct{ name, raw string }{
		{"empty", ""}, {"malformed", "{"}, {"array", "[]"},
		{"unknown field", strings.Replace(baseRaw, "}", `,"secret":true}`, 1)},
		{"alias", strings.Replace(baseRaw, `"tenantId"`, `"TenantId"`, 1)},
		{"duplicate", strings.Replace(baseRaw, "{", `{"id":"membership-1",`, 1)},
		{"missing roles", strings.Replace(baseRaw, `,"roles":["reader"]`, "", 1)},
		{"null id", strings.Replace(baseRaw, `"id":"membership-1"`, `"id":null`, 1)},
		{"tenant mismatch", encode(func(value *domain.Membership) { value.TenantId = "storifly" })},
		{"user mismatch", encode(func(value *domain.Membership) { value.UserId = "user-2" })},
		{"empty id", encode(func(value *domain.Membership) { value.Id = "" })},
		{"zero timestamp", encode(func(value *domain.Membership) { value.CreatedAt = time.Time{} })},
		{"unsafe role", encode(func(value *domain.Membership) { value.Roles = []string{"-reader"} })},
		{"duplicate role", encode(func(value *domain.Membership) { value.Roles = []string{"reader", "reader"} })},
		{"role limit", encode(func(value *domain.Membership) { value.Roles = roles501 })},
		{"invalid utf8", strings.Replace(baseRaw, "reader", string([]byte{0xff}), 1)},
		{"invalid surrogate", strings.Replace(baseRaw, `"reader"`, `"\ud800"`, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, reader, _ := newExactMembershipReaderForTest(t)
			ctx := context.Background()
			seedExactTenant(t, client, "bereia")
			seedExactUser(t, client, "user-1", "user@example.com")
			if err := client.HSet(ctx, membershipsKey("bereia"), "user-1", test.raw).Err(); err != nil {
				t.Fatal(err)
			}
			if err := client.SAdd(ctx, membershipsByUserPrefix+"user-1", "bereia").Err(); err != nil {
				t.Fatal(err)
			}
			got, err := reader.GetExact(ctx, "bereia", "user-1")
			if got != nil || !errors.Is(err, errStoredMembershipReadContract) || strings.Contains(err.Error(), "reader") {
				t.Fatalf("result = %+v, %v", got, err)
			}
		})
	}
}

func TestExactMembershipReader_RequiresExactTenantAndUser(t *testing.T) {
	client, reader, _ := newExactMembershipReaderForTest(t)
	ctx := context.Background()
	membership := domain.Membership{Id: "membership-1", TenantId: "bereia", UserId: "user-1", Roles: []string{}, CreatedAt: exactIdentityTime}
	if err := client.HSet(ctx, membershipsKey("bereia"), "user-1", mustJSON(t, membership)).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.SAdd(ctx, membershipsByUserPrefix+"user-1", "bereia").Err(); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.GetExact(ctx, "bereia", "user-1"); got != nil || !errors.Is(err, errStoredMembershipReadContract) {
		t.Fatalf("missing tenant = %+v, %v", got, err)
	}
	seedExactTenant(t, client, "bereia")
	if got, err := reader.GetExact(ctx, "bereia", "user-1"); got != nil || !errors.Is(err, errStoredMembershipReadContract) {
		t.Fatalf("missing user = %+v, %v", got, err)
	}
	seedExactUser(t, client, "user-1", "user@example.com")
	if err := client.Set(ctx, userByEmailKeyNS+"user@example.com", "other", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.GetExact(ctx, "bereia", "user-1"); got != nil || !errors.Is(err, errStoredMembershipReadContract) {
		t.Fatalf("corrupt user index = %+v, %v", got, err)
	}
}

func TestExactMembershipReader_InputAndRedisErrors(t *testing.T) {
	client, reader, _ := newExactMembershipReaderForTest(t)
	if _, err := reader.GetExact(context.Background(), "Bereia", "user-1"); !errors.Is(err, domain.ErrInvalidTenant) {
		t.Fatalf("tenant input error = %v", err)
	}
	if _, err := reader.GetExact(context.Background(), "bereia", "user/1"); !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("user input error = %v", err)
	}
	want := errors.New("redis unavailable")
	client.AddHook(commandErrorHook{byName: map[string]error{"hget": want}})
	if got, err := reader.GetExact(context.Background(), "bereia", "user-1"); got != nil || !errors.Is(err, errStoredMembershipReadContract) || strings.Contains(err.Error(), want.Error()) {
		t.Fatalf("HGET error = %+v, %v", got, err)
	}
	var nilReader *exactMembershipReader
	if got, err := nilReader.GetExact(context.Background(), "bereia", "user-1"); got != nil || !errors.Is(err, errStoredMembershipReadContract) {
		t.Fatalf("nil reader = %+v, %v", got, err)
	}
}

func TestExactMembershipReader_ReverseIndexRedisError(t *testing.T) {
	client, reader, _ := newExactMembershipReaderForTest(t)
	client.AddHook(commandErrorHook{byName: map[string]error{"sismember": errors.New("reverse unavailable")}})
	if got, err := reader.GetExact(context.Background(), "bereia", "user-1"); got != nil || !errors.Is(err, errStoredMembershipReadContract) {
		t.Fatalf("SISMEMBER error = %+v, %v", got, err)
	}
}

func TestCanonicalMembershipAssignmentBoundaries(t *testing.T) {
	roles500 := make([]string, 500)
	for index := range roles500 {
		roles500[index] = "role" + strings.Repeat("x", index/100) + string(rune('A'+index%26)) + string(rune('0'+index%10))
	}
	for name, valid := range map[string]bool{
		"empty": func() bool {
			roles, ok := canonicalMembershipAssignments(nil)
			return ok && roles != nil && len(roles) == 0
		}(),
		"limit":      func() bool { _, ok := canonicalMembershipAssignments(roles500); return ok }(),
		"over limit": func() bool { _, ok := canonicalMembershipAssignments(append(roles500, "extra")); return !ok }(),
		"minimum":    canonicalMembershipRoleName("A"), "maximum": canonicalMembershipRoleName("A" + strings.Repeat("-", 126) + "Z"),
		"too long":     !canonicalMembershipRoleName("A" + strings.Repeat("-", 127) + "Z"),
		"edge grammar": canonicalMembershipRoleName("A.z_0-9"), "unsafe edge": !canonicalMembershipRoleName("-admin"),
		"unicode": !canonicalMembershipRoleName("rôle"), "duplicate": func() bool { _, ok := canonicalMembershipAssignments([]string{"reader", "reader"}); return !ok }(),
	} {
		if !valid {
			t.Errorf("boundary %s was not discriminated", name)
		}
	}
}

func FuzzDecodeExactMembership(f *testing.F) {
	for _, seed := range []string{"", "{", `{"id":"m"}`, `{"roles":null}`, `{"roles":["reader"]}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = decodeExactMembership(value)
		_, _ = canonicalMembershipAssignments([]string{value})
	})
}
