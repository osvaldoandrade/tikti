package repository

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

var exactListTokenKey = []byte("0123456789abcdef0123456789abcdef")

func newExactMembershipListForTest(t *testing.T) (*redis.Client, *exactMembershipListReader, MembershipRepository) {
	t.Helper()
	client, memberships := newMembershipRepoForTest(t)
	reader, err := NewExactMembershipListReader(client, NewTenantRepo(client).(ExactTenantRepository), NewRedisRepo(client).(ExactUserBatchRepository), exactListTokenKey)
	if err != nil {
		t.Fatal(err)
	}
	return client, reader.(*exactMembershipListReader), memberships
}

func seedActiveListTenant(t *testing.T, client *redis.Client, tenantID string) {
	t.Helper()
	tenant := domain.Tenant{Id: tenantID, Slug: tenantID, Name: "Tenant " + tenantID, Status: domain.TenantStatusActive, CreatedAt: exactIdentityTime}
	if err := client.HSet(context.Background(), tenantsHash, tenantID, mustJSON(t, tenant)).Err(); err != nil {
		t.Fatal(err)
	}
}

func seedListMembership(t *testing.T, client *redis.Client, memberships MembershipRepository, tenantID, userID string, roles []string) {
	t.Helper()
	seedExactUser(t, client, userID, userID+"@example.com")
	if err := memberships.Create(context.Background(), &domain.Membership{
		Id: "membership-" + userID, TenantId: tenantID, UserId: userID, Roles: roles, CreatedAt: exactIdentityTime,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExactMembershipList_PaginatesTargetOnlyAndReadsValuesPerPage(t *testing.T) {
	client, reader, memberships := newExactMembershipListForTest(t)
	ctx := context.Background()
	seedActiveListTenant(t, client, "bereia")
	seedActiveListTenant(t, client, "storifly")
	seedListMembership(t, client, memberships, "bereia", "user-c", []string{"member"})
	seedListMembership(t, client, memberships, "bereia", "user-a", []string{"writer", "reader"})
	seedListMembership(t, client, memberships, "bereia", "user-b", nil)
	seedListMembership(t, client, memberships, "storifly", "user-a", []string{"storifly-admin"})
	if err := client.HSet(ctx, membershipsKey("storifly"), "user-a", "{").Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.Set(ctx, rolesKey("bereia"), "role definitions must not be read", 0).Err(); err != nil {
		t.Fatal(err)
	}
	client.AddHook(commandErrorHook{byName: map[string]error{"evalsha": errors.New("must use direct eval"), "hscan": errors.New("hscan forbidden"), "hgetall": errors.New("hgetall forbidden")}})

	first, err := reader.ListExact(ctx, "bereia", "", 2)
	if err != nil || len(first.Memberships) != 2 || first.NextPageToken == "" ||
		first.Memberships[0].UserId != "user-a" || first.Memberships[1].UserId != "user-b" ||
		strings.Join(first.Memberships[0].Roles, ",") != "reader,writer" || first.Memberships[1].Roles == nil {
		t.Fatalf("first page = %+v, %v", first, err)
	}
	replay, err := reader.ListExact(ctx, "bereia", "", 2)
	if err != nil || replay.NextPageToken != first.NextPageToken {
		t.Fatalf("deterministic replay = %+v, %v", replay, err)
	}
	updated := domain.Membership{Id: "membership-user-c", TenantId: "bereia", UserId: "user-c", Roles: []string{"updated"}, CreatedAt: exactIdentityTime}
	if err := client.HSet(ctx, membershipsKey("bereia"), "user-c", mustJSON(t, updated)).Err(); err != nil {
		t.Fatal(err)
	}
	second, err := reader.ListExact(ctx, "bereia", first.NextPageToken, 2)
	if err != nil || len(second.Memberships) != 1 || second.Memberships[0].UserId != "user-c" || strings.Join(second.Memberships[0].Roles, ",") != "updated" || second.NextPageToken != "" {
		t.Fatalf("read-committed second page = %+v, %v", second, err)
	}
	projection, _ := json.Marshal(append(first.Memberships, second.Memberships...))
	for _, secret := range []string{"private-hash-canary", "private-company-canary", "storifly-admin", `"password":`, "companyId", "tokenVersion", "externalSubject", "permissions"} {
		if strings.Contains(string(projection), secret) {
			t.Fatalf("unsafe projection contains %q: %s", secret, projection)
		}
	}
}

func TestExactMembershipList_InputTenantAndEmptyBoundaries(t *testing.T) {
	client, reader, _ := newExactMembershipListForTest(t)
	ctx := context.Background()
	seedActiveListTenant(t, client, "bereia")
	if err := client.SAdd(ctx, membershipsByUserPrefix+"reverse-only", "bereia").Err(); err != nil {
		t.Fatal(err)
	}
	empty, err := reader.ListExact(ctx, "bereia", "", exactMembershipListPageMax)
	if err != nil || empty == nil || empty.Memberships == nil || len(empty.Memberships) != 0 || empty.NextPageToken != "" {
		t.Fatalf("active empty tenant = %+v, %v", empty, err)
	}
	for _, test := range []struct {
		tenant string
		size   int
		want   error
	}{{"Bereia", 1, domain.ErrInvalidTenant}, {"bereia", 0, domain.ErrInvalidArgument}, {"bereia", 201, domain.ErrInvalidArgument}} {
		if got, err := reader.ListExact(ctx, test.tenant, "", test.size); got != nil || !errors.Is(err, test.want) {
			t.Fatalf("input tenant=%q size=%d = %+v, %v", test.tenant, test.size, got, err)
		}
	}
	if got, err := reader.ListExact(ctx, "missing", "", 1); got != nil || !errors.Is(err, errStoredMembershipReadContract) {
		t.Fatalf("missing tenant = %+v, %v", got, err)
	}
	seedExactTenant(t, client, "disabled")
	if got, err := reader.ListExact(ctx, "disabled", "", 1); got != nil || !errors.Is(err, errStoredMembershipReadContract) {
		t.Fatalf("disabled tenant = %+v, %v", got, err)
	}
	var nilReader *exactMembershipListReader
	if got, err := nilReader.ListExact(ctx, "bereia", "", 1); got != nil || !errors.Is(err, errStoredMembershipReadContract) {
		t.Fatalf("nil reader = %+v, %v", got, err)
	}
	tenants, users := NewTenantRepo(client).(ExactTenantRepository), NewRedisRepo(client).(ExactUserBatchRepository)
	for _, args := range []struct {
		client  *redis.Client
		tenants ExactTenantRepository
		users   ExactUserBatchRepository
	}{{nil, tenants, users}, {client, nil, users}, {client, tenants, nil}} {
		if got, err := NewExactMembershipListReader(args.client, args.tenants, args.users, exactListTokenKey); got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
			t.Fatalf("invalid constructor = %+v, %v", got, err)
		}
	}
	if got, err := NewExactMembershipListReader(client, tenants, users, bytes.Repeat([]byte{'k'}, 31)); got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("short constructor key = %+v, %v", got, err)
	}
}

func TestExactUserBatch_BoundsAndStorageErrors(t *testing.T) {
	client, _ := newMembershipRepoForTest(t)
	batch := NewRedisRepo(client).(ExactUserBatchRepository)
	if got, err := batch.GetManyExact(context.Background(), nil); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty batch = %+v, %v", got, err)
	}
	for _, ids := range [][]string{{"user/a"}, make([]string, exactMembershipListPageMax+1)} {
		if got, err := batch.GetManyExact(context.Background(), ids); got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
			t.Fatalf("invalid batch = %+v, %v", got, err)
		}
	}
	maxIDs := make([]string, exactMembershipListPageMax)
	for index := range maxIDs {
		maxIDs[index] = fmt.Sprintf("user-%03d", index)
	}
	if got, err := batch.GetManyExact(context.Background(), maxIDs); got != nil || !errors.Is(err, errStoredUserContract) {
		t.Fatalf("maximum batch = %+v, %v", got, err)
	}
	var nilRepo *redisRepo
	if got, err := nilRepo.GetManyExact(context.Background(), nil); got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("nil batch = %+v, %v", got, err)
	}
	client.AddHook(commandErrorHook{byName: map[string]error{"hmget": context.Canceled}})
	if got, err := batch.GetManyExact(context.Background(), []string{"user-a"}); got != nil || !errors.Is(err, errStoredUserContract) {
		t.Fatalf("batch storage error = %+v, %v", got, err)
	}
}

func TestExactMembershipPageToken_AuthenticatesCanonicalPayload(t *testing.T) {
	key := append([]byte(nil), exactListTokenKey...)
	codec, err := newExactMembershipPageTokenCodec(key)
	if err != nil {
		t.Fatal(err)
	}
	value := exactMembershipPageToken{Version: 1, Tenant: strings.Repeat("t", 63), Digest: strings.Repeat("a", 64), After: strings.Repeat("u", 128), PageSize: 200}
	token, err := codec.encode(value)
	if err != nil || len(token) > exactMembershipPageTokenMaxSize {
		t.Fatalf("maximum token = %q, %v", token, err)
	}
	key[0] ^= 0xff
	decoded, err := codec.decode(token, value.Tenant, value.PageSize)
	if err != nil || decoded == nil || *decoded != value {
		t.Fatalf("copied key decode = %+v, %v", decoded, err)
	}
	last := byte('A')
	if token[len(token)-1] == last {
		last = 'B'
	}
	invalid := []string{"x", ".x", "x.", "x.y.z", strings.Repeat("x", 513), token[:len(token)-1] + string(last)}
	for _, encoded := range invalid {
		if got, err := codec.decode(encoded, value.Tenant, value.PageSize); got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
			t.Fatalf("invalid token %q = %+v, %v", encoded, got, err)
		}
	}
	if got, err := codec.decode(token, "foreign", 200); got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("foreign token = %+v, %v", got, err)
	}
	if got, err := codec.decode(token, value.Tenant, 199); got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("page-size token = %+v, %v", got, err)
	}
	if got, err := codec.decode("", value.Tenant, 200); err != nil || got != nil {
		t.Fatalf("empty token = %+v, %v", got, err)
	}
}

func TestExactMembershipPageToken_RejectsSignedNonCanonicalValues(t *testing.T) {
	codec, _ := newExactMembershipPageTokenCodec(exactListTokenKey)
	digest := strings.Repeat("a", 64)
	valid := fmt.Sprintf(`{"v":1,"tenant":"bereia","digest":"%s","after":"user-a","pageSize":1}`, digest)
	sign := func(raw string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(raw)) + "." + base64.RawURLEncoding.EncodeToString(codec.mac([]byte(raw)))
	}
	for name, raw := range map[string]string{
		"whitespace": " " + valid, "malformed": "{", "unknown": strings.Replace(valid, "}", `,"x":1}`, 1),
		"duplicate": strings.Replace(valid, "{", `{"v":1,`, 1), "missing": strings.Replace(valid, `,"after":"user-a"`, "", 1),
		"null": strings.Replace(valid, `"after":"user-a"`, `"after":null`, 1), "version": strings.Replace(valid, `"v":1`, `"v":2`, 1),
		"digest": strings.Replace(valid, digest, strings.Repeat("A", 64), 1), "after": strings.Replace(valid, "user-a", "user/a", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := codec.decode(sign(raw), "bereia", 1); got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
				t.Fatalf("signed invalid = %+v, %v", got, err)
			}
		})
	}
	if _, err := newExactMembershipPageTokenCodec(bytes.Repeat([]byte{'k'}, 31)); !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("short key = %v", err)
	}
	if _, err := (*exactMembershipPageTokenCodec)(nil).encode(exactMembershipPageToken{}); !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("nil codec = %v", err)
	}
	for value, valid := range map[string]bool{strings.Repeat("0", 64): true, strings.Repeat("a", 63): false, strings.Repeat("g", 64): false} {
		if validMembershipSnapshotDigest(value) != valid {
			t.Fatalf("digest validity %q", value)
		}
	}
}

func TestExactMembershipList_StaleAndUnknownAfter(t *testing.T) {
	for _, change := range []string{"add", "delete"} {
		t.Run(change, func(t *testing.T) {
			client, reader, memberships := newExactMembershipListForTest(t)
			seedActiveListTenant(t, client, "bereia")
			seedListMembership(t, client, memberships, "bereia", "user-a", []string{"reader"})
			seedListMembership(t, client, memberships, "bereia", "user-b", []string{"reader"})
			first, err := reader.ListExact(context.Background(), "bereia", "", 1)
			if err != nil {
				t.Fatal(err)
			}
			if change == "add" {
				seedListMembership(t, client, memberships, "bereia", "user-c", []string{"reader"})
			} else if err := client.HDel(context.Background(), membershipsKey("bereia"), "user-b").Err(); err != nil {
				t.Fatal(err)
			}
			if got, err := reader.ListExact(context.Background(), "bereia", first.NextPageToken, 1); got != nil || !errors.Is(err, ErrExactMembershipListStaleCursor) {
				t.Fatalf("changed field set = %+v, %v", got, err)
			}
		})
	}
	client, reader, memberships := newExactMembershipListForTest(t)
	seedActiveListTenant(t, client, "bereia")
	seedListMembership(t, client, memberships, "bereia", "user-a", []string{"reader"})
	fields, digest, err := reader.snapshot(context.Background(), "bereia")
	if err != nil || len(fields) != 1 {
		t.Fatal(err)
	}
	forged, _ := reader.tokens.encode(exactMembershipPageToken{Version: 1, Tenant: "bereia", Digest: digest, After: "user-z", PageSize: 1})
	if got, err := reader.ListExact(context.Background(), "bereia", forged, 1); got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("unknown after = %+v, %v", got, err)
	}
	last, _ := reader.tokens.encode(exactMembershipPageToken{Version: 1, Tenant: "bereia", Digest: digest, After: "user-a", PageSize: 1})
	if got, err := reader.ListExact(context.Background(), "bereia", last, 1); got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("terminal after = %+v, %v", got, err)
	}
}

func TestExactMembershipList_CapAndCorruptionFailClosed(t *testing.T) {
	client, reader, memberships := newExactMembershipListForTest(t)
	ctx := context.Background()
	seedActiveListTenant(t, client, "bereia")
	values := make(map[string]interface{}, exactMembershipListTenantMax)
	for index := range exactMembershipListTenantMax {
		values[fmt.Sprintf("u%05d", index)] = "{}"
	}
	if err := client.HSet(ctx, membershipsKey("bereia"), values).Err(); err != nil {
		t.Fatal(err)
	}
	seedListMembership(t, client, memberships, "bereia", "u00000", []string{"reader"})
	page, err := reader.ListExact(ctx, "bereia", "", 1)
	if err != nil || len(page.Memberships) != 1 || page.NextPageToken == "" {
		t.Fatalf("10k boundary = %+v, %v", page, err)
	}
	if err := client.HSet(ctx, membershipsKey("bereia"), "u10000", "{}").Err(); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.ListExact(ctx, "bereia", "", 1); got != nil || !errors.Is(err, errStoredMembershipReadContract) {
		t.Fatalf("10001 boundary = %+v, %v", got, err)
	}
}

func TestExactMembershipList_EntryAndRedisFailuresAreAtomic(t *testing.T) {
	for _, test := range []struct {
		name, raw, field, index string
		reverse, user           bool
		hook                    map[string]error
	}{
		{name: "empty", raw: "", reverse: true, user: true}, {name: "malformed", raw: "{", reverse: true, user: true},
		{name: "field mismatch", raw: mustJSON(t, domain.Membership{Id: "membership-user-a", TenantId: "bereia", UserId: "user-b", Roles: []string{}, CreatedAt: exactIdentityTime}), reverse: true, user: true},
		{name: "forward orphan", raw: mustJSON(t, domain.Membership{Id: "membership-user-a", TenantId: "bereia", UserId: "user-a", Roles: []string{}, CreatedAt: exactIdentityTime}), user: true},
		{name: "missing user", raw: mustJSON(t, domain.Membership{Id: "membership-user-a", TenantId: "bereia", UserId: "user-a", Roles: []string{}, CreatedAt: exactIdentityTime}), reverse: true},
		{name: "invalid field", field: "user/a", raw: "valid", reverse: true, user: true},
		{name: "missing user index", raw: "valid", reverse: true, user: true, index: "missing"},
		{name: "mismatched user index", raw: "valid", reverse: true, user: true, index: "other"},
		{name: "eval error", raw: "valid", reverse: true, user: true, hook: map[string]error{"eval": context.Canceled}},
		{name: "hmget error", raw: "valid", reverse: true, user: true, hook: map[string]error{"hmget": context.Canceled}},
		{name: "reverse error", raw: "valid", reverse: true, user: true, hook: map[string]error{"sismember": context.Canceled}},
		{name: "index error", raw: "valid", reverse: true, user: true, hook: map[string]error{"mget": context.Canceled}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, reader, _ := newExactMembershipListForTest(t)
			ctx := context.Background()
			seedActiveListTenant(t, client, "bereia")
			if test.user {
				seedExactUser(t, client, "user-a", "user-a@example.com")
				if test.index == "missing" {
					_ = client.Del(ctx, userByEmailKeyNS+"user-a@example.com").Err()
				} else if test.index != "" {
					_ = client.Set(ctx, userByEmailKeyNS+"user-a@example.com", test.index, 0).Err()
				}
			}
			raw := test.raw
			if raw == "valid" {
				raw = mustJSON(t, domain.Membership{Id: "membership-user-a", TenantId: "bereia", UserId: "user-a", Roles: []string{"reader"}, CreatedAt: exactIdentityTime})
			}
			field := test.field
			if field == "" {
				field = "user-a"
			}
			if err := client.HSet(ctx, membershipsKey("bereia"), field, raw).Err(); err != nil {
				t.Fatal(err)
			}
			if test.reverse {
				if err := client.SAdd(ctx, membershipsByUserPrefix+"user-a", "bereia").Err(); err != nil {
					t.Fatal(err)
				}
			}
			client.AddHook(commandErrorHook{byName: test.hook})
			got, err := reader.ListExact(ctx, "bereia", "", 1)
			if got != nil || !errors.Is(err, errStoredMembershipReadContract) || raw != "" && strings.Contains(fmt.Sprint(err), raw) {
				t.Fatalf("atomic failure = %+v, %v", got, err)
			}
		})
	}
}

func FuzzExactMembershipPageToken(f *testing.F) {
	for _, seed := range []string{"", "x", "x.y", strings.Repeat("x", 513)} {
		f.Add(seed)
	}
	codec, _ := newExactMembershipPageTokenCodec(exactListTokenKey)
	f.Fuzz(func(t *testing.T, encoded string) {
		_, _ = codec.decode(encoded, "bereia", 1)
	})
}
