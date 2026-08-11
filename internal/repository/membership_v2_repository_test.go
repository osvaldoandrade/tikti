package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

var membershipV2TestTime = time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)

func newMembershipV2ForTest(t *testing.T) (*redis.Client, *membershipV2Repo) {
	t.Helper()
	client, _ := newMembershipRepoForTest(t)
	return client, NewMembershipV2Repo(client).(*membershipV2Repo)
}

func membershipV2JSON(t *testing.T, membership domain.Membership) string {
	t.Helper()
	value, err := json.Marshal(membership)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func seedMembershipV2(t *testing.T, client *redis.Client, tenantID, userID, value string, forward, reverse bool) {
	t.Helper()
	ctx := context.Background()
	if forward {
		if err := client.HSet(ctx, membershipV2Key(tenantID), userID, value).Err(); err != nil {
			t.Fatal(err)
		}
	}
	if reverse {
		if err := client.SAdd(ctx, membershipV2ByUserKey(userID), tenantID).Err(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMembershipV2EnsureCreatesAndReplaysImmutableSnapshot(t *testing.T) {
	client, repo := newMembershipV2ForTest(t)
	ctx := context.Background()
	roles := []string{"bereia-read", "bereia-write"}
	created, wasCreated, err := repo.Ensure(ctx, "bereia", "user-1", roles)
	if err != nil || !wasCreated || created == nil || created.CreatedAt.IsZero() {
		t.Fatalf("create = %+v, %t, %v", created, wasCreated, err)
	}
	wantID := "m2_m1G_DpaCc_gaBgFYIGLq6XwZc1gBy24lr6b8Rp5WAng"
	if created.Id != wantID || created.TenantId != "bereia" || created.UserId != "user-1" || !reflect.DeepEqual(created.Roles, roles) {
		t.Fatalf("created snapshot = %+v", created)
	}
	raw, _ := client.HGet(ctx, membershipV2Key("bereia"), "user-1").Result()
	reverse, _ := client.SIsMember(ctx, membershipV2ByUserKey("user-1"), "bereia").Result()
	legacyForward, _ := client.HExists(ctx, membershipsKey("bereia"), "user-1").Result()
	legacyReverse, _ := client.SIsMember(ctx, membershipsByUserPrefix+"user-1", "bereia").Result()
	legacyRaw, _ := client.HGet(ctx, membershipsKey("bereia"), "user-1").Result()
	if raw == "" || !reverse || !legacyForward || !legacyReverse || legacyRaw != raw {
		t.Fatalf("unexpected key state: raw=%q reverse=%t legacy=%t/%t", raw, reverse, legacyForward, legacyReverse)
	}
	legacy, err := NewMembershipRepo(client).Get(ctx, "bereia", "user-1")
	if err != nil || !reflect.DeepEqual(legacy, created) {
		t.Fatalf("legacy compatibility read = %+v, %v", legacy, err)
	}
	replay, replayCreated, err := repo.Ensure(ctx, "bereia", "user-1", roles)
	if err != nil || replayCreated || !reflect.DeepEqual(replay, created) {
		t.Fatalf("replay = %+v, %t, %v", replay, replayCreated, err)
	}
	replay.Roles[0] = "mutated"
	got, err := repo.GetExact(ctx, "bereia", "user-1")
	if err != nil || !reflect.DeepEqual(got, created) {
		t.Fatalf("defensive read = %+v, %v", got, err)
	}
	if divergent, divergentCreated, err := repo.Ensure(ctx, "bereia", "user-1", []string{"other"}); divergent != nil || divergentCreated || !errors.Is(err, domain.ErrMembershipConflict) {
		t.Fatalf("divergent replay = %+v, %t, %v", divergent, divergentCreated, err)
	}
	after, _ := client.HGet(ctx, membershipV2Key("bereia"), "user-1").Result()
	if after != raw {
		t.Fatal("divergent replay overwrote the snapshot")
	}
	other, otherCreated, err := repo.Ensure(ctx, "storifly", "user-1", []string{"reader"})
	if err != nil || !otherCreated || other.Id == created.Id || other.TenantId != "storifly" {
		t.Fatalf("tenant isolation = %+v, %t, %v", other, otherCreated, err)
	}
}

func TestMembershipV2ReplayRequiresIntactCompatibilityPair(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(context.Context, *redis.Client) error
	}{
		{name: "forward missing", mutate: func(ctx context.Context, client *redis.Client) error {
			return client.HDel(ctx, membershipsKey("bereia"), "user-1").Err()
		}},
		{name: "reverse missing", mutate: func(ctx context.Context, client *redis.Client) error {
			return client.SRem(ctx, membershipsByUserPrefix+"user-1", "bereia").Err()
		}},
		{name: "payload mismatch", mutate: func(ctx context.Context, client *redis.Client) error {
			return client.HSet(ctx, membershipsKey("bereia"), "user-1", `{"mismatch":true}`).Err()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, repo := newMembershipV2ForTest(t)
			ctx := context.Background()
			if _, created, err := repo.Ensure(ctx, "bereia", "user-1", []string{"reader"}); err != nil || !created {
				t.Fatalf("create: %t, %v", created, err)
			}
			if err := test.mutate(ctx, client); err != nil {
				t.Fatal(err)
			}
			if got, created, err := repo.Ensure(ctx, "bereia", "user-1", []string{"reader"}); got != nil || created || !errors.Is(err, errStoredMembershipV2Contract) {
				t.Fatalf("corrupt compatibility replay = %+v, %t, %v", got, created, err)
			}
		})
	}
}

func TestMembershipV2EnsureRejectsEveryLegacyShadowWithoutFallback(t *testing.T) {
	for _, test := range []struct {
		name             string
		forward, reverse bool
		value            string
	}{
		{name: "forward", forward: true, value: `{"legacy":true}`},
		{name: "empty forward", forward: true, value: ""},
		{name: "reverse", reverse: true},
		{name: "bilateral", forward: true, reverse: true, value: `{"legacy":true}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, repo := newMembershipV2ForTest(t)
			ctx := context.Background()
			if test.forward {
				if err := client.HSet(ctx, membershipsKey("bereia"), "user-1", test.value).Err(); err != nil {
					t.Fatal(err)
				}
			}
			if test.reverse {
				if err := client.SAdd(ctx, membershipsByUserPrefix+"user-1", "bereia").Err(); err != nil {
					t.Fatal(err)
				}
			}
			missing, err := repo.GetExact(ctx, "bereia", "user-1")
			if err != nil || missing != nil {
				t.Fatalf("v2 read fell back to v1: %+v, %v", missing, err)
			}
			got, created, err := repo.Ensure(ctx, "bereia", "user-1", []string{"reader"})
			if got != nil || created || !errors.Is(err, domain.ErrMembershipConflict) {
				t.Fatalf("legacy shadow = %+v, %t, %v", got, created, err)
			}
			if exists, _ := client.HExists(ctx, membershipV2Key("bereia"), "user-1").Result(); exists {
				t.Fatal("legacy shadow was migrated")
			}
		})
	}
}

func TestMembershipV2ExactReadRejectsUnilateralAndStoredViolations(t *testing.T) {
	for _, test := range []struct {
		name             string
		forward, reverse bool
	}{
		{name: "forward orphan", forward: true}, {name: "reverse orphan", reverse: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, repo := newMembershipV2ForTest(t)
			seedMembershipV2(t, client, "bereia", "user-1", "{}", test.forward, test.reverse)
			if got, err := repo.GetExact(context.Background(), "bereia", "user-1"); got != nil || !errors.Is(err, errStoredMembershipV2Contract) {
				t.Fatalf("unilateral read = %+v, %v", got, err)
			}
			if got, created, err := repo.Ensure(context.Background(), "bereia", "user-1", []string{"reader"}); got != nil || created || !errors.Is(err, errStoredMembershipV2Contract) {
				t.Fatalf("unilateral ensure = %+v, %t, %v", got, created, err)
			}
		})
	}
	roles101 := make([]string, 101)
	for index := range roles101 {
		roles101[index] = fmt.Sprintf("role-%03d", index)
	}
	base := domain.Membership{
		Id: membershipV2ID("bereia", "user-1"), TenantId: "bereia", UserId: "user-1",
		Roles: []string{"reader"}, CreatedAt: membershipV2TestTime,
	}
	valid := membershipV2JSON(t, base)
	encode := func(change func(*domain.Membership)) string {
		copy := base
		change(&copy)
		return membershipV2JSON(t, copy)
	}
	oversized := valid + strings.Repeat(" ", membershipV2PayloadMax-len(valid)+1)
	t.Run("payload 16KiB", func(t *testing.T) {
		client, repo := newMembershipV2ForTest(t)
		seedMembershipV2(t, client, "bereia", "user-1", valid+strings.Repeat(" ", membershipV2PayloadMax-len(valid)), true, true)
		if got, err := repo.GetExact(context.Background(), "bereia", "user-1"); err != nil || got == nil {
			t.Fatalf("exact payload boundary = %+v, %v", got, err)
		}
	})
	for _, test := range []struct{ name, raw string }{
		{name: "empty", raw: ""}, {name: "malformed", raw: "{"}, {name: "array", raw: "[]"},
		{name: "unknown", raw: strings.Replace(valid, "}", `,"secret":"redis-password-canary"}`, 1)},
		{name: "alias", raw: strings.Replace(valid, `"tenantId"`, `"TenantId"`, 1)},
		{name: "duplicate", raw: strings.Replace(valid, "{", `{"id":"duplicate",`, 1)},
		{name: "missing", raw: strings.Replace(valid, `,"roles":["reader"]`, "", 1)},
		{name: "null id", raw: strings.Replace(valid, `"id":"`+base.Id+`"`, `"id":null`, 1)},
		{name: "null roles", raw: strings.Replace(valid, `["reader"]`, "null", 1)},
		{name: "trailing", raw: valid + ` {}`},
		{name: "invalid utf8", raw: strings.Replace(valid, "reader", string([]byte{0xff}), 1)},
		{name: "invalid surrogate", raw: strings.Replace(valid, `"reader"`, `"\ud800"`, 1)},
		{name: "id mismatch", raw: encode(func(value *domain.Membership) { value.Id = "other" })},
		{name: "tenant mismatch", raw: encode(func(value *domain.Membership) { value.TenantId = "storifly" })},
		{name: "user mismatch", raw: encode(func(value *domain.Membership) { value.UserId = "user-2" })},
		{name: "zero time", raw: encode(func(value *domain.Membership) { value.CreatedAt = time.Time{} })},
		{name: "empty roles", raw: encode(func(value *domain.Membership) { value.Roles = []string{} })},
		{name: "unsorted roles", raw: encode(func(value *domain.Membership) { value.Roles = []string{"writer", "reader"} })},
		{name: "duplicate roles", raw: encode(func(value *domain.Membership) { value.Roles = []string{"reader", "reader"} })},
		{name: "unsafe role", raw: encode(func(value *domain.Membership) { value.Roles = []string{"-reader"} })},
		{name: "role 101", raw: encode(func(value *domain.Membership) { value.Roles = roles101 })},
		{name: "role 129", raw: encode(func(value *domain.Membership) { value.Roles = []string{"a" + strings.Repeat("x", 127) + "z"} })},
		{name: "oversized", raw: oversized},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, repo := newMembershipV2ForTest(t)
			seedMembershipV2(t, client, "bereia", "user-1", test.raw, true, true)
			if err := client.HSet(context.Background(), membershipsKey("bereia"), "user-1", test.raw).Err(); err != nil {
				t.Fatal(err)
			}
			if err := client.SAdd(context.Background(), membershipsByUserPrefix+"user-1", "bereia").Err(); err != nil {
				t.Fatal(err)
			}
			got, err := repo.GetExact(context.Background(), "bereia", "user-1")
			if got != nil || !errors.Is(err, errStoredMembershipV2Contract) || strings.Contains(err.Error(), "canary") {
				t.Fatalf("stored violation = %+v, %v", got, err)
			}
			before, _ := client.HGet(context.Background(), membershipV2Key("bereia"), "user-1").Result()
			if ensured, created, err := repo.Ensure(context.Background(), "bereia", "user-1", []string{"reader"}); ensured != nil || created || !errors.Is(err, errStoredMembershipV2Contract) {
				t.Fatalf("ensure corrupt = %+v, %t, %v", ensured, created, err)
			}
			after, _ := client.HGet(context.Background(), membershipV2Key("bereia"), "user-1").Result()
			if before != after {
				t.Fatal("stored violation was repaired")
			}
		})
	}
}

func TestMembershipV2InputAndBoundariesFailBeforeEval(t *testing.T) {
	client, repo := newMembershipV2ForTest(t)
	client.AddHook(commandErrorHook{byName: map[string]error{"eval": errors.New("eval reached")}})
	for _, test := range []struct {
		name, tenant, user string
		roles              []string
		want               error
	}{
		{name: "tenant", tenant: "Bereia", user: "user-1", roles: []string{"reader"}, want: domain.ErrInvalidTenant},
		{name: "empty user", tenant: "bereia", roles: []string{"reader"}, want: domain.ErrInvalidArgument},
		{name: "dot user", tenant: "bereia", user: ".", roles: []string{"reader"}, want: domain.ErrInvalidArgument},
		{name: "dot-dot user", tenant: "bereia", user: "..", roles: []string{"reader"}, want: domain.ErrInvalidArgument},
		{name: "slash user", tenant: "bereia", user: "user/1", roles: []string{"reader"}, want: domain.ErrInvalidArgument},
		{name: "zero roles", tenant: "bereia", user: "user-1", want: domain.ErrInvalidArgument},
		{name: "unsorted", tenant: "bereia", user: "user-1", roles: []string{"writer", "reader"}, want: domain.ErrInvalidArgument},
		{name: "duplicate", tenant: "bereia", user: "user-1", roles: []string{"reader", "reader"}, want: domain.ErrInvalidArgument},
		{name: "whitespace", tenant: "bereia", user: "user-1", roles: []string{" reader"}, want: domain.ErrInvalidArgument},
		{name: "edge", tenant: "bereia", user: "user-1", roles: []string{"-reader"}, want: domain.ErrInvalidArgument},
		{name: "role 129", tenant: "bereia", user: "user-1", roles: []string{"a" + strings.Repeat("x", 127) + "z"}, want: domain.ErrInvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, created, err := repo.Ensure(context.Background(), test.tenant, test.user, test.roles); got != nil || created || !errors.Is(err, test.want) {
				t.Fatalf("invalid input = %+v, %t, %v", got, created, err)
			}
		})
	}
	if got, err := repo.GetExact(context.Background(), "Bereia", "user-1"); got != nil || !errors.Is(err, domain.ErrInvalidTenant) {
		t.Fatalf("invalid read tenant = %+v, %v", got, err)
	}
	if got, err := repo.GetExact(context.Background(), "bereia", ".."); got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("invalid read user = %+v, %v", got, err)
	}
	_, repo = newMembershipV2ForTest(t)
	roles100 := make([]string, 100)
	for index := range roles100 {
		roles100[index] = fmt.Sprintf("role-%03d", index)
	}
	roles100[99] = "z" + strings.Repeat("x", 126) + "z"
	if got, created, err := repo.Ensure(context.Background(), "bereia", "u", roles100); err != nil || !created || got == nil || len(got.Roles) != 100 || len(got.Roles[99]) != 128 {
		t.Fatalf("valid boundaries = %+v, %t, %v", got, created, err)
	}
	roles101 := append(append([]string(nil), roles100...), "zz")
	if got, created, err := repo.Ensure(context.Background(), "bereia", "user-2", roles101); got != nil || created || !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("role 101 = %+v, %t, %v", got, created, err)
	}
}

func TestMembershipV2UsesDirectEvalAndRedactsStorageErrors(t *testing.T) {
	client, repo := newMembershipV2ForTest(t)
	client.AddHook(commandErrorHook{byName: map[string]error{"evalsha": errors.New("EVALSHA forbidden")}})
	if _, _, err := repo.Ensure(context.Background(), "bereia", "user-1", []string{"reader"}); err != nil {
		t.Fatalf("direct ensure EVAL: %v", err)
	}
	if _, err := repo.GetExact(context.Background(), "bereia", "user-1"); err != nil {
		t.Fatalf("direct read EVAL: %v", err)
	}
	client, repo = newMembershipV2ForTest(t)
	client.AddHook(commandErrorHook{byName: map[string]error{"eval": errors.New("redis-password-canary")}})
	if got, _, err := repo.Ensure(context.Background(), "bereia", "user-1", []string{"reader"}); got != nil || !errors.Is(err, errStoredMembershipV2Contract) || strings.Contains(err.Error(), "canary") {
		t.Fatalf("ensure storage error = %+v, %v", got, err)
	}
	if got, err := repo.GetExact(context.Background(), "bereia", "user-1"); got != nil || !errors.Is(err, errStoredMembershipV2Contract) || strings.Contains(err.Error(), "canary") {
		t.Fatalf("read storage error = %+v, %v", got, err)
	}
	_, repo = newMembershipV2ForTest(t)
	if _, _, err := repo.eval(context.Background(), `return {"one"}`, nil); !errors.Is(err, errStoredMembershipV2Contract) {
		t.Fatalf("malformed script result = %v", err)
	}
	var nilRepo *membershipV2Repo
	if _, _, err := nilRepo.Ensure(context.Background(), "bereia", "user-1", []string{"reader"}); !errors.Is(err, errStoredMembershipV2Contract) {
		t.Fatalf("nil ensure = %v", err)
	}
	if _, err := nilRepo.GetExact(context.Background(), "bereia", "user-1"); !errors.Is(err, errStoredMembershipV2Contract) {
		t.Fatalf("nil read = %v", err)
	}
}

func TestMembershipV2FailureAndCanceledContextCreateNoPartialState(t *testing.T) {
	client, repo := newMembershipV2ForTest(t)
	ctx := context.Background()
	if err := client.Set(ctx, membershipsByUserPrefix+"user-1", "wrong-type", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if got, created, err := repo.Ensure(ctx, "bereia", "user-1", []string{"reader"}); got != nil || created || !errors.Is(err, errStoredMembershipV2Contract) {
		t.Fatalf("preflight failure = %+v, %t, %v", got, created, err)
	}
	keys := []string{membershipV2Key("bereia"), membershipV2ByUserKey("user-1"), membershipsKey("bereia")}
	if count, err := client.Exists(ctx, keys...).Result(); err != nil || count != 0 {
		t.Fatalf("partial state after preflight failure: count=%d err=%v", count, err)
	}
	client, repo = newMembershipV2ForTest(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if got, created, err := repo.Ensure(canceled, "bereia", "user-1", []string{"reader"}); got != nil || created || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ensure = %+v, %t, %v", got, created, err)
	}
	keys = append(keys, membershipsByUserPrefix+"user-1")
	if count, err := client.Exists(context.Background(), keys...).Result(); err != nil || count != 0 {
		t.Fatalf("canceled ensure created state: count=%d err=%v", count, err)
	}
	deadline, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if got, err := repo.GetExact(deadline, "bereia", "user-1"); got != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired read = %+v, %v", got, err)
	}
}

func TestMembershipV2ConcurrentIdenticalHasOneCreator(t *testing.T) {
	_, repo := newMembershipV2ForTest(t)
	type outcome struct {
		membership *domain.Membership
		created    bool
		err        error
	}
	results := make(chan outcome, 100)
	var wait sync.WaitGroup
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			membership, created, err := repo.Ensure(context.Background(), "bereia", "user-1", []string{"reader"})
			results <- outcome{membership: membership, created: created, err: err}
		}()
	}
	wait.Wait()
	close(results)
	created, replayed := 0, 0
	var snapshot *domain.Membership
	for result := range results {
		if result.err != nil || result.membership == nil {
			t.Fatalf("concurrent identical = %+v", result)
		}
		if snapshot == nil {
			snapshot = result.membership
		} else if !reflect.DeepEqual(snapshot, result.membership) {
			t.Fatalf("replay snapshot changed: %+v != %+v", snapshot, result.membership)
		}
		if result.created {
			created++
		} else {
			replayed++
		}
	}
	if created != 1 || replayed != 99 {
		t.Fatalf("created=%d replayed=%d", created, replayed)
	}
}

func TestMembershipV2ConcurrentDifferentHasOneWinner(t *testing.T) {
	_, repo := newMembershipV2ForTest(t)
	type outcome struct {
		created bool
		err     error
	}
	results := make(chan outcome, 100)
	var wait sync.WaitGroup
	for index := range 100 {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, created, err := repo.Ensure(context.Background(), "bereia", "user-1", []string{fmt.Sprintf("role-%03d", index)})
			results <- outcome{created: created, err: err}
		}(index)
	}
	wait.Wait()
	close(results)
	winners, conflicts := 0, 0
	for result := range results {
		switch {
		case result.created && result.err == nil:
			winners++
		case !result.created && errors.Is(result.err, domain.ErrMembershipConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent result: %+v", result)
		}
	}
	if winners != 1 || conflicts != 99 {
		t.Fatalf("winners=%d conflicts=%d", winners, conflicts)
	}
}

func FuzzDecodeMembershipV2(f *testing.F) {
	encoded, err := json.Marshal(domain.Membership{
		Id: membershipV2ID("bereia", "user-1"), TenantId: "bereia", UserId: "user-1",
		Roles: []string{"reader"}, CreatedAt: membershipV2TestTime,
	})
	if err != nil {
		f.Fatal(err)
	}
	valid := string(encoded)
	for _, seed := range []string{valid, "", "{", `{"id":null}`, strings.Repeat("x", membershipV2PayloadMax+1)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		membership, ok := decodeMembershipV2("bereia", "user-1", value)
		if ok && (membership == nil || membership.Id != membershipV2ID("bereia", "user-1") ||
			membership.TenantId != "bereia" || membership.UserId != "user-1" ||
			!validMembershipV2Roles(membership.Roles) || membership.CreatedAt.IsZero()) {
			t.Fatalf("invalid v2 membership accepted: %+v", membership)
		}
	})
}
