package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

var exactIdentityTime = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

func TestExactIdentityRepositoriesAreAdditive(t *testing.T) {
	_, tenantRepository := newTenantRepoForTest(t)
	_, userRepository := newUserRepoForTest(t)
	if _, ok := tenantRepository.(ExactTenantRepository); !ok {
		t.Fatal("tenant repository does not implement exact reads")
	}
	if _, ok := userRepository.(ExactUserRepository); !ok {
		t.Fatal("user repository does not implement exact reads")
	}
}

func TestTenantRepo_GetExact_ValidAndMissing(t *testing.T) {
	rdb, legacy := newTenantRepoForTest(t)
	repo := legacy.(ExactTenantRepository)
	ctx := context.Background()
	missing, err := repo.GetExact(ctx, "missing")
	if err != nil || missing != nil {
		t.Fatalf("missing tenant = %+v, %v", missing, err)
	}

	tenantID := strings.Repeat("a", 63)
	tenant := domain.Tenant{Id: tenantID, Slug: "bereia", Name: strings.Repeat("界", 128), Status: domain.TenantStatusActive, CreatedAt: exactIdentityTime}
	raw := mustJSON(t, tenant)
	if err := rdb.HSet(ctx, tenantsHash, tenantID, raw).Err(); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetExact(ctx, tenantID)
	if err != nil || got == nil || *got != tenant {
		t.Fatalf("exact tenant = %+v, %v", got, err)
	}
	stored, _ := rdb.HGet(ctx, tenantsHash, tenantID).Result()
	if stored != raw {
		t.Fatal("exact read mutated stored tenant")
	}

	disabled := domain.Tenant{Id: "tenant-2", Slug: "not-the-id", Name: "Disabled", Status: domain.TenantStatusDisabled, CreatedAt: exactIdentityTime}
	if err := rdb.HSet(ctx, tenantsHash, disabled.Id, mustJSON(t, disabled)).Err(); err != nil {
		t.Fatal(err)
	}
	if got, err = repo.GetExact(ctx, disabled.Id); err != nil || got.Status != domain.TenantStatusDisabled {
		t.Fatalf("disabled tenant = %+v, %v", got, err)
	}
	emoji := domain.Tenant{Id: "emoji", Slug: "emoji", Name: "placeholder", Status: domain.TenantStatusActive, CreatedAt: exactIdentityTime}
	emojiRaw := strings.Replace(mustJSON(t, emoji), `"placeholder"`, `"\ud83d\ude00"`, 1)
	if err := rdb.HSet(ctx, tenantsHash, emoji.Id, emojiRaw).Err(); err != nil {
		t.Fatal(err)
	}
	if got, err = repo.GetExact(ctx, emoji.Id); err != nil || got.Name != "😀" {
		t.Fatalf("surrogate pair tenant = %+v, %v", got, err)
	}
}

func TestTenantRepo_GetExact_RejectsInvalidInputAndStorage(t *testing.T) {
	for _, tenantID := range []string{"", "Tenant", "-tenant", "tenant-", "tênant", strings.Repeat("t", 64)} {
		_, legacy := newTenantRepoForTest(t)
		if got, err := legacy.(ExactTenantRepository).GetExact(context.Background(), tenantID); got != nil || !errors.Is(err, domain.ErrInvalidTenant) {
			t.Fatalf("input %q = %+v, %v", tenantID, got, err)
		}
	}

	base := domain.Tenant{Id: "tenant-1", Slug: "bereia", Name: "Bereia", Status: domain.TenantStatusActive, CreatedAt: exactIdentityTime}
	encode := func(change func(*domain.Tenant)) string {
		copy := base
		change(&copy)
		return mustJSON(t, copy)
	}
	baseRaw := mustJSON(t, base)
	tests := []struct{ name, raw string }{
		{"empty", ""},
		{"malformed", "{"},
		{"top-level array", "[]"},
		{"field alias", strings.Replace(baseRaw, `"id"`, `"Id"`, 1)},
		{"unknown field", strings.Replace(baseRaw, "}", `,"secret":true}`, 1)},
		{"duplicate field", strings.Replace(baseRaw, "{", `{"id":"tenant-1",`, 1)},
		{"trailing document", baseRaw + "{}"},
		{"null id", strings.Replace(baseRaw, `"id":"tenant-1"`, `"id":null`, 1)},
		{"null name", strings.Replace(baseRaw, `"name":"Bereia"`, `"name":null`, 1)},
		{"invalid utf8", strings.Replace(baseRaw, "Bereia", string([]byte{0xff}), 1)},
		{"unpaired high surrogate", strings.Replace(baseRaw, `"Bereia"`, `"\ud800"`, 1)},
		{"unpaired low surrogate", strings.Replace(baseRaw, `"Bereia"`, `"\udc00"`, 1)},
		{"invalid surrogate pair", strings.Replace(baseRaw, `"Bereia"`, `"\ud800\u0041"`, 1)},
		{"field identity mismatch", encode(func(v *domain.Tenant) { v.Id = "tenant-2" })},
		{"noncanonical embedded id", encode(func(v *domain.Tenant) { v.Id = "Tenant-1" })},
		{"empty slug", encode(func(v *domain.Tenant) { v.Slug = "" })},
		{"unicode slug", encode(func(v *domain.Tenant) { v.Slug = "beréia" })},
		{"slug boundary", encode(func(v *domain.Tenant) { v.Slug = strings.Repeat("s", 64) })},
		{"padded name", encode(func(v *domain.Tenant) { v.Name = " Bereia" })},
		{"name boundary", encode(func(v *domain.Tenant) { v.Name = strings.Repeat("n", 129) })},
		{"unknown status", encode(func(v *domain.Tenant) { v.Status = "DELETED" })},
		{"zero createdAt", encode(func(v *domain.Tenant) { v.CreatedAt = time.Time{} })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rdb, legacy := newTenantRepoForTest(t)
			if err := rdb.HSet(context.Background(), tenantsHash, base.Id, test.raw).Err(); err != nil {
				t.Fatal(err)
			}
			got, err := legacy.(ExactTenantRepository).GetExact(context.Background(), base.Id)
			if got != nil || !errors.Is(err, errStoredTenantContract) || test.raw != "" && strings.Contains(err.Error(), test.raw) {
				t.Fatalf("result = %+v, %v", got, err)
			}
		})
	}
}

func TestUserRepo_GetExact_ProjectsPasswordFreeIdentity(t *testing.T) {
	rdb, legacy := newUserRepoForTest(t)
	repo := legacy.(ExactUserRepository)
	ctx := context.Background()
	missing, err := repo.GetExact(ctx, "missing")
	if err != nil || missing != nil {
		t.Fatalf("missing user = %+v, %v", missing, err)
	}

	longEmail := strings.Repeat("a", 64) + "@" + strings.Repeat("b", 189)
	users := []struct {
		user domain.User
		want domain.AuthSource
	}{
		{domain.User{Id: strings.Repeat("u", 128), Email: longEmail, Password: "explicit-hash-canary", Status: domain.UserStatusActive, CreatedAt: exactIdentityTime, AuthSource: domain.AuthSourcePassword}, domain.AuthSourcePassword},
		{domain.User{Id: "legacy-user", Email: "Case@Example.COM", Password: "legacy-hash-canary", Status: domain.UserStatusSuspended, CreatedAt: exactIdentityTime}, domain.AuthSourcePassword},
		{domain.User{Id: "legacy-empty", Email: "empty@example.com", Password: "legacy-empty-hash-canary", Status: domain.UserStatusActive, CreatedAt: exactIdentityTime}, domain.AuthSourcePassword},
		{domain.User{Id: "inactive-user", Email: "inactive@example.com", Password: "hash", Status: domain.UserStatusInactive, CreatedAt: exactIdentityTime, AuthSource: domain.AuthSourcePassword}, domain.AuthSourcePassword},
		{domain.User{Id: "saml-user", Email: "saml@example.com", Status: domain.UserStatusSuspended, CreatedAt: exactIdentityTime, AuthSource: domain.AuthSourceSAML, ExternalSubject: "saml-subject-界"}, domain.AuthSourceSAML},
		{domain.User{Id: "saml-max", Email: "max@example.com", Status: domain.UserStatusActive, CreatedAt: exactIdentityTime, AuthSource: domain.AuthSourceSAML, ExternalSubject: strings.Repeat("s", 512)}, domain.AuthSourceSAML},
	}
	for _, test := range users {
		raw := mustJSON(t, test.user)
		if test.user.Id == "legacy-user" {
			raw = strings.Replace(raw, `,"authSource":""`, "", 1)
			if strings.Contains(raw, `"authSource"`) {
				t.Fatal("legacy absent-source fixture still contains authSource")
			}
		}
		if err := rdb.HSet(ctx, usersHashV2, test.user.Id, raw).Err(); err != nil {
			t.Fatal(err)
		}
		if err := rdb.Set(ctx, userByEmailKeyNS+test.user.Email, test.user.Id, 0).Err(); err != nil {
			t.Fatal(err)
		}
		got, err := repo.GetExact(ctx, test.user.Id)
		if err != nil || got == nil || got.Id != test.user.Id || got.Email != test.user.Email || got.Status != test.user.Status || got.AuthSource != test.want || got.CreatedAt != exactIdentityTime {
			t.Fatalf("exact user = %+v, %v", got, err)
		}
		projection, _ := json.Marshal(got)
		if strings.Contains(string(projection), `"password":`) || strings.Contains(string(projection), "hash-canary") || strings.Contains(string(projection), "externalSubject") {
			t.Fatalf("unsafe projection: %s", projection)
		}
		stored, _ := rdb.HGet(ctx, usersHashV2, test.user.Id).Result()
		if stored != raw {
			t.Fatal("exact read repaired or rewrote a user")
		}
	}
}

func TestUserRepo_GetExact_RejectsInvalidInputAndStorage(t *testing.T) {
	for _, userID := range []string{"", " user", "user/id", "usér", strings.Repeat("u", 129)} {
		_, legacy := newUserRepoForTest(t)
		if got, err := legacy.(ExactUserRepository).GetExact(context.Background(), userID); got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
			t.Fatalf("input %q = %+v, %v", userID, got, err)
		}
	}

	base := domain.User{Id: "user-1", Email: "User@example.COM", Password: "hash-canary", Status: domain.UserStatusActive, CreatedAt: exactIdentityTime, AuthSource: domain.AuthSourcePassword}
	encode := func(change func(*domain.User)) string {
		copy := base
		change(&copy)
		return mustJSON(t, copy)
	}
	baseRaw := mustJSON(t, base)
	tests := []struct {
		name, raw, index string
		noIndex          bool
	}{
		{name: "empty", raw: ""},
		{name: "malformed", raw: "{"},
		{name: "field alias", raw: strings.Replace(baseRaw, `"localId"`, `"LocalId"`, 1)},
		{name: "duplicate field", raw: strings.Replace(baseRaw, "{", `{"localId":"user-1",`, 1)},
		{name: "wrong field type", raw: strings.Replace(baseRaw, `"email":"User@example.COM"`, `"email":7`, 1)},
		{name: "field identity mismatch", raw: encode(func(v *domain.User) { v.Id = "user-2" })},
		{name: "unicode embedded id", raw: encode(func(v *domain.User) { v.Id = "usér" })},
		{name: "unicode email", raw: encode(func(v *domain.User) { v.Email = "usér@example.com" })},
		{name: "email boundary", raw: encode(func(v *domain.User) { v.Email = strings.Repeat("a", 64) + "@" + strings.Repeat("b", 190) })},
		{name: "unknown status", raw: encode(func(v *domain.User) { v.Status = "DELETED" })},
		{name: "zero createdAt", raw: encode(func(v *domain.User) { v.CreatedAt = time.Time{} })},
		{name: "negative token version", raw: encode(func(v *domain.User) { v.TokenVersion = -1 })},
		{name: "null auth source", raw: strings.Replace(baseRaw, `"authSource":"password"`, `"authSource":null`, 1)},
		{name: "null optional scalar", raw: strings.Replace(baseRaw, "}", `,"tokenVersion":null}`, 1)},
		{name: "password source without password", raw: encode(func(v *domain.User) { v.Password = "" })},
		{name: "legacy source without password", raw: encode(func(v *domain.User) { v.AuthSource, v.Password = "", "" })},
		{name: "unknown auth source", raw: encode(func(v *domain.User) { v.AuthSource = "oidc" })},
		{name: "saml without subject", raw: encode(func(v *domain.User) { v.AuthSource, v.Password, v.ExternalSubject = domain.AuthSourceSAML, "", "" })},
		{name: "saml padded subject", raw: encode(func(v *domain.User) {
			v.AuthSource, v.Password, v.ExternalSubject = domain.AuthSourceSAML, "", " subject"
		})},
		{name: "saml subject boundary", raw: encode(func(v *domain.User) {
			v.AuthSource, v.Password, v.ExternalSubject = domain.AuthSourceSAML, "", strings.Repeat("s", 513)
		})},
		{name: "saml control subject", raw: encode(func(v *domain.User) {
			v.AuthSource, v.Password, v.ExternalSubject = domain.AuthSourceSAML, "", "sub\nject"
		})},
		{name: "missing exact-case index", raw: baseRaw, noIndex: true},
		{name: "empty index", raw: baseRaw, index: ""},
		{name: "mismatched index", raw: baseRaw, index: "other-user"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rdb, legacy := newUserRepoForTest(t)
			ctx := context.Background()
			if err := rdb.HSet(ctx, usersHashV2, base.Id, test.raw).Err(); err != nil {
				t.Fatal(err)
			}
			if !test.noIndex {
				index := test.index
				if index == "" && test.name != "empty index" {
					index = base.Id
				}
				if err := rdb.Set(ctx, userByEmailKeyNS+base.Email, index, 0).Err(); err != nil {
					t.Fatal(err)
				}
			}
			got, err := legacy.(ExactUserRepository).GetExact(ctx, base.Id)
			if got != nil || !errors.Is(err, errStoredUserContract) || strings.Contains(err.Error(), "hash-canary") {
				t.Fatalf("result = %+v, %v", got, err)
			}
		})
	}
}

func TestExactIdentityValidatorCharacterBoundaries(t *testing.T) {
	offset, offsetOK := jsonHexUnit("xdfff", 1)
	exact, exactOK := jsonHexUnit("d800", 0)
	_, shortOK := jsonHexUnit("fff", 0)
	done := make(chan map[string]bool, 1)
	go func() {
		done <- map[string]bool{
			"tenant minimum": canonicalTenantIdentity("a"), "tenant edge chars": canonicalTenantIdentity("a-z09"),
			"user minimum": canonicalUserIdentity("A"), "user edge chars": canonicalUserIdentity("AZaz09._:-"),
			"email minimum": canonicalEmail("!@~"), "email truncated": !canonicalEmail("a@"),
			"email low control": !canonicalEmail("a @b"), "email high control": !canonicalEmail("a@\x7f"),
			"name unicode minimum": validTenantName("界"), "name control": !validTenantName("a\nb"),
			"subject minimum": validExternalSubject("界"), "subject control": !validExternalSubject("a\x00b"),
			"low surrogate max": !validJSONUnicode(`"\udfff"`), "low pair minimum": validJSONUnicode(`"\ud800\udc00"`),
			"high pair maximum": validJSONUnicode(`"\udbff\udfff"`), "truncated high": !validJSONUnicode(`"\ud80"`),
			"truncated scalar": !validJSONUnicode(`"\u000"`), "truncated pair": !validJSONUnicode(`"\ud800\udc0"`),
			"dangling escape": !validJSONUnicode(string([]byte{'"', '\\'})), "hex offset": offsetOK && offset == 0xdfff,
			"hex exact": exactOK && exact == 0xd800, "hex short": !shortOK,
		}
	}()
	select {
	case tests := <-done:
		for name, valid := range tests {
			if !valid {
				t.Errorf("boundary %s was not discriminated", name)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("Unicode validation did not terminate")
	}
}

func TestExactIdentityReads_PropagateRedisErrors(t *testing.T) {
	want := errors.New("redis unavailable")
	_, tenantLegacy := newTenantRepoForTest(t)
	tenant := tenantLegacy.(*tenantRepo)
	tenant.client.AddHook(commandErrorHook{byName: map[string]error{"hget": want}})
	if _, err := tenant.GetExact(context.Background(), "tenant-1"); !errors.Is(err, want) {
		t.Fatalf("tenant error = %v", err)
	}

	rdb, userLegacy := newUserRepoForTest(t)
	user := domain.User{Id: "user-1", Email: "user@example.com", Password: "hash", Status: domain.UserStatusActive, CreatedAt: exactIdentityTime, AuthSource: domain.AuthSourcePassword}
	if err := rdb.HSet(context.Background(), usersHashV2, user.Id, mustJSON(t, user)).Err(); err != nil {
		t.Fatal(err)
	}
	rdb.AddHook(commandErrorHook{byName: map[string]error{"get": want}})
	if _, err := userLegacy.(ExactUserRepository).GetExact(context.Background(), user.Id); !errors.Is(err, want) {
		t.Fatalf("user index error = %v", err)
	}
}

func FuzzExactIdentityValidators(f *testing.F) {
	for _, seed := range []string{"", "bereia", "-tenant", "usér@example.com", strings.Repeat("a", 255), `{\"id\":\"tenant\"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_ = canonicalTenantIdentity(value)
		_ = canonicalUserIdentity(value)
		_ = canonicalEmail(value)
		_ = validTenantName(value)
		_ = validExternalSubject(value)
		var tenant domain.Tenant
		_ = decodeExactObject(value, tenantFields, &tenant)
	})
}
