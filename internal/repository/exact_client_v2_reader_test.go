package repository

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type exactClientCommandRecorder struct {
	seen map[string]bool
}

func (h *exactClientCommandRecorder) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
	h.seen[strings.ToLower(cmd.Name())] = true
	return ctx, nil
}

func (*exactClientCommandRecorder) AfterProcess(context.Context, redis.Cmder) error { return nil }

func (h *exactClientCommandRecorder) BeforeProcessPipeline(ctx context.Context, cmds []redis.Cmder) (context.Context, error) {
	for _, cmd := range cmds {
		h.seen[strings.ToLower(cmd.Name())] = true
	}
	return ctx, nil
}

func (*exactClientCommandRecorder) AfterProcessPipeline(context.Context, []redis.Cmder) error {
	return nil
}

var exactClientTestHash = func() string {
	hash, err := bcrypt.GenerateFromPassword([]byte("exact-client-secret-canary"), 10)
	if err != nil {
		panic(err)
	}
	return string(hash)
}()

func newExactClientReaderForTest(t *testing.T) (*redis.Client, ExactClientReader) {
	t.Helper()
	client, _ := newClientRepoForTest(t)
	return client, NewExactClientReader(client, NewTenantRepo(client).(ExactTenantRepository))
}

func seedExactClientTenant(t *testing.T, client *redis.Client, tenantID string, status domain.TenantStatus) {
	t.Helper()
	tenant := domain.Tenant{Id: tenantID, Slug: tenantID, Name: "Tenant " + tenantID, Status: status, CreatedAt: exactIdentityTime}
	if err := client.HSet(context.Background(), tenantsHash, tenantID, mustJSON(t, tenant)).Err(); err != nil {
		t.Fatal(err)
	}
}

func validStoredExactClient(clientID, tenantID string) storedExactClient {
	return storedExactClient{
		ClientId: clientID, TenantId: tenantID, SecretHash: exactClientTestHash,
		Type: domain.ClientTypeService, AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes: []string{"bereia:write", "bereia:read"}, Status: domain.ClientStatusActive,
	}
}

func seedStoredExactClient(t *testing.T, client *redis.Client, tenantID, field, value string) {
	t.Helper()
	if err := client.HSet(context.Background(), exactClientsV2Key(tenantID), field, value).Err(); err != nil {
		t.Fatal(err)
	}
}

func TestExactClientReader_GetExactRedactsCredentialAndUsesV2(t *testing.T) {
	client, reader := newExactClientReaderForTest(t)
	ctx := context.Background()
	seedExactClientTenant(t, client, "bereia", domain.TenantStatusActive)
	stored := validStoredExactClient("bereia-api", "bereia")
	stored.Status = domain.ClientStatusInactive
	raw := mustJSON(t, stored)
	seedStoredExactClient(t, client, "bereia", stored.ClientId, raw)
	seedStoredExactClient(t, client, "bereia", "public-ui", mustJSON(t, storedExactClient{
		ClientId: "public-ui", TenantId: "bereia", Type: domain.ClientTypePublic,
		AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: []string{}, Status: domain.ClientStatusActive,
	}))
	if err := client.HSet(ctx, clientsKey("bereia"), stored.ClientId, "legacy-secret-canary").Err(); err != nil {
		t.Fatal(err)
	}

	got, err := reader.GetExact(ctx, "bereia", stored.ClientId)
	if err != nil || got == nil || got.ClientId != stored.ClientId || got.TenantId != "bereia" || got.Status != domain.ClientStatusInactive ||
		!reflect.DeepEqual(got.DefaultScopes, stored.DefaultScopes) {
		t.Fatalf("GetExact() = %+v, %v", got, err)
	}
	projection, _ := json.Marshal(got)
	for _, forbidden := range []string{"secretHash", `"secret"`, exactClientTestHash, "legacy-secret-canary"} {
		if strings.Contains(string(projection), forbidden) {
			t.Fatalf("unsafe projection contains %q: %s", forbidden, projection)
		}
	}
	after, _ := client.HGet(ctx, exactClientsV2Key("bereia"), stored.ClientId).Result()
	if after != raw {
		t.Fatal("exact read mutated stored client")
	}
	if public, publicErr := reader.GetExact(ctx, "bereia", "public-ui"); publicErr != nil || public == nil || public.Type != domain.ClientTypePublic {
		t.Fatalf("public client = %+v, %v", public, publicErr)
	}
	if missing, missingErr := reader.GetExact(ctx, "bereia", "missing"); missingErr != nil || missing != nil {
		t.Fatalf("missing = %+v, %v", missing, missingErr)
	}
}

func TestExactClientReader_RequiresCanonicalInputsAndActiveTenant(t *testing.T) {
	client, reader := newExactClientReaderForTest(t)
	for _, tenantID := range []string{"", "Bereia", "-bereia", "bereia-", strings.Repeat("t", 64)} {
		if got, err := reader.GetExact(context.Background(), tenantID, "client-1"); got != nil || !errors.Is(err, domain.ErrInvalidTenant) {
			t.Fatalf("tenant %q = %+v, %v", tenantID, got, err)
		}
	}
	if got, err := reader.ListExact(context.Background(), "Bereia"); got != nil || !errors.Is(err, domain.ErrInvalidTenant) {
		t.Fatalf("list invalid tenant = %+v, %v", got, err)
	}
	for _, clientID := range []string{"", ".", "..", "-client", "client-", "client/id", "clïent", strings.Repeat("c", 129)} {
		if got, err := reader.GetExact(context.Background(), "bereia", clientID); got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
			t.Fatalf("client %q = %+v, %v", clientID, got, err)
		}
	}
	if got, err := reader.GetExact(context.Background(), "bereia", "client-1"); got != nil || !errors.Is(err, errStoredExactClientContract) {
		t.Fatalf("missing tenant = %+v, %v", got, err)
	}
	seedExactClientTenant(t, client, "bereia", domain.TenantStatusDisabled)
	if got, err := reader.ListExact(context.Background(), "bereia"); got != nil || !errors.Is(err, errStoredExactClientContract) {
		t.Fatalf("disabled tenant = %+v, %v", got, err)
	}
	var nilReader *exactClientReader
	if got, err := nilReader.GetExact(context.Background(), "bereia", "client-1"); got != nil || !errors.Is(err, errStoredExactClientContract) {
		t.Fatalf("nil reader = %+v, %v", got, err)
	}
}

func TestExactClientReader_RejectsStoredContractViolations(t *testing.T) {
	base := validStoredExactClient("client-1", "bereia")
	baseRaw := mustJSON(t, base)
	encode := func(change func(*storedExactClient)) string {
		copy := base
		copy.AllowedGrantTypes = append([]string{}, base.AllowedGrantTypes...)
		copy.DefaultScopes = append([]string{}, base.DefaultScopes...)
		change(&copy)
		return mustJSON(t, copy)
	}
	scopes501 := make([]string, 501)
	for index := range scopes501 {
		scopes501[index] = "scope:" + strings.Repeat("x", index/100) + string(rune('A'+index%26)) + string(rune('0'+index%10))
	}
	tests := []struct{ name, field, raw string }{
		{"empty", "client-1", ""}, {"malformed", "client-1", "{"}, {"array", "client-1", "[]"},
		{"oversized payload", "client-1", strings.Replace(baseRaw, "}", strings.Repeat(" ", exactClientPayloadLimit)+"}", 1)},
		{"oversized field", strings.Repeat("c", 129), baseRaw},
		{"field mismatch", "other-client", baseRaw},
		{"unknown redirectUris", "client-1", strings.Replace(baseRaw, "}", `,"redirectUris":[]}`, 1)},
		{"alias", "client-1", strings.Replace(baseRaw, `"clientId"`, `"ClientId"`, 1)},
		{"duplicate", "client-1", strings.Replace(baseRaw, "{", `{"clientId":"client-1",`, 1)},
		{"trailing", "client-1", baseRaw + "{}"},
		{"missing field", "client-1", strings.Replace(baseRaw, `,"status":"ACTIVE"`, "", 1)},
		{"null scalar", "client-1", strings.Replace(baseRaw, `"tenantId":"bereia"`, `"tenantId":null`, 1)},
		{"null grants", "client-1", strings.Replace(baseRaw, `"allowedGrantTypes":["token_exchange"]`, `"allowedGrantTypes":null`, 1)},
		{"invalid utf8", "client-1", strings.Replace(baseRaw, "bereia:read", string([]byte{0xff}), 1)},
		{"invalid surrogate", "client-1", strings.Replace(baseRaw, `"bereia:read"`, `"\ud800"`, 1)},
		{"embedded client mismatch", "client-1", encode(func(value *storedExactClient) { value.ClientId = "client-2" })},
		{"embedded tenant mismatch", "client-1", encode(func(value *storedExactClient) { value.TenantId = "storifly" })},
		{"public hash", "client-1", encode(func(value *storedExactClient) { value.Type = domain.ClientTypePublic })},
		{"service empty hash", "client-1", encode(func(value *storedExactClient) { value.SecretHash = "" })},
		{"bcrypt low cost", "client-1", encode(func(value *storedExactClient) {
			value.SecretHash = strings.Replace(exactClientTestHash, "$10$", "$09$", 1)
		})},
		{"bcrypt high cost", "client-1", encode(func(value *storedExactClient) {
			value.SecretHash = strings.Replace(exactClientTestHash, "$10$", "$15$", 1)
		})},
		{"bcrypt invalid version", "client-1", encode(func(value *storedExactClient) {
			value.SecretHash = strings.Replace(exactClientTestHash, "$2a$", "$2x$", 1)
		})},
		{"bcrypt invalid delimiter", "client-1", encode(func(value *storedExactClient) {
			value.SecretHash = exactClientTestHash[:6] + "!" + exactClientTestHash[7:]
		})},
		{"bcrypt invalid salt", "client-1", encode(func(value *storedExactClient) {
			value.SecretHash = exactClientTestHash[:7] + "!" + exactClientTestHash[8:]
		})},
		{"bcrypt salt CRLF", "client-1", encode(func(value *storedExactClient) {
			value.SecretHash = exactClientTestHash[:27] + "\r\n" + exactClientTestHash[29:]
		})},
		{"bcrypt noncanonical salt", "client-1", encode(func(value *storedExactClient) {
			value.SecretHash = exactClientTestHash[:28] + "/" + exactClientTestHash[29:]
		})},
		{"bcrypt invalid hash", "client-1", encode(func(value *storedExactClient) {
			value.SecretHash = exactClientTestHash[:59] + "!"
		})},
		{"bcrypt hash CRLF", "client-1", encode(func(value *storedExactClient) {
			value.SecretHash = exactClientTestHash[:58] + "\r\n"
		})},
		{"bcrypt noncanonical hash", "client-1", encode(func(value *storedExactClient) {
			value.SecretHash = exactClientTestHash[:59] + "/"
		})},
		{"unknown type", "client-1", encode(func(value *storedExactClient) { value.Type = "MOBILE" })},
		{"unknown status", "client-1", encode(func(value *storedExactClient) { value.Status = "DISABLED" })},
		{"empty grants", "client-1", encode(func(value *storedExactClient) { value.AllowedGrantTypes = []string{} })},
		{"duplicate grants", "client-1", encode(func(value *storedExactClient) { value.AllowedGrantTypes = []string{"token_exchange", "token_exchange"} })},
		{"unknown grant", "client-1", encode(func(value *storedExactClient) { value.AllowedGrantTypes = []string{"client_credentials"} })},
		{"null scopes", "client-1", encode(func(value *storedExactClient) { value.DefaultScopes = nil })},
		{"duplicate scope", "client-1", encode(func(value *storedExactClient) { value.DefaultScopes = []string{"read", "read"} })},
		{"unsafe scope", "client-1", encode(func(value *storedExactClient) { value.DefaultScopes = []string{"read scope"} })},
		{"long scope", "client-1", encode(func(value *storedExactClient) { value.DefaultScopes = []string{strings.Repeat("s", 129)} })},
		{"scope limit", "client-1", encode(func(value *storedExactClient) { value.DefaultScopes = scopes501 })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, reader := newExactClientReaderForTest(t)
			seedExactClientTenant(t, client, "bereia", domain.TenantStatusActive)
			seedStoredExactClient(t, client, "bereia", test.field, test.raw)
			got, err := reader.GetExact(context.Background(), "bereia", test.field)
			if !canonicalClientIdentity(test.field) {
				if got != nil || !errors.Is(err, domain.ErrInvalidArgument) {
					t.Fatalf("invalid field result = %+v, %v", got, err)
				}
				return
			}
			if got != nil || !errors.Is(err, errStoredExactClientContract) || strings.Contains(err.Error(), exactClientTestHash) {
				t.Fatalf("result = %+v, %v", got, err)
			}
		})
	}
}

func TestExactClientReader_ListExactIsAtomicBoundedAndSorted(t *testing.T) {
	client, reader := newExactClientReaderForTest(t)
	ctx := context.Background()
	seedExactClientTenant(t, client, "bereia", domain.TenantStatusActive)
	recorder := &exactClientCommandRecorder{seen: make(map[string]bool)}
	client.AddHook(recorder)
	empty, err := reader.ListExact(ctx, "bereia")
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty list = %+v, %v", empty, err)
	}
	if !recorder.seen["eval"] || recorder.seen["evalsha"] {
		t.Fatalf("ListExact commands = %+v; require direct EVAL without EVALSHA", recorder.seen)
	}
	for _, clientID := range []string{"z-client", "a-client", "m-client"} {
		seedStoredExactClient(t, client, "bereia", clientID, mustJSON(t, validStoredExactClient(clientID, "bereia")))
	}
	listed, err := reader.ListExact(ctx, "bereia")
	if err != nil || len(listed) != 3 || listed[0].ClientId != "a-client" || listed[1].ClientId != "m-client" || listed[2].ClientId != "z-client" {
		t.Fatalf("sorted list = %+v, %v", listed, err)
	}
	seedStoredExactClient(t, client, "bereia", "bad-client", "{")
	if got, listErr := reader.ListExact(ctx, "bereia"); got != nil || !errors.Is(listErr, errStoredExactClientContract) {
		t.Fatalf("corrupt list = %+v, %v", got, listErr)
	}
}

func TestExactClientReader_ListExactCapsCountFieldsAndPayloads(t *testing.T) {
	for _, test := range []struct {
		name        string
		seed        func(*testing.T, *redis.Client)
		want        int
		checkMarker bool
		marker      int64
	}{
		{name: "500 clients", want: 500, seed: func(t *testing.T, client *redis.Client) {
			values := make(map[string]any, 500)
			for index := 0; index < 500; index++ {
				id := "client-" + strings.Repeat("x", index/100) + string(rune('A'+index%26)) + string(rune('0'+index%10)) + string(rune('a'+index/26%26))
				values[id] = mustJSON(t, validStoredExactClient(id, "bereia"))
			}
			if err := client.HSet(context.Background(), exactClientsV2Key("bereia"), values).Err(); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "501 clients", checkMarker: true, marker: 0, seed: func(t *testing.T, client *redis.Client) {
			for index := 0; index < 501; index++ {
				id := "c" + strings.Repeat("x", index/100) + string(rune('A'+index%26)) + string(rune('0'+index%10)) + string(rune('a'+index/26%26))
				seedStoredExactClient(t, client, "bereia", id, mustJSON(t, validStoredExactClient(id, "bereia")))
			}
		}},
		{name: "128-byte field", want: 1, seed: func(t *testing.T, client *redis.Client) {
			id := "a" + strings.Repeat("-", 126) + "z"
			seedStoredExactClient(t, client, "bereia", id, mustJSON(t, validStoredExactClient(id, "bereia")))
		}},
		{name: "129-byte field", checkMarker: true, marker: -2, seed: func(t *testing.T, client *redis.Client) {
			seedStoredExactClient(t, client, "bereia", strings.Repeat("f", 129), "{}")
		}},
		{name: "16 KiB payload", want: 1, seed: func(t *testing.T, client *redis.Client) {
			raw := mustJSON(t, validStoredExactClient("client-1", "bereia"))
			raw = raw[:len(raw)-1] + strings.Repeat(" ", exactClientPayloadLimit-len(raw)) + "}"
			seedStoredExactClient(t, client, "bereia", "client-1", raw)
		}},
		{name: "16 KiB plus one payload", checkMarker: true, marker: -1, seed: func(t *testing.T, client *redis.Client) {
			raw := mustJSON(t, validStoredExactClient("client-1", "bereia"))
			raw = raw[:len(raw)-1] + strings.Repeat(" ", exactClientPayloadLimit+1-len(raw)) + "}"
			seedStoredExactClient(t, client, "bereia", "client-1", raw)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, reader := newExactClientReaderForTest(t)
			seedExactClientTenant(t, client, "bereia", domain.TenantStatusActive)
			test.seed(t, client)
			if test.checkMarker {
				result, evalErr := client.Eval(context.Background(), luaListExactClientsV2, []string{exactClientsV2Key("bereia")}, exactClientListLimit, exactClientPayloadLimit).Result()
				values, ok := result.([]any)
				if evalErr != nil || !ok || len(values) != 1 || values[0] != test.marker {
					t.Fatalf("Lua marker = %#v, %v; want %d", result, evalErr, test.marker)
				}
			}
			got, err := reader.ListExact(context.Background(), "bereia")
			if test.want > 0 && (err != nil || len(got) != test.want) {
				t.Fatalf("valid cap = %d, %v", len(got), err)
			}
			if test.want == 0 && (got != nil || !errors.Is(err, errStoredExactClientContract)) {
				t.Fatalf("invalid cap = %+v, %v", got, err)
			}
		})
	}
}

func TestExactClientReader_RedisAndResultFailuresAreRedacted(t *testing.T) {
	client, reader := newExactClientReaderForTest(t)
	seedExactClientTenant(t, client, "bereia", domain.TenantStatusActive)
	client.AddHook(commandErrorHook{byName: map[string]error{"eval": errors.New("redis-secret-canary")}})
	if got, err := reader.ListExact(context.Background(), "bereia"); got != nil || !errors.Is(err, errStoredExactClientContract) || strings.Contains(err.Error(), "redis-secret-canary") {
		t.Fatalf("EVAL error = %+v, %v", got, err)
	}
	for _, result := range []any{nil, "bad", []any{}, []any{int64(0)}, []any{int64(1), "odd"}} {
		if values, ok := exactClientListResult(result); ok || values != nil {
			t.Fatalf("accepted result %#v", result)
		}
	}
	if _, ok := redisResultString(7); ok {
		t.Fatal("accepted non-string Redis result")
	}
}

func TestExactClientValidationBoundaries(t *testing.T) {
	validScopes := make([]string, 500)
	for index := range validScopes {
		validScopes[index] = "scope:" + strings.Repeat("x", index/100) + string(rune('A'+index%26)) + string(rune('0'+index%10))
	}
	checks := map[string]bool{
		"client minimum": canonicalClientIdentity("a"), "client maximum": canonicalClientIdentity("a" + strings.Repeat("-", 126) + "z"),
		"client too long": !canonicalClientIdentity("a" + strings.Repeat("-", 127) + "z"), "client chars": canonicalClientIdentity("A.z_0:9"),
		"public empty hash": validExactClientSecret(domain.ClientTypePublic, ""), "public bcrypt": !validExactClientSecret(domain.ClientTypePublic, exactClientTestHash),
		"service bcrypt": validExactClientSecret(domain.ClientTypeService, exactClientTestHash), "bad hash": !validExactClientSecret(domain.ClientTypeService, "hash"),
		"grant": validExactClientGrantTypes([]string{"token_exchange"}), "grant duplicate": !validExactClientGrantTypes([]string{"token_exchange", "token_exchange"}),
		"empty scopes": validExactClientScopes([]string{}), "nil scopes": !validExactClientScopes(nil), "500 scopes": validExactClientScopes(validScopes),
		"501 scopes": !validExactClientScopes(append(validScopes, "extra")), "scope grammar": validExactClientScopes([]string{"A.z_0:/*-"}),
		"active": validExactClientStatus(domain.ClientStatusActive), "inactive": validExactClientStatus(domain.ClientStatusInactive),
	}
	for name, valid := range checks {
		if !valid {
			t.Errorf("boundary %s was not discriminated", name)
		}
	}
}

func FuzzDecodeExactClient(f *testing.F) {
	for _, seed := range []string{"", "{", `{"clientId":"c"}`, `{"defaultScopes":null}`, strings.Repeat("x", exactClientPayloadLimit+1)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		_, _ = decodeExactClient(value)
		_ = canonicalClientIdentity(value)
		_ = validExactClientScopes([]string{value})
	})
}

func TestClientIdentityProjectionHasNoCredentialFields(t *testing.T) {
	projection, err := json.Marshal(domain.ClientIdentity{ClientId: "client-1", TenantId: "bereia", Type: domain.ClientTypePublic, AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: []string{}, Status: domain.ClientStatusActive})
	if err != nil || strings.Contains(string(projection), "secret") || strings.Contains(string(projection), "hash") {
		t.Fatalf("projection = %s, %v", projection, err)
	}
}
