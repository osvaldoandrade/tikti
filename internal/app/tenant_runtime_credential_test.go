package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/internal/storagests"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

// Independently computed with OpenSSL and Python's hmac module:
//
//	printf '%s' 'code-foundry/tikti/tenant-runtime-state/v1' | openssl dgst -sha256 -hmac '<key>'
const (
	derivedKnownVectorKey   = "tikti-derived-credential-known-vector"
	derivedKnownVector      = "c187225187eeb9c08bf24c01c89f10f22f1da1f20c8590728374389e64ee23a4"
	derivedRuntimeTestKey   = "42e9e1da445b1bbd21eed655ab220adbce9b071b06dec7becf34872e3b61821a" // HMAC(runtimeTestKey, label v1)
	derivedWrongLabelV2     = "d080578d43e5b7ffadab0d0ec1015900d99ba7a955ee416d0bb480e07b264aac" // HMAC(runtimeTestKey, ".../v2")
	apiKeyMiddlewareRefusal = `{"error":"Invalid or missing API key"}`
)

func hmacHex(key, message string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestSQLTenantRuntimeDerivedCredentialKnownVector(t *testing.T) {
	if tenantRuntimeStateCredentialLabel != "code-foundry/tikti/tenant-runtime-state/v1" {
		t.Fatal("derived credential label changed; every installation Secret would break")
	}
	for _, test := range []struct{ master, want string }{
		{derivedKnownVectorKey, derivedKnownVector},
		{runtimeTestKey, derivedRuntimeTestKey},
	} {
		got, ok := deriveTenantRuntimeStateCredential(test.master)
		if !ok || got != test.want || len(got) != 64 || strings.ToLower(got) != got {
			t.Fatalf("derived credential differs from the independent vector")
		}
	}
	if got, ok := deriveTenantRuntimeStateCredential(""); ok || got != "" {
		t.Fatal("an empty master derived a credential")
	}
	if hmacHex(runtimeTestKey, "code-foundry/tikti/tenant-runtime-state/v2") != derivedWrongLabelV2 {
		t.Fatal("wrong-label fixture differs from its independent vector")
	}
}

func runtimeStatusWithKey(engine http.Handler, key string, edit func(*http.Request)) *httptest.ResponseRecorder {
	request := authorityRequest(http.MethodGet, runtimeTestPath, nil)
	request.Header.Set("X-API-Key", key)
	if edit != nil {
		edit(request)
	}
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	return response
}

func TestSQLTenantRuntimeDerivedCredentialAcceptedOnRuntimeStateOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	application, counter := runtimeApplication(t, true)
	for _, test := range []struct {
		name, key string
		edit      func(*http.Request)
		status    int
		code      string
	}{
		{name: "derived", key: derivedRuntimeTestKey, status: http.StatusOK},
		{name: "master", key: runtimeTestKey, status: http.StatusOK},
		{name: "wrong", key: "incorrect-secret-sentinel", status: http.StatusUnauthorized, code: "TenantRuntimeUnauthorized"},
		{name: "empty", key: "", status: http.StatusUnauthorized, code: "TenantRuntimeUnauthorized"},
		{name: "wrong label", key: derivedWrongLabelV2, status: http.StatusUnauthorized, code: "TenantRuntimeUnauthorized"},
		{name: "wrong master", key: hmacHex("other-master-sentinel", tenantRuntimeStateCredentialLabel), status: http.StatusUnauthorized, code: "TenantRuntimeUnauthorized"},
		{name: "derived from empty", key: hmacHex("", tenantRuntimeStateCredentialLabel), status: http.StatusUnauthorized, code: "TenantRuntimeUnauthorized"},
		{name: "uppercase derived", key: strings.ToUpper(derivedRuntimeTestKey), status: http.StatusUnauthorized, code: "TenantRuntimeUnauthorized"},
		{name: "truncated derived", key: derivedRuntimeTestKey[:63], status: http.StatusUnauthorized, code: "TenantRuntimeUnauthorized"},
		{name: "raw derived bytes", key: string(mustDecodeHex(t, derivedRuntimeTestKey)), status: http.StatusUnauthorized, code: "TenantRuntimeUnauthorized"},
		{name: "derived of derived", key: hmacHex(derivedRuntimeTestKey, tenantRuntimeStateCredentialLabel), status: http.StatusUnauthorized, code: "TenantRuntimeUnauthorized"},
		{name: "duplicate derived", key: derivedRuntimeTestKey, edit: func(r *http.Request) { r.Header.Add("X-API-Key", derivedRuntimeTestKey) }, status: http.StatusUnauthorized, code: "TenantRuntimeUnauthorized"},
		// Every pre-existing request-shape check still applies to the derived key.
		{name: "derived post", key: derivedRuntimeTestKey, edit: func(r *http.Request) { r.Method = http.MethodPost }, status: http.StatusBadRequest, code: "TenantRuntimeInvalidRequest"},
		{name: "derived query", key: derivedRuntimeTestKey, edit: func(r *http.Request) { r.URL.RawQuery = "a=b" }, status: http.StatusBadRequest, code: "TenantRuntimeInvalidRequest"},
		{name: "derived origin", key: derivedRuntimeTestKey, edit: func(r *http.Request) { r.Header.Set("Origin", "https://console.example.com") }, status: http.StatusBadRequest, code: "TenantRuntimeInvalidRequest"},
		{name: "derived cookie", key: derivedRuntimeTestKey, edit: func(r *http.Request) { r.Header.Set("Cookie", "a=b") }, status: http.StatusBadRequest, code: "TenantRuntimeInvalidRequest"},
		{name: "derived authorization", key: derivedRuntimeTestKey, edit: func(r *http.Request) { r.Header.Set("Authorization", "Bearer x") }, status: http.StatusBadRequest, code: "TenantRuntimeInvalidRequest"},
		{name: "derived no version", key: derivedRuntimeTestKey, edit: func(r *http.Request) { r.Header.Del("X-Code-Foundry-Tenant-Runtime") }, status: http.StatusBadRequest, code: "TenantRuntimeInvalidRequest"},
		{name: "derived no nonce", key: derivedRuntimeTestKey, edit: func(r *http.Request) { r.Header.Del("X-Code-Foundry-Tenant-Runtime-Nonce") }, status: http.StatusBadRequest, code: "TenantRuntimeInvalidRequest"},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := counter.reads.Load()
			response := runtimeStatusWithKey(application.Engine, test.key, test.edit)
			if response.Code != test.status || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("status=%d want %d", response.Code, test.status)
			}
			if test.status != http.StatusOK {
				if response.Body.String() != `{"code":"`+test.code+`"}` || counter.reads.Load() != before {
					t.Fatalf("rejection was not the static pre-storage error: %d reads", counter.reads.Load()-before)
				}
				return
			}
			if !strings.Contains(response.Body.String(), `"state":"ABSENT"`) || counter.reads.Load() == before {
				t.Fatal("accepted credential did not perform the read")
			}
		})
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestSQLTenantRuntimeDerivedCredentialDisabledForEmptyMaster(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	reader := repository.NewTenantRepo(client).(repository.RetainedTenantRepository)
	// Configuration validation already refuses this combination at startup;
	// the handler must fail closed on its own as well.
	engine := newSafeEngineWithWriters(&strings.Builder{}, &strings.Builder{})
	setupTenantRuntimeMappings(engine, &config.Config{ApiKey: "", TenantRuntimeAuthorityV1: true}, reader)
	for _, key := range []string{"", hmacHex("", tenantRuntimeStateCredentialLabel), derivedRuntimeTestKey, runtimeTestKey} {
		response := runtimeStatusWithKey(engine, key, nil)
		if response.Code != http.StatusUnauthorized || response.Body.String() != `{"code":"TenantRuntimeUnauthorized"}` {
			t.Fatalf("empty master accepted a credential: status=%d", response.Code)
		}
	}
}

// fullRouterWithEveryAPIKeyRoute assembles the production router order
// (NewApplication, browser CORS, SetupMappings) with every optional
// API-key-protected route family enabled, so route discovery below covers
// the complete set rather than a hand-maintained list.
func fullRouterWithEveryAPIKeyRoute(t *testing.T) *gin.Engine {
	t.Helper()
	t.Setenv("REDIS_URL", "")
	t.Setenv("REDIS_PASSWORD", "")
	mr := miniredis.RunT(t)
	application, err := NewApplication(&config.Config{RedisURL: "redis://" + mr.Addr(), ApiKey: runtimeTestKey, JwtSecret: strings.Repeat("j", 32), TenantRuntimeAuthorityV1: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Redis.Close() })
	application.Engine.Use(cors.New(cors.Config{AllowOrigins: []string{"https://console.example.com"}, AllowMethods: []string{"GET", "OPTIONS"}, AllowCredentials: true}))
	expanded := *application.Config
	expanded.AIGateway.Enabled = true
	expanded.TenantScopedTokenClaimsV1 = true
	expanded.ObjectStorageBrowser = config.ObjectStorageBrowserConfig{Enabled: true, DeleteEnabled: true}
	SetupMappings(application.Engine, &expanded, application.UserService, application.TenantSvc, application.RoleSvc, application.ClientSvc, application.WorkloadSvc, application.WorkloadAccountSvc, saml.NewRedisStore(application.Redis), nil)
	setupAIGatewayIdentityMappings(application.Engine, &expanded, &routeAIIdentityService{}, application.UserService)
	setupObjectStorageBrowserMappings(application.Engine, &expanded, storagests.NewAdminController(&adminControllerBrokerAdapter{}))
	return application.Engine
}

func concreteRoutePath(pattern string) string {
	segments := strings.Split(pattern, "/")
	for index, segment := range segments {
		switch {
		case segment == ":tenantId":
			segments[index] = "payments"
		case segment == ":bucketId":
			segments[index] = "invoices"
		case strings.HasPrefix(segment, ":"):
			segments[index] = "x1"
		case strings.HasPrefix(segment, "*"):
			segments[index] = "x1"
		}
	}
	return strings.Join(segments, "/")
}

func serveRoute(engine http.Handler, method, path, key string, withKey bool) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	if withKey {
		request.Header.Set("X-API-Key", key)
	}
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	return response
}

func TestSQLTenantRuntimeDerivedCredentialRejectedByEveryOtherAPIKeyRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := fullRouterWithEveryAPIKeyRoute(t)
	protected := map[string]bool{}
	for _, route := range engine.Routes() {
		if strings.HasPrefix(route.Path, tenantRuntimePrefix) {
			continue
		}
		path := concreteRoutePath(route.Path)
		name := route.Method + " " + route.Path
		unauthenticated := serveRoute(engine, route.Method, path, "", false)
		if unauthenticated.Code != http.StatusUnauthorized || unauthenticated.Body.String() != apiKeyMiddlewareRefusal {
			continue
		}
		// The master key passes the API-key layer on this route, so its
		// refusal of the derived key is a real scope boundary, not a 404.
		if master := serveRoute(engine, route.Method, path, runtimeTestKey, true); master.Body.String() == apiKeyMiddlewareRefusal {
			t.Fatalf("%s: master key no longer passes the API-key layer", name)
		}
		protected[name] = true
		for _, key := range []string{derivedRuntimeTestKey, " " + derivedRuntimeTestKey + " ", strings.ToUpper(derivedRuntimeTestKey)} {
			derived := serveRoute(engine, route.Method, path, key, true)
			if derived.Code != http.StatusUnauthorized || derived.Body.String() != apiKeyMiddlewareRefusal {
				t.Fatalf("%s accepted the tenant-runtime-state derived credential: status=%d", name, derived.Code)
			}
		}
	}
	required := []string{
		"POST /v1/workloads/bindings",
		"POST /v1/workloads/bindings/revoke",
		"GET /v1/admin/tenants/:tenantId/roles",
		"GET /v1/admin/tenants/:tenantId/roles/:roleName",
		"PUT /v1/admin/tenants/:tenantId/roles/:roleName",
		"GET /v1/admin/tenants/:tenantId/clients",
		"POST /v1/admin/tenants/:tenantId/clients",
		"GET /v1/admin/tenants/:tenantId/clients/:clientId",
		"GET /v1/admin/identity/tenant-inventory",
		"GET /v1/admin/identity/tenants/:tenantId",
		"PUT /v1/admin/identity/tenants/:tenantId",
		"DELETE /v1/admin/identity/tenants/:tenantId",
		"POST /v1/tenants/:tenantId/oob/send",
		"POST /v1/accounts/signInWithPassword",
		"POST /v1/accounts/lookup",
		"POST /v1/accounts/token/exchange",
		"POST /v1/accounts/status",
		"POST /v1/accounts/revoke",
		"POST /v1/accounts/validate",
		"POST /v1/internal/access-tokens:validate",
		"POST /v1/internal/ai/access-tokens:validate",
		"POST /v1/accounts/update",
		"POST /v1/accounts/delete",
		"GET /v1/admin/tenants/:tenantId/saml/idp",
		"PUT /v1/admin/tenants/:tenantId/saml/idp",
		"DELETE /v1/admin/tenants/:tenantId/saml/idp",
		"PUT /v1/admin/tenants/:tenantId/ai-gateway/identity",
		"PUT /v1/admin/tenants/:tenantId/ai-gateway/identity/deactivation",
		"GET /v1/admin/identity/directory/users",
		"POST /v1/admin/identity/directory/users",
		"DELETE /v1/admin/identity/directory/users/:userId",
		"PUT /v1/admin/identity/tenants/:tenantId/access-assignments/users/:userId",
		"GET /v1/admin/tenants/:tenantId/storage/buckets/:bucketId/objects",
		"POST /v1/admin/tenants/:tenantId/storage/buckets/:bucketId/objects/upload-url",
		"POST /v1/admin/tenants/:tenantId/storage/buckets/:bucketId/objects/download-url",
		"POST /v1/admin/tenants/:tenantId/storage/buckets/:bucketId/objects:delete",
	}
	for _, name := range required {
		if !protected[name] {
			names := make([]string, 0, len(protected))
			for discovered := range protected {
				names = append(names, discovered)
			}
			sort.Strings(names)
			t.Fatalf("expected API-key route %q was not discovered; discovered %d: %v", name, len(names), names)
		}
	}
	// The same router still serves the derived credential on its one route.
	if response := runtimeStatusWithKey(engine, derivedRuntimeTestKey, nil); response.Code != http.StatusOK {
		t.Fatalf("derived credential refused on the runtime-state route: %d", response.Code)
	}
	if response := runtimeStatusWithKey(engine, runtimeTestKey, nil); response.Code != http.StatusOK {
		t.Fatalf("master key refused on the runtime-state route: %d", response.Code)
	}
}
