package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const runtimeTestKey = "private-authority-key-sentinel"
const runtimeTestNonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const runtimeTestPath = "/v1/internal/tenants/payments/runtime-state"

type authorityReadCounter struct{ reads atomic.Int64 }

func (h *authorityReadCounter) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
	h.reads.Add(1)
	return ctx, nil
}
func (*authorityReadCounter) AfterProcess(context.Context, redis.Cmder) error { return nil }
func (h *authorityReadCounter) BeforeProcessPipeline(ctx context.Context, cmds []redis.Cmder) (context.Context, error) {
	h.reads.Add(int64(len(cmds)))
	return ctx, nil
}
func (*authorityReadCounter) AfterProcessPipeline(context.Context, []redis.Cmder) error { return nil }

func runtimeApplication(t *testing.T, enabled bool) (*Application, *authorityReadCounter) {
	t.Helper()
	t.Setenv("REDIS_URL", "")
	t.Setenv("REDIS_PASSWORD", "")
	mr := miniredis.RunT(t)
	application, err := NewApplication(&config.Config{RedisURL: "redis://" + mr.Addr(), ApiKey: runtimeTestKey, JwtSecret: strings.Repeat("j", 32), TenantRuntimeAuthorityV1: enabled})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Redis.Close() })
	// Match cmd/tikti: browser CORS is attached after machine registration.
	application.Engine.Use(cors.New(cors.Config{AllowOrigins: []string{"https://console.example.com"}, AllowMethods: []string{"GET", "OPTIONS"}, AllowCredentials: true}))
	SetupMappings(application.Engine, application.Config, application.UserService, application.TenantSvc, application.RoleSvc, application.ClientSvc, application.WorkloadSvc, application.WorkloadAccountSvc, nil, nil)
	counter := &authorityReadCounter{}
	application.Redis.AddHook(counter)
	return application, counter
}

func authorityRequest(method, path string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, path, body)
	request.Header.Set("X-API-Key", runtimeTestKey)
	request.Header.Set("X-Code-Foundry-Tenant-Runtime", "tenant-runtime/v1")
	request.Header.Set("X-Code-Foundry-Tenant-Runtime-Nonce", runtimeTestNonce)
	return request
}

func TestSQLTenantRuntimeActualApplicationStatesAndEpoch(t *testing.T) {
	application, _ := runtimeApplication(t, true)
	server := httptest.NewServer(application.Engine)
	defer server.Close()
	repo := repository.NewTenantRepo(application.Redis)
	birth := time.Date(2024, 1, 2, 3, 4, 5, 123456789, time.UTC)
	epochBytes := sha256.Sum256([]byte("codefoundry/tenant-lifetime/v1\x00payments\x00" + birth.Format(time.RFC3339Nano)))
	epoch := hex.EncodeToString(epochBytes[:])
	for _, state := range []string{"ABSENT", "ACTIVE", "DISABLED", "RETIRED"} {
		if state == "ACTIVE" || state == "DISABLED" {
			if err := repo.Create(context.Background(), &domain.Tenant{Id: "payments", Slug: "payments", Name: "Secret name sentinel", CreatedAt: birth, Status: domain.TenantStatus(state)}); err != nil {
				t.Fatal(err)
			}
		}
		if state == "RETIRED" {
			if err := repo.(interface {
				Retire(context.Context, string) error
			}).Retire(context.Background(), "payments"); err != nil {
				t.Fatal(err)
			}
		}
		request := authorityRequest(http.MethodGet, runtimeTestPath, nil)
		request.RequestURI = ""
		request.URL.Scheme, request.URL.Host = "http", strings.TrimPrefix(server.URL, "http://")
		before := time.Now().UTC()
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal("actual runtime HTTP request failed")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || len(body) > 4096 {
			t.Fatalf("state %s unavailable: %d", state, response.StatusCode)
		}
		var fields map[string]string
		if json.Unmarshal(body, &fields) != nil || len(fields) != 6 || fields["schemaVersion"] != "tenant-runtime/v1" || fields["tenantId"] != "payments" || fields["nonce"] != runtimeTestNonce || fields["state"] != state {
			t.Fatal("response differs from strict six-field authority contract")
		}
		wantedEpoch := epoch
		if state == "ABSENT" {
			wantedEpoch = ""
		}
		if fields["tenantEpoch"] != wantedEpoch {
			t.Fatal("tenant lifetime epoch changed or ABSENT carried one")
		}
		observed, err := time.Parse(time.RFC3339Nano, fields["observedAt"])
		if err != nil || observed.Before(before) || observed.After(time.Now().UTC()) || fields["observedAt"] != observed.UTC().Format(time.RFC3339Nano) {
			t.Fatal("observation is not a current canonical UTC timestamp")
		}
		if strings.Contains(string(body), "sentinel") || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("authority leaked data or browser/cache access")
		}
	}
}

func TestSQLTenantRuntimeRejectsBeforeStorageAndOutsideCORS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	application, counter := runtimeApplication(t, true)
	tests := []struct {
		name, method, path string
		edit               func(*http.Request)
	}{
		{name: "missing key", edit: func(r *http.Request) { r.Header.Del("X-API-Key") }},
		{name: "wrong key", edit: func(r *http.Request) { r.Header.Set("X-API-Key", "incorrect-secret-sentinel") }},
		{name: "empty key", edit: func(r *http.Request) { r.Header.Set("X-API-Key", "") }},
		{name: "missing version", edit: func(r *http.Request) { r.Header.Del("X-Code-Foundry-Tenant-Runtime") }},
		{name: "unknown version", edit: func(r *http.Request) { r.Header.Set("X-Code-Foundry-Tenant-Runtime", "tenant-runtime/v0") }},
		{name: "missing nonce", edit: func(r *http.Request) { r.Header.Del("X-Code-Foundry-Tenant-Runtime-Nonce") }},
		{name: "uppercase nonce", edit: func(r *http.Request) {
			r.Header.Set("X-Code-Foundry-Tenant-Runtime-Nonce", strings.ToUpper(runtimeTestNonce))
		}},
		{name: "short nonce", edit: func(r *http.Request) { r.Header.Set("X-Code-Foundry-Tenant-Runtime-Nonce", "a") }},
		{name: "head", method: "HEAD"}, {name: "options", method: "OPTIONS"}, {name: "post", method: "POST"},
		{name: "query", path: runtimeTestPath + "?token=query-secret-sentinel"}, {name: "empty query", path: runtimeTestPath + "?"},
		{name: "trailing slash", path: runtimeTestPath + "/"}, {name: "encoded tenant", path: "/v1/internal/tenants/%70ayments/runtime-state"},
		{name: "encoded prefix", path: "/%761/internal/tenants/payments/runtime-state"},
		{name: "double slash", path: "//v1/internal/tenants/payments/runtime-state"},
		{name: "normalized parent", path: "/v1/internal/tenants/other/../payments/runtime-state"},
		{name: "case alias", path: "/V1/internal/tenants/payments/runtime-state"},
		{name: "default tenant", path: "/v1/internal/tenants/default/runtime-state"},
		{name: "case tenant", path: "/v1/internal/tenants/Payments/runtime-state"},
		{name: "body", edit: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("body-secret-sentinel"))
			r.ContentLength = 20
		}},
		{name: "transfer", edit: func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }},
	}
	for _, header := range []string{"Origin", "Cookie", "Authorization"} {
		for _, value := range []string{"", "https://console.example.com"} {
			tests = append(tests, struct {
				name, method, path string
				edit               func(*http.Request)
			}{name: header + value, edit: func(r *http.Request) { r.Header[header] = []string{value} }})
		}
	}
	for _, header := range []string{"X-API-Key", "X-Code-Foundry-Tenant-Runtime", "X-Code-Foundry-Tenant-Runtime-Nonce"} {
		for _, mode := range []string{"duplicate", "mixed-case", "comma"} {
			tests = append(tests, struct {
				name, method, path string
				edit               func(*http.Request)
			}{name: header + mode, edit: func(r *http.Request) {
				value := r.Header.Get(header)
				switch mode {
				case "duplicate":
					r.Header.Add(header, value)
				case "mixed-case":
					r.Header[strings.ToLower(header)] = []string{value}
				case "comma":
					r.Header.Set(header, value+","+value)
				}
			}})
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			method, path := test.method, test.path
			if method == "" {
				method = "GET"
			}
			if path == "" {
				path = runtimeTestPath
			}
			request := authorityRequest(method, path, nil)
			if test.edit != nil {
				test.edit(request)
			}
			before := counter.reads.Load()
			response := httptest.NewRecorder()
			application.Engine.ServeHTTP(response, request)
			if response.Code < 400 || response.Code >= 500 || counter.reads.Load() != before || response.Header().Get("Location") != "" || response.Header().Get("Access-Control-Allow-Origin") != "" || response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), "sentinel") {
				t.Fatalf("negative %s violated machine boundary: status=%d reads=%d", test.name, response.Code, counter.reads.Load()-before)
			}
		})
	}
}

func TestSQLTenantRuntimeDefaultOffAndUnavailable(t *testing.T) {
	application, counter := runtimeApplication(t, false)
	request := authorityRequest("GET", runtimeTestPath, nil)
	request.Header.Set("Origin", "https://console.example.com")
	response := httptest.NewRecorder()
	application.Engine.ServeHTTP(response, request)
	if response.Code != 404 || counter.reads.Load() != 0 || response.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("disabled/old producer exposed authority")
	}
	application, _ = runtimeApplication(t, true)
	if err := application.Redis.Close(); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	application.Engine.ServeHTTP(response, authorityRequest("GET", runtimeTestPath, nil))
	if response.Code != 503 || strings.Contains(response.Body.String(), "redis") {
		t.Fatal("storage failure was disclosed or treated as absence")
	}
}
