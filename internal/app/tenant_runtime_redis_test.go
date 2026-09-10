package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/testredis"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestSQLTenantRuntimeRealHTTPRedisAndRedaction(t *testing.T) {
	t.Setenv("REDIS_URL", "")
	t.Setenv("REDIS_PASSWORD", "")
	redisServer, err := testredis.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer redisServer.Close()
	application, err := NewApplication(&config.Config{RedisURL: redisServer.URL, ApiKey: runtimeTestKey, JwtSecret: strings.Repeat("j", 32), TenantRuntimeAuthorityV1: true})
	if err != nil {
		t.Fatal(err)
	}
	defer application.Redis.Close()
	application.Engine.Use(cors.New(cors.Config{AllowOrigins: []string{"https://console.example.com"}, AllowMethods: []string{"GET", "OPTIONS"}, AllowCredentials: true}))
	server := httptest.NewServer(application.Engine)
	defer server.Close()
	repo := repository.NewTenantRepo(application.Redis)
	if err := repo.Create(context.Background(), &domain.Tenant{Id: "payments", Slug: "payments", Name: "private-name-sentinel", CreatedAt: time.Now().Add(-time.Hour).UTC()}); err != nil {
		t.Fatal(err)
	}
	counter := &authorityReadCounter{}
	application.Redis.AddHook(counter)
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, fixture := range []struct {
		path, method, header, value string
		status                      int
	}{
		{path: runtimeTestPath, method: "GET", status: 200},
		{path: runtimeTestPath, method: "GET", header: "Origin", value: "https://console.example.com", status: 400},
		{path: runtimeTestPath, method: "GET", header: "Authorization", value: "Bearer browser-secret-sentinel", status: 400},
		{path: runtimeTestPath, method: "GET", header: "X-API-Key", value: runtimeTestKey, status: 401},
		{path: runtimeTestPath, method: "OPTIONS", header: "Origin", value: "https://console.example.com", status: 400},
		{path: runtimeTestPath + "/", method: "GET", status: 400},
		{path: "/v1/internal/tenants/%70ayments/runtime-state", method: "GET", status: 400},
	} {
		request := authorityRequest(fixture.method, fixture.path, nil)
		request.RequestURI = ""
		request.URL.Scheme, request.URL.Host = "http", strings.TrimPrefix(server.URL, "http://")
		if fixture.header != "" {
			request.Header.Add(fixture.header, fixture.value)
		}
		beforeReads := counter.reads.Load()
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("real HTTP failed")
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != fixture.status || len(payload) > 4096 || response.Header.Get("Location") != "" || response.Header.Get("Access-Control-Allow-Origin") != "" || response.Header.Get("Cache-Control") != "no-store" || strings.Contains(string(payload), "sentinel") {
			t.Fatalf("HTTP boundary violation: %s status %d", fixture.method, response.StatusCode)
		}
		expectedReads := int64(0)
		if fixture.status == 200 {
			expectedReads = 1
		}
		if counter.reads.Load()-beforeReads != expectedReads {
			t.Fatal("real Redis boundary performed an unauthorized read or mutation")
		}
		if response.StatusCode == 200 {
			var state tenantRuntimeResponse
			if json.Unmarshal(payload, &state) != nil || state.State != "ACTIVE" {
				t.Fatal("actual Redis tenant did not produce ACTIVE")
			}
		}
	}
}

func TestSQLTenantRuntimeCredentialSentinelsStayOutOfAccessAndRecoveryLogs(t *testing.T) {
	server, err := testredis.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var logs bytes.Buffer
	engine := newSafeEngineWithWriters(&logs, &logs)
	cfg := &config.Config{ApiKey: runtimeTestKey, TenantRuntimeAuthorityV1: true}
	repo := repository.NewTenantRepo(server.Client)
	setupTenantRuntimeMappings(engine, cfg, repo.(repository.RetainedTenantRepository))
	if err := server.Client.HSet(context.Background(), "tenants", "payments", `{"password":"stored-secret-sentinel"}`).Err(); err != nil {
		t.Fatal(err)
	}
	for _, request := range []*http.Request{
		authorityRequest("GET", runtimeTestPath, nil),
		authorityRequest("GET", runtimeTestPath+"?private=query-secret-sentinel", nil),
		authorityRequest("GET", runtimeTestPath, strings.NewReader("body-secret-sentinel")),
	} {
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, request)
		if response.Code < 400 || strings.Contains(response.Body.String(), "sentinel") {
			t.Fatal("error disclosed credential fixture")
		}
	}
	// Recovery must also omit raw errors even when a dependency panics.
	panicking := newSafeEngineWithWriters(&logs, &logs)
	setupTenantRuntimeMappings(panicking, cfg, panickingRetainedReader{})
	response := httptest.NewRecorder()
	panicking.ServeHTTP(response, authorityRequest("GET", runtimeTestPath, nil))
	if response.Code != 503 || response.Header().Get("Cache-Control") != "no-store" || response.Body.String() != `{"code":"TenantRuntimeUnavailable"}` {
		t.Fatal("panic escaped the static non-cacheable JSON error boundary")
	}
	for _, sentinel := range []string{runtimeTestKey, runtimeTestNonce, "stored-secret-sentinel", "query-secret-sentinel", "body-secret-sentinel", "panic-secret-sentinel"} {
		if strings.Contains(logs.String(), sentinel) {
			t.Fatal("credential/store sentinel entered access or recovery logs")
		}
	}
}

type panickingRetainedReader struct{}

func (panickingRetainedReader) GetRetained(context.Context, string, time.Time) (*domain.Tenant, error) {
	panic("panic-secret-sentinel")
}
