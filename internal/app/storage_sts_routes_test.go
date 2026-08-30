package app

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/storagests"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

type appStorageBroker struct{}

func (appStorageBroker) Exchange(context.Context, storagests.Request, string) (storagests.Result, *storagests.Error) {
	return storagests.Result{}, &storagests.Error{
		Code: storagests.CodeAccessDenied, HTTPStatus: http.StatusForbidden, Reason: "denied", Message: "Access is denied.",
	}
}

type appStorageResultBroker struct{ result storagests.Result }

func (b appStorageResultBroker) Exchange(context.Context, storagests.Request, string) (storagests.Result, *storagests.Error) {
	return b.result, nil
}

type appStorageJWKSProvider struct{}

func (appStorageJWKSProvider) JWKS(context.Context) (map[string]any, error) {
	return map[string]any{"keys": []any{}}, nil
}

func TestStorageOIDCRoutesAreDefaultOffExactAndOutsideCORS(t *testing.T) {
	disabled := gin.New()
	setupStorageOIDCMappings(disabled, &config.Config{}, nil)
	for _, route := range disabled.Routes() {
		if strings.Contains(route.Path, "/internal/v1/storage/") {
			t.Fatalf("disabled OIDC metadata registered route %#v", route)
		}
	}

	enabled := newSafeEngineWithWriters(&strings.Builder{}, &strings.Builder{})
	cfg := &config.Config{StorageSTS: config.StorageSTSConfig{Enabled: true}}
	controller := storagests.NewOIDCController(
		"https://tikti.example.com",
		"http://tikti.code-admin.svc:8080/internal/v1/storage/jwks.json",
		appStorageJWKSProvider{},
	)
	setupStorageOIDCMappings(enabled, cfg, controller)
	enabled.Use(cors.New(cors.Config{AllowOrigins: []string{"https://console.example.com"}, AllowMethods: []string{"GET"}}))

	for _, test := range []struct {
		method     string
		path       string
		wantStatus int
	}{
		{method: http.MethodGet, path: storagests.MachineOIDCDiscoveryPath, wantStatus: http.StatusOK},
		{method: http.MethodGet, path: storagests.MachineOIDCJWKSPath, wantStatus: http.StatusOK},
		{method: http.MethodGet, path: storagests.MachineOIDCDiscoveryPath + "/", wantStatus: http.StatusNotFound},
		{method: http.MethodGet, path: storagests.MachineOIDCJWKSPath + "/", wantStatus: http.StatusNotFound},
		{method: http.MethodOptions, path: storagests.MachineOIDCJWKSPath, wantStatus: http.StatusNotFound},
	} {
		request := httptest.NewRequest(test.method, test.path, nil)
		request.Header.Set("Origin", "https://console.example.com")
		response := httptest.NewRecorder()
		enabled.ServeHTTP(response, request)
		if response.Code != test.wantStatus || response.Header().Get("Location") != "" ||
			response.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("method=%s path=%s status=%d headers=%v body=%s", test.method, test.path, response.Code, response.Header(), response.Body.String())
		}
	}
}

func TestStorageSTSRouteIsDefaultOffExactAndOutsideCORS(t *testing.T) {
	disabled := gin.New()
	setupStorageSTSMappings(disabled, &config.Config{}, nil)
	for _, route := range disabled.Routes() {
		if strings.Contains(route.Path, "/storage/sts") {
			t.Fatalf("disabled broker registered route %#v", route)
		}
	}

	enabled := newSafeEngineWithWriters(&strings.Builder{}, &strings.Builder{})
	cfg := &config.Config{StorageSTS: config.StorageSTSConfig{Enabled: true}}
	controller := storagests.NewController("000000000000", appStorageBroker{}, nil)
	setupStorageSTSMappings(enabled, cfg, controller)
	// Production adds browser CORS only after NewApplication returns. Routes
	// already registered here must remain outside that middleware chain.
	enabled.Use(cors.New(cors.Config{AllowOrigins: []string{"https://console.example.com"}, AllowMethods: []string{"POST"}}))

	form := url.Values{
		"Action": {storagests.AWSQueryAction}, "Version": {storagests.AWSQueryVersion},
		"RoleArn":          {"arn:aws:iam::000000000000:role/codefoundry/payments/workload-payments/payments-api-invoices"},
		"WebIdentityToken": {"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ3b3JrbG9hZCJ9.c2lnbmF0dXJl"},
	}.Encode()
	for _, test := range []struct {
		method     string
		path       string
		wantStatus int
	}{
		{method: http.MethodPost, path: "/v1/storage/sts", wantStatus: http.StatusForbidden},
		{method: http.MethodPost, path: "/v1/storage/sts/", wantStatus: http.StatusBadRequest},
		{method: http.MethodOptions, path: "/v1/storage/sts", wantStatus: http.StatusBadRequest},
	} {
		request := httptest.NewRequest(test.method, test.path, strings.NewReader(form))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", "https://console.example.com")
		response := httptest.NewRecorder()
		enabled.ServeHTTP(response, request)
		if response.Code != test.wantStatus || response.Header().Get("Location") != "" ||
			response.Header().Get("Access-Control-Allow-Origin") != "" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("path=%s status=%d headers=%v body=%s", test.path, response.Code, response.Header(), response.Body.String())
		}
	}
}

func TestStorageSTSCredentialSentinelsNeverEnterAccessOrRecoveryLogs(t *testing.T) {
	var logs bytes.Buffer
	engine := newSafeEngineWithWriters(&logs, &logs)
	controller := storagests.NewController("000000000000", appStorageResultBroker{result: storagests.Result{
		Credentials: storagests.Credentials{
			AccessKeyID: "access-key-sentinel", SecretAccessKey: "secret-access-sentinel",
			SessionToken: "session-token-sentinel", Expiration: time.Now().Add(15 * time.Minute),
		},
		AssumedRoleARN: "arn:aws:sts::000000000000:assumed-role/codefoundry-payments/session",
		AssumedRoleID:  "assumed-role-id:session", Audience: "tikti-workload-exchange",
		Provider: "https://cluster.example.com", Subject: "system:serviceaccount:workload-payments:payments-api",
	}}, nil)
	setupStorageSTSMappings(engine, &config.Config{StorageSTS: config.StorageSTSConfig{Enabled: true}}, controller)
	request := httptest.NewRequest(http.MethodPost, "/v1/storage/sts", strings.NewReader(appStorageValidForm()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
	for _, sentinel := range []string{"access-key-sentinel", "secret-access-sentinel", "session-token-sentinel"} {
		if strings.Contains(logs.String(), sentinel) {
			t.Fatalf("storage credential %q entered logs: %s", sentinel, logs.String())
		}
	}
}

func appStorageValidForm() string {
	return url.Values{
		"Action": {storagests.AWSQueryAction}, "Version": {storagests.AWSQueryVersion},
		"RoleArn":          {"arn:aws:iam::000000000000:role/codefoundry/payments/workload-payments/payments-api-invoices"},
		"WebIdentityToken": {"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ3b3JrbG9hZCJ9.c2lnbmF0dXJl"},
	}.Encode()
}
