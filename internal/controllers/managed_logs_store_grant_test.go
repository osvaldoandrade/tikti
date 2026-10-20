package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestManagedLogsStoreWireUsesExistingStrictExchange(t *testing.T) {
	gin.SetMode(gin.TestMode)
	base := `{"subjectToken":"test-projected","subjectTokenType":"urn:ietf:params:oauth:token-type:jwt","audience":"code-admin-logs-store","scopes":["cefas:table:create","cefas:table:describe"],"logsGrant":"CefasBootstrap"}`
	for _, kind := range []string{"valid", "duplicate-scopes-field", "duplicate-grant", "case-variant", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			service := &fakeWorkloadIdentityService{exchangeFn: func(_ context.Context, r domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
				calls++
				if r.LogsGrant != "CefasBootstrap" || r.Audience != "code-admin-logs-store" || r.TenantID != "" || r.LogsGrantKind != "" || r.LogsConfigUID != "" || r.LogsConfigGeneration != 0 {
					t.Error("store wire changed or acquired selectors")
				}
				return &domain.WorkloadTokenExchangeResp{TokenType: "Bearer"}, nil
			}}
			router := gin.New()
			router.POST("/v1/workloads/token/exchange", NewWorkloadIdentityController(service).Exchange)
			body := base
			switch kind {
			case "duplicate-scopes-field":
				body = base[:len(base)-1] + `,"scopes":["cefas:cluster:admin"]}`
			case "duplicate-grant":
				body = base[:len(base)-1] + `,"logsGrant":"CefasRuntime"}`
			case "case-variant":
				body = strings.ReplaceAll(base, `"scopes"`, `"Scopes"`)
			case "unknown-field":
				body = base[:len(base)-1] + `,"clusterUID":"injected"}`
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/workloads/token/exchange", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if kind == "valid" {
				if recorder.Code != http.StatusOK || calls != 1 || recorder.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("existing store exchange wire refused")
				}
			} else if recorder.Code != http.StatusBadRequest || calls != 0 {
				t.Fatal("ambiguous store exchange reached issuance")
			}
		})
	}
}
