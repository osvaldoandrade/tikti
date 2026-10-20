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

func TestManagedLogsExchangeDecodesTopLevelGrantKind(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var seen domain.WorkloadTokenExchangeReq
	service := &fakeWorkloadIdentityService{exchangeFn: func(_ context.Context, r domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
		seen = r
		return &domain.WorkloadTokenExchangeResp{TokenType: "Bearer"}, nil
	}}
	router := gin.New()
	router.POST("/v1/workloads/token/exchange", NewWorkloadIdentityController(service).Exchange)
	body := `{"subjectToken":"test-projected","subjectTokenType":"urn:ietf:params:oauth:token-type:jwt","audience":"codeq-worker","scopes":["codeq:claim"],"tenantId":"conveste","logsGrant":"Subscribe","grantKind":"LogRetentionPolicy","configUID":"native-policy","configGeneration":4}`
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads/token/exchange", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || seen.LogsGrant != "Subscribe" || seen.LogsGrantKind != "LogRetentionPolicy" || seen.LogsConfigUID != "native-policy" || seen.LogsConfigGeneration != 4 {
		t.Fatal("canonical top-level retained-policy selector not preserved")
	}
}
