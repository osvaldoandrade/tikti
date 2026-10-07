package controllers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestWorkloadExchangeRefusalCarriesCodeAndCorrelation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		refusal    domain.WorkloadExchangeError
		wantStatus int
		wantError  string
		retryAfter string
	}{
		{refusal: domain.WorkloadExchangeError{Status: 400, Code: "InvalidRequest", CorrelationID: "c-1"}, wantStatus: 400, wantError: "invalid workload identity request"},
		{refusal: domain.WorkloadExchangeError{Status: 401, Code: "UnboundSubjectToken", CorrelationID: "c-2"}, wantStatus: 401, wantError: "invalid workload token"},
		{refusal: domain.WorkloadExchangeError{Status: 403, Code: "AuthorityPlacementMismatch", CorrelationID: "c-3"}, wantStatus: 403, wantError: "workload binding denied"},
		{refusal: domain.WorkloadExchangeError{Status: 429, Code: "RateLimited", CorrelationID: "c-4", RetryAfterSeconds: 17}, wantStatus: 429, wantError: "workload exchange rate limited", retryAfter: "17"},
		{refusal: domain.WorkloadExchangeError{Status: 503, Code: "AuthorityBusy", CorrelationID: "c-5", RetryAfterSeconds: 1}, wantStatus: 503, wantError: "workload identity unavailable", retryAfter: "1"},
		{refusal: domain.WorkloadExchangeError{Status: 500, Code: "Unexpected", CorrelationID: "c-6"}, wantStatus: 503, wantError: "workload identity unavailable"},
		{refusal: domain.WorkloadExchangeError{Status: 503, Code: "AuthorityUnavailable", CorrelationID: "c-7", RetryAfterSeconds: 1}, wantStatus: 503, wantError: "workload identity unavailable", retryAfter: "1"},
		{refusal: domain.WorkloadExchangeError{Status: 503, Code: "AuthorityUnavailable", CorrelationID: "c-8"}, wantStatus: 503, wantError: "workload identity unavailable"},
	}
	for _, test := range tests {
		refusal := test.refusal
		service := &fakeWorkloadIdentityService{exchangeFn: func(context.Context, domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
			return nil, &refusal
		}}
		router := gin.New()
		router.POST("/v1/workloads/token/exchange", NewWorkloadIdentityController(service).Exchange)
		recorder := performWorkloadRequest(t, router, "/v1/workloads/token/exchange", domain.WorkloadTokenExchangeReq{
			SubjectToken: "projected-secret", SubjectTokenType: domain.WorkloadSubjectTokenType,
			Audience: domain.WorkloadWorkerAudience, Scopes: []string{"codeq:claim"}, TenantID: "conveste", CodeQTopicID: "conveste.cflow-executar",
		})
		var body map[string]string
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: body %s", refusal.Code, recorder.Body.String())
		}
		if recorder.Code != test.wantStatus || body["error"] != test.wantError || body["code"] != refusal.Code ||
			body["correlationId"] != refusal.CorrelationID || len(body) != 3 ||
			recorder.Header().Get("Retry-After") != test.retryAfter || recorder.Header().Get("Cache-Control") != "no-store" ||
			strings.Contains(recorder.Body.String(), "projected-secret") {
			t.Fatalf("%s: %d %s headers=%v", refusal.Code, recorder.Code, recorder.Body.String(), recorder.Header())
		}
	}
}

// The request can never name cluster, namespace, ServiceAccount or UIDs: the
// strict decoder refuses those fields before the service is reached.
func TestWorkloadExchangeRejectsSpoofedIdentityFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeWorkloadIdentityService{exchangeFn: func(context.Context, domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
		t.Fatal("service reached with spoofed identity fields")
		return nil, nil
	}}
	router := gin.New()
	router.POST("/v1/workloads/token/exchange", NewWorkloadIdentityController(service).Exchange)
	for _, field := range []string{"clusterRef", "namespace", "serviceAccount", "serviceAccountName", "serviceAccountUid", "podUid", "issuer", "bindingUid"} {
		body := `{"subjectToken":"t","subjectTokenType":"urn:ietf:params:oauth:token-type:jwt","audience":"codeq-worker",` +
			`"scopes":["codeq:abandon","codeq:claim","codeq:heartbeat","codeq:nack","codeq:result"],"tenantId":"conveste",` +
			`"codeqTopicId":"conveste.cflow-executar","` + field + `":"code-cloud"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/workloads/token/exchange", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d %s", field, recorder.Code, recorder.Body.String())
		}
	}
}

func TestWorkloadExchangeDecodesCodeQTopicID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var seen domain.WorkloadTokenExchangeReq
	service := &fakeWorkloadIdentityService{exchangeFn: func(_ context.Context, req domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
		seen = req
		return &domain.WorkloadTokenExchangeResp{AccessToken: "a", TokenType: "Bearer", ExpiresIn: 300, EventTypes: []string{"cflow-executar"}}, nil
	}}
	router := gin.New()
	router.POST("/v1/workloads/token/exchange", NewWorkloadIdentityController(service).Exchange)
	body := `{"subjectToken":"t","subjectTokenType":"urn:ietf:params:oauth:token-type:jwt","audience":"codeq-producer",` +
		`"scopes":["codeq:publish"],"tenantId":"conveste","codeqTopicId":"conveste.cflow-executar"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads/token/exchange", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || seen.CodeQTopicID != "conveste.cflow-executar" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response %d %s seen=%#v", recorder.Code, recorder.Body.String(), seen)
	}
}
