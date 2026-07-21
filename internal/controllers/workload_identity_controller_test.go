package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeWorkloadIdentityService struct {
	exchangeFn func(context.Context, domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error)
	upsertFn   func(context.Context, domain.WorkloadBindingUpsertReq) (*domain.WorkloadBinding, error)
	revokeFn   func(context.Context, domain.WorkloadBindingRevokeReq) (*domain.WorkloadBinding, error)
}

func (s *fakeWorkloadIdentityService) Exchange(ctx context.Context, req domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
	return s.exchangeFn(ctx, req)
}

func (s *fakeWorkloadIdentityService) UpsertBinding(ctx context.Context, req domain.WorkloadBindingUpsertReq) (*domain.WorkloadBinding, error) {
	return s.upsertFn(ctx, req)
}

func (s *fakeWorkloadIdentityService) RevokeBinding(ctx context.Context, req domain.WorkloadBindingRevokeReq) (*domain.WorkloadBinding, error) {
	return s.revokeFn(ctx, req)
}

func TestWorkloadIdentityControllerExchangeContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeWorkloadIdentityService{
		exchangeFn: func(_ context.Context, req domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
			if req.SubjectToken != "projected-secret" || req.TenantID != "payments" {
				t.Fatalf("exchange request = %#v", req)
			}
			return &domain.WorkloadTokenExchangeResp{
				AccessToken: "access-token", TokenType: "Bearer", ExpiresIn: 300,
				Audience: domain.WorkloadTargetAudience, Scopes: []string{domain.WorkloadAdminScope}, TenantID: "payments",
			}, nil
		},
	}
	router := gin.New()
	router.POST("/v1/workloads/token/exchange", NewWorkloadIdentityController(service).Exchange)
	body := domain.WorkloadTokenExchangeReq{
		SubjectToken: "projected-secret", SubjectTokenType: domain.WorkloadSubjectTokenType,
		Audience: domain.WorkloadTargetAudience, Scopes: []string{domain.WorkloadAdminScope}, TenantID: "payments",
	}
	recorder := performWorkloadRequest(t, router, "/v1/workloads/token/exchange", body)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"accessToken":"access-token"`) {
		t.Fatalf("exchange response = %d %s headers=%v", recorder.Code, recorder.Body.String(), recorder.Header())
	}
}

func TestWorkloadIdentityControllerErrorsDoNotLeakTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name string
		err  error
		code int
	}{
		{name: "invalid", err: domain.ErrInvalidArgument, code: http.StatusBadRequest},
		{name: "token", err: domain.ErrWorkloadTokenInvalid, code: http.StatusUnauthorized},
		{name: "binding", err: domain.ErrWorkloadBindingDenied, code: http.StatusForbidden},
		{name: "unavailable", err: domain.ErrWorkloadIdentityUnavailable, code: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeWorkloadIdentityService{exchangeFn: func(context.Context, domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
				return nil, test.err
			}}
			router := gin.New()
			router.POST("/v1/workloads/token/exchange", NewWorkloadIdentityController(service).Exchange)
			recorder := performWorkloadRequest(t, router, "/v1/workloads/token/exchange", domain.WorkloadTokenExchangeReq{
				SubjectToken: "projected-secret", SubjectTokenType: domain.WorkloadSubjectTokenType,
				Audience: domain.WorkloadTargetAudience, Scopes: []string{domain.WorkloadAdminScope}, TenantID: "payments",
			})
			if recorder.Code != test.code || recorder.Header().Get("Cache-Control") != "no-store" || strings.Contains(recorder.Body.String(), "projected-secret") {
				t.Fatalf("error response = %d %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestWorkloadIdentityControllerRejectsUnknownTrailingAndOversizedJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeWorkloadIdentityService{exchangeFn: func(context.Context, domain.WorkloadTokenExchangeReq) (*domain.WorkloadTokenExchangeResp, error) {
		t.Fatal("service must not be called for invalid JSON")
		return nil, nil
	}}
	router := gin.New()
	router.POST("/v1/workloads/token/exchange", NewWorkloadIdentityController(service).Exchange)

	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "unknown field", body: `{"subjectToken":"token","unknown":true}`, want: http.StatusBadRequest},
		{name: "multiple values", body: `{}` + `{}`, want: http.StatusBadRequest},
		{name: "oversized", body: `{"subjectToken":"` + strings.Repeat("x", maxWorkloadIdentityRequestBytes) + `"}`, want: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/workloads/token/exchange", strings.NewReader(test.body))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if recorder.Code != test.want || recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response = %d %s headers=%v", recorder.Code, recorder.Body.String(), recorder.Header())
			}
		})
	}
}

func performWorkloadRequest(t *testing.T, handler http.Handler, target string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}
