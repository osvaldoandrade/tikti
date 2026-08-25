package controllers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type workloadAccountControllerService struct {
	token       string
	credentials domain.WorkloadAccountCredentials
	created     bool
	err         error
}

func (f *workloadAccountControllerService) Register(_ context.Context, token string, credentials domain.WorkloadAccountCredentials) (*domain.WorkloadAccountRegistrationResp, bool, error) {
	f.token, f.credentials = token, credentials
	if f.err != nil {
		return nil, false, f.err
	}
	return &domain.WorkloadAccountRegistrationResp{
		LocalId: "user-1", Email: credentials.Email, TenantID: "bereia",
		Role: "bereia-user", CreatedAt: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
	}, f.created, nil
}

func (f *workloadAccountControllerService) Session(_ context.Context, token string, credentials domain.WorkloadAccountCredentials) (*domain.WorkloadAccountSessionResp, error) {
	f.token, f.credentials = token, credentials
	if f.err != nil {
		return nil, f.err
	}
	return &domain.WorkloadAccountSessionResp{
		AccessToken: "access-token", TokenType: "Bearer", LocalId: "user-1",
		Email: credentials.Email, ExpiresIn: 900,
	}, nil
}

func TestWorkloadAccountBFFControllerContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name, path string
		created    bool
		want       int
	}{
		{name: "register created", path: "/v1/workloads/accounts/register", created: true, want: http.StatusCreated},
		{name: "register replay", path: "/v1/workloads/accounts/register", want: http.StatusOK},
		{name: "session", path: "/v1/workloads/accounts/session", want: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &workloadAccountControllerService{created: test.created}
			controller := NewWorkloadAccountBFFController(service)
			engine := gin.New()
			engine.POST("/v1/workloads/accounts/register", controller.Register)
			engine.POST("/v1/workloads/accounts/session", controller.Session)
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(`{"email":"reader@example.com","password":"correct horse battery staple"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer projected-token")
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, request)
			if response.Code != test.want || response.Header().Get("X-Tikti-Contract") != "workload-account-bff-v1" ||
				response.Header().Get("Cache-Control") != "no-store" || service.token != "projected-token" ||
				service.credentials.Email != "reader@example.com" || strings.Contains(response.Body.String(), "projected-token") {
				t.Fatalf("status=%d headers=%v body=%s service=%#v", response.Code, response.Header(), response.Body.String(), service)
			}
		})
	}
}

func TestWorkloadAccountBFFControllerRejectsUnsafeRequestsBeforeService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name, authorization, body string
		extraAuthorization        bool
		want                      int
	}{
		{name: "missing bearer", body: `{}`, want: http.StatusUnauthorized},
		{name: "wrong scheme", authorization: "Basic projected", body: `{}`, want: http.StatusUnauthorized},
		{name: "duplicate bearer", authorization: "Bearer first", extraAuthorization: true, body: `{}`, want: http.StatusUnauthorized},
		{name: "unknown field", authorization: "Bearer projected", body: `{"email":"reader@example.com","password":"correct horse battery staple","tenantId":"other"}`, want: http.StatusBadRequest},
		{name: "multiple values", authorization: "Bearer projected", body: `{"email":"reader@example.com","password":"correct horse battery staple"}{}`, want: http.StatusBadRequest},
		{name: "too large", authorization: "Bearer projected", body: `{"email":"reader@example.com","password":"` + strings.Repeat("x", (8<<10)+1) + `"}`, want: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &workloadAccountControllerService{}
			controller := NewWorkloadAccountBFFController(service)
			engine := gin.New()
			engine.POST("/v1/workloads/accounts/session", controller.Session)
			request := httptest.NewRequest(http.MethodPost, "/v1/workloads/accounts/session", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			if test.extraAuthorization {
				request.Header.Add("Authorization", "Bearer second")
			}
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, request)
			if response.Code != test.want || service.token != "" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d body=%s token=%q", response.Code, response.Body.String(), service.token)
			}
		})
	}
}

func TestWorkloadAccountBFFControllerMapsErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		err  error
		want int
	}{
		{domain.ErrInvalidArgument, http.StatusBadRequest},
		{domain.ErrWorkloadTokenInvalid, http.StatusUnauthorized},
		{domain.ErrInvalidCreds, http.StatusUnauthorized},
		{domain.ErrWorkloadBindingDenied, http.StatusForbidden},
		{domain.ErrWorkloadAccountConflict, http.StatusConflict},
		{domain.ErrMembershipConflict, http.StatusConflict},
		{domain.ErrWorkloadAccountUnavailable, http.StatusServiceUnavailable},
		{errors.New("storage token=canary"), http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		service := &workloadAccountControllerService{err: test.err}
		controller := NewWorkloadAccountBFFController(service)
		engine := gin.New()
		engine.POST("/v1/workloads/accounts/session", controller.Session)
		request := httptest.NewRequest(http.MethodPost, "/v1/workloads/accounts/session", strings.NewReader(`{"email":"reader@example.com","password":"correct horse battery staple"}`))
		request.Header.Set("Authorization", "Bearer projected")
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, request)
		if response.Code != test.want || strings.Contains(response.Body.String(), "canary") {
			t.Fatalf("error=%v status=%d body=%s", test.err, response.Code, response.Body.String())
		}
	}
}
