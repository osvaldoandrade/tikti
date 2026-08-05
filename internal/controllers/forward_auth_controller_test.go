package controllers

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestForwardAuthControllerAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{
		validateAccessTokenFn: func(_ context.Context, token, issuer, audience string) (jwt.MapClaims, error) {
			if token != "access-token" || issuer != "https://identity.example.com" || audience != "payments-api" {
				t.Fatalf("validation inputs token=%q issuer=%q audience=%q", token, issuer, audience)
			}
			return jwt.MapClaims{
				"sub": "user-1", "email": "user@example.com", "tid": "tenant-1",
				"role": "COMPANY_ADMIN", "scope": "payments:read",
			}, nil
		},
	}
	router := forwardAuthRouter(svc)
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/forward", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	req.Header.Set(forwardAuthAudienceHeader, "payments-api")
	req.Header.Set(forwardAuthTenantHeader, "tenant-1")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("X-Tikti-Subject") != "user-1" ||
		recorder.Header().Get("X-Tikti-Email") != "user@example.com" ||
		recorder.Header().Get("X-Tikti-Tenant") != "tenant-1" ||
		recorder.Header().Get("X-Tikti-Role") != "COMPANY_ADMIN" ||
		recorder.Header().Get("X-Tikti-Scope") != "payments:read" {
		t.Fatalf("unexpected identity headers: %v", recorder.Header())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing no-store response header")
	}
}

func TestForwardAuthControllerEnforcesServiceAndScopeRoutePolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{
		validateAccessTokenFn: func(context.Context, string, string, string) (jwt.MapClaims, error) {
			return jwt.MapClaims{
				"sub": "system:serviceaccount:workload-payments:payments-web",
				"tid": "tenant-1", "scope": "payments:read payments:write",
			}, nil
		},
	}
	router := forwardAuthRouter(svc)
	request := func(services, scopes string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/forward", nil)
		req.Header.Set("Authorization", "Bearer access-token")
		req.Header.Set(forwardAuthAudienceHeader, "payments-api")
		req.Header.Set(forwardAuthTenantHeader, "tenant-1")
		req.Header.Set(forwardAuthServicesHeader, services)
		req.Header.Set(forwardAuthScopesHeader, scopes)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}

	if response := request("payments-web,settlement-worker", "payments:read"); response.Code != http.StatusNoContent {
		t.Fatalf("valid route policy status=%d body=%s", response.Code, response.Body.String())
	}
	if response := request("settlement-worker", "payments:read"); response.Code != http.StatusForbidden {
		t.Fatalf("caller denial status=%d body=%s", response.Code, response.Body.String())
	}
	if response := request("payments-web", "payments:delete"); response.Code != http.StatusForbidden {
		t.Fatalf("scope denial status=%d body=%s", response.Code, response.Body.String())
	}
	if response := request("payments-web,payments-web", "payments:read"); response.Code != http.StatusUnauthorized {
		t.Fatalf("malformed policy status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestForwardAuthControllerAcceptsAllowlistedProjectedWorkloadToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	users := &fakeUserService{validateAccessTokenFn: func(context.Context, string, string, string) (jwt.MapClaims, error) {
		return nil, errors.New("not a Tikti access token")
	}}
	workloads := &fakeWorkloadIdentityService{verifyFn: func(_ context.Context, token string) (domain.WorkloadSubject, error) {
		if token != "projected-token" {
			t.Fatalf("projected token = %q", token)
		}
		return domain.WorkloadSubject{
			Subject:   "system:serviceaccount:workload-local-tenant:payments-web",
			Namespace: "workload-local-tenant", ServiceAccount: "payments-web",
		}, nil
	}}
	router := forwardAuthRouterWithWorkload(users, workloads)
	request := func(callers string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/forward", nil)
		req.Header.Set("Authorization", "Bearer projected-token")
		req.Header.Set(forwardAuthAudienceHeader, "payments-api")
		req.Header.Set(forwardAuthTenantHeader, "local-tenant")
		req.Header.Set(forwardAuthServicesHeader, callers)
		// User scopes do not broaden or restrict an explicitly allowlisted
		// projected ServiceAccount identity.
		req.Header.Set(forwardAuthScopesHeader, "payments:write")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}
	if response := request("payments-web"); response.Code != http.StatusNoContent ||
		response.Header().Get("X-Tikti-Subject") != "system:serviceaccount:workload-local-tenant:payments-web" ||
		response.Header().Get("X-Tikti-Tenant") != "local-tenant" {
		t.Fatalf("allowlisted workload status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if response := request("settlement-worker"); response.Code != http.StatusForbidden {
		t.Fatalf("unlisted workload status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestForwardAuthControllerDoesNotAcceptProjectedTokenWithoutCallerPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	users := &fakeUserService{validateAccessTokenFn: func(context.Context, string, string, string) (jwt.MapClaims, error) {
		return nil, errors.New("invalid")
	}}
	workloads := &fakeWorkloadIdentityService{verifyFn: func(context.Context, string) (domain.WorkloadSubject, error) {
		t.Fatal("projected verifier must not run without an explicit caller allowlist")
		return domain.WorkloadSubject{}, nil
	}}
	router := forwardAuthRouterWithWorkload(users, workloads)
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/forward", nil)
	req.Header.Set("Authorization", "Bearer projected-token")
	req.Header.Set(forwardAuthAudienceHeader, "payments-api")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestForwardAuthControllerSAMLSessionCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{
		validateIDTokenFn: func(_ context.Context, token, issuer, audience string) (jwt.MapClaims, error) {
			if token != "session-token" || issuer != "https://identity.example.com" || audience != "tikti" {
				t.Fatalf("validation inputs token=%q issuer=%q audience=%q", token, issuer, audience)
			}
			return jwt.MapClaims{"sub": "user-1", "tid": "tenant-1"}, nil
		},
	}
	router := forwardAuthRouter(svc)
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/forward", nil)
	req.AddCookie(&http.Cookie{Name: "tikti_idt", Value: "session-token"})
	req.Header.Set(forwardAuthTenantHeader, "tenant-1")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent || recorder.Header().Get("X-Tikti-Subject") != "user-1" {
		t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func TestForwardAuthControllerAccessCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{
		validateAccessTokenFn: func(_ context.Context, token, issuer, audience string) (jwt.MapClaims, error) {
			if token != "access-cookie-token" || issuer != "https://identity.example.com" || audience != "payments-api" {
				t.Fatalf("validation inputs token=%q issuer=%q audience=%q", token, issuer, audience)
			}
			return jwt.MapClaims{"sub": "user-1", "tid": "tenant-1"}, nil
		},
	}
	router := forwardAuthRouter(svc)
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/forward", nil)
	req.AddCookie(&http.Cookie{Name: "code_admin_session", Value: "access-cookie-token"})
	req.Header.Set(forwardAuthAudienceHeader, "payments-api")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent || recorder.Header().Get("X-Tikti-Subject") != "user-1" {
		t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func TestForwardAuthControllerRejectsMissingPolicyInvalidTokenAndTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{
		validateAccessTokenFn: func(context.Context, string, string, string) (jwt.MapClaims, error) {
			return nil, errors.New("invalid")
		},
		validateIDTokenFn: func(context.Context, string, string, string) (jwt.MapClaims, error) {
			return jwt.MapClaims{"sub": "user-1", "tid": "tenant-1"}, nil
		},
	}
	router := forwardAuthRouter(svc)

	tests := []struct {
		name    string
		setup   func(*http.Request)
		want    int
		noToken string
	}{
		{name: "missing", setup: func(*http.Request) {}, want: http.StatusUnauthorized},
		{name: "missing bearer policy", setup: func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer access-token")
		}, want: http.StatusUnauthorized, noToken: "access-token"},
		{name: "invalid bearer", setup: func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer access-token")
			req.Header.Set(forwardAuthAudienceHeader, "payments-api")
		}, want: http.StatusUnauthorized, noToken: "access-token"},
		{name: "tenant mismatch", setup: func(req *http.Request) {
			req.AddCookie(&http.Cookie{Name: "tikti_idt", Value: "session-token"})
			req.Header.Set(forwardAuthTenantHeader, "tenant-2")
		}, want: http.StatusForbidden, noToken: "session-token"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/auth/forward", nil)
			test.setup(req)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)
			if recorder.Code != test.want {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if test.noToken != "" && contains(recorder.Body.String(), test.noToken) {
				t.Fatalf("response leaked token: %s", recorder.Body.String())
			}
		})
	}
}

func TestForwardAuthControllerLogsSafeEarlyDenialReasons(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{}
	router := forwardAuthRouter(svc)

	var output bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	tests := []struct {
		name   string
		setup  func(*http.Request)
		reason string
	}{
		{name: "missing authentication", setup: func(*http.Request) {}, reason: "missing_authentication"},
		{name: "invalid allowed services", setup: func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer private-token")
			req.Header.Set(forwardAuthServicesHeader, "invalid/service")
		}, reason: "invalid_allowed_services_policy"},
		{name: "invalid required scopes", setup: func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer private-token")
			req.Header.Set(forwardAuthScopesHeader, "invalid,scope")
		}, reason: "invalid_required_scopes_policy"},
		{name: "missing audience", setup: func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer private-token")
		}, reason: "missing_audience_policy"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output.Reset()
			req := httptest.NewRequest(http.MethodGet, "/v1/auth/forward", nil)
			req.Header.Set("X-Request-Id", "req-safe-telemetry")
			test.setup(req)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			logged := output.String()
			if !strings.Contains(logged, "reason="+test.reason) ||
				!strings.Contains(logged, `request_id="req-safe-telemetry"`) {
				t.Fatalf("missing denial telemetry: %s", logged)
			}
			if strings.Contains(logged, "private-token") {
				t.Fatalf("telemetry leaked credential: %s", logged)
			}
		})
	}
}

func TestForwardAuthControllerDoesNotReflectInjectedIdentityHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{
		validateIDTokenFn: func(context.Context, string, string, string) (jwt.MapClaims, error) {
			return jwt.MapClaims{"sub": "trusted-user", "email": "trusted@example.com"}, nil
		},
	}
	router := forwardAuthRouter(svc)
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/forward", nil)
	req.AddCookie(&http.Cookie{Name: "tikti_idt", Value: "session-token"})
	req.Header.Set("X-Tikti-Subject", "attacker")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent || recorder.Header().Get("X-Tikti-Subject") != "trusted-user" {
		t.Fatalf("status=%d headers=%v", recorder.Code, recorder.Header())
	}
}

func forwardAuthRouter(svc *fakeUserService) http.Handler {
	return forwardAuthRouterWithWorkload(svc, nil)
}

func forwardAuthRouterWithWorkload(svc *fakeUserService, workloadSvc *fakeWorkloadIdentityService) http.Handler {
	router := gin.New()
	router.GET("/v1/auth/forward", NewForwardAuthController(svc, workloadSvc, &config.Config{
		IssuerBaseURL:   "https://identity.example.com",
		DefaultAudience: "tikti",
		SAML:            config.SAMLConfig{ACS: config.ACSConfig{CookieName: "tikti_idt"}},
		ForwardAuth:     config.ForwardAuthConfig{AccessCookieName: "code_admin_session"},
	}).Handle)
	return router
}

func contains(value, part string) bool {
	for index := 0; index+len(part) <= len(value); index++ {
		if value[index:index+len(part)] == part {
			return true
		}
	}
	return false
}
