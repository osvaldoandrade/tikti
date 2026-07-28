package controllers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/config"
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
	router := gin.New()
	router.GET("/v1/auth/forward", NewForwardAuthController(svc, &config.Config{
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
