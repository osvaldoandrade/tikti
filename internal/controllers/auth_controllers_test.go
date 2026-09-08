package controllers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestSignInController_Handle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{}
	ctrl := NewSignInController(svc, &config.Config{})
	r := gin.New()
	r.POST("/signin", ctrl.Handle)

	rec := performJSON(t, r, http.MethodPost, "/signin", nil, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	assertSensitiveResponseHeaders(t, rec)

	svc.signInFn = func(ctx context.Context, req domain.SignInReq) (*domain.SignInResp, error) {
		return nil, domain.ErrInvalidCreds
	}
	rec = performJSON(t, r, http.MethodPost, "/signin", domain.SignInReq{Email: "a", Password: "b"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	svc.signInFn = func(context.Context, domain.SignInReq) (*domain.SignInResp, error) {
		return nil, errors.New("dial redis.internal:6379 credential=signin-canary")
	}
	rec = performJSON(t, r, http.MethodPost, "/signin", domain.SignInReq{Email: "a", Password: "b"}, "")
	assertAuthenticationErrorRedacted(t, rec, http.StatusInternalServerError, "signin-canary")

	svc.signInFn = func(ctx context.Context, req domain.SignInReq) (*domain.SignInResp, error) {
		return &domain.SignInResp{IdToken: "tok", Email: req.Email}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/signin", domain.SignInReq{Email: "a", Password: "b"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	assertSensitiveResponseHeaders(t, rec)
}

func TestLookupController_Handle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{}
	ctrl := NewLookupController(svc, &config.Config{})
	r := gin.New()
	r.POST("/lookup", ctrl.Handle)

	rec := performJSON(t, r, http.MethodPost, "/lookup", nil, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	svc.lookupFn = func(ctx context.Context, req domain.LookupReq) (*domain.LookupResp, error) {
		return nil, domain.ErrInvalidToken
	}
	rec = performJSON(t, r, http.MethodPost, "/lookup", domain.LookupReq{IdToken: "x"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	svc.lookupFn = func(context.Context, domain.LookupReq) (*domain.LookupResp, error) {
		return nil, errors.New("dial redis.internal:6379 credential=lookup-canary")
	}
	rec = performJSON(t, r, http.MethodPost, "/lookup", domain.LookupReq{IdToken: "x"}, "")
	assertAuthenticationErrorRedacted(t, rec, http.StatusInternalServerError, "lookup-canary")

	svc.lookupFn = func(ctx context.Context, req domain.LookupReq) (*domain.LookupResp, error) {
		return &domain.LookupResp{Users: []domain.UserInfo{{LocalId: "u1"}}}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/lookup", domain.LookupReq{IdToken: "x"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestTokenExchangeController_Handle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{}
	ctrl := NewTokenExchangeController(svc)
	r := gin.New()
	r.POST("/exchange", ctrl.Handle)

	rec := performJSON(t, r, http.MethodPost, "/exchange", nil, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	assertSensitiveResponseHeaders(t, rec)

	internalErr := errors.New("dial redis.internal:6379 credential=exchange-canary")
	cases := []struct {
		err  error
		code int
	}{
		{domain.ErrInvalidToken, http.StatusUnauthorized},
		{domain.ErrUnauthorizedScope, http.StatusForbidden},
		{domain.ErrInvalidAudience, http.StatusBadRequest},
		{domain.ErrInvalidTenant, http.StatusBadRequest},
		{domain.ErrInvalidArgument, http.StatusBadRequest},
		{domain.ErrNotFound, http.StatusNotFound},
		{internalErr, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		svc.tokenExchangeFn = func(ctx context.Context, req domain.TokenExchangeReq) (*domain.TokenExchangeResp, error) {
			return nil, tc.err
		}
		rec = performJSON(t, r, http.MethodPost, "/exchange", domain.TokenExchangeReq{IdToken: "x", Audience: "a"}, "")
		if rec.Code != tc.code {
			t.Fatalf("err %v: expected %d got %d", tc.err, tc.code, rec.Code)
		}
		if tc.err == internalErr {
			assertAuthenticationErrorRedacted(t, rec, http.StatusInternalServerError, "exchange-canary")
		}
	}

	svc.tokenExchangeFn = func(ctx context.Context, req domain.TokenExchangeReq) (*domain.TokenExchangeResp, error) {
		return &domain.TokenExchangeResp{AccessToken: "a"}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/exchange", domain.TokenExchangeReq{IdToken: "x", Audience: "a"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	assertSensitiveResponseHeaders(t, rec)
}

func TestUpdateDeleteControllers_Handle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{}

	update := NewUpdateController(svc, &config.Config{})
	del := NewDeleteController(svc, &config.Config{})

	r := gin.New()
	r.POST("/update", update.Handle)
	r.POST("/delete", del.Handle)

	rec := performJSON(t, r, http.MethodPost, "/update", nil, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("update bad req: expected 400, got %d", rec.Code)
	}
	svc.updateUserFn = func(ctx context.Context, req domain.UpdateReq) (*domain.UpdateResp, error) {
		return nil, domain.ErrInvalidToken
	}
	rec = performJSON(t, r, http.MethodPost, "/update", domain.UpdateReq{IdToken: "x"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("update err: expected 401, got %d", rec.Code)
	}
	svc.updateUserFn = func(context.Context, domain.UpdateReq) (*domain.UpdateResp, error) {
		return nil, errors.New("dial redis.internal:6379 credential=update-canary")
	}
	rec = performJSON(t, r, http.MethodPost, "/update", domain.UpdateReq{IdToken: "x"}, "")
	assertAuthenticationErrorRedacted(t, rec, http.StatusInternalServerError, "update-canary")
	svc.updateUserFn = func(ctx context.Context, req domain.UpdateReq) (*domain.UpdateResp, error) {
		return &domain.UpdateResp{LocalId: "u1"}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/update", domain.UpdateReq{IdToken: "x"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("update ok: expected 200, got %d", rec.Code)
	}

	rec = performJSON(t, r, http.MethodPost, "/delete", nil, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete bad req: expected 400, got %d", rec.Code)
	}
	svc.deleteUserFn = func(ctx context.Context, req domain.DeleteReq) error { return domain.ErrInvalidToken }
	rec = performJSON(t, r, http.MethodPost, "/delete", domain.DeleteReq{IdToken: "x"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("delete err: expected 401, got %d", rec.Code)
	}
	svc.deleteUserFn = func(context.Context, domain.DeleteReq) error {
		return errors.New("dial redis.internal:6379 credential=delete-canary")
	}
	rec = performJSON(t, r, http.MethodPost, "/delete", domain.DeleteReq{IdToken: "x"}, "")
	assertAuthenticationErrorRedacted(t, rec, http.StatusInternalServerError, "delete-canary")
	svc.deleteUserFn = func(ctx context.Context, req domain.DeleteReq) error { return nil }
	rec = performJSON(t, r, http.MethodPost, "/delete", domain.DeleteReq{IdToken: "x"}, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "DeleteAccountResponse") {
		t.Fatalf("delete ok unexpected: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestJWKSValidateAndOobControllers_Handle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg, key := roleAccessConfig(t)
	cfg.JwtSecret = "s1"
	svc := &fakeUserService{}

	jwksCtrl := NewJWKSController(svc)
	validateCtrl := NewValidateController(svc, cfg)
	oobSend := NewOobSendController(svc, cfg)
	oobReset := NewOobResetController(svc, cfg)
	oobSignin := NewOobSignInController(svc)
	oobDispatch := NewOobDispatchController(svc)

	r := gin.New()
	r.GET("/jwks", jwksCtrl.Handle)
	r.POST("/validate", validateCtrl.Handle)
	r.POST("/send-oob", oobSend.Handle)
	r.POST("/reset-oob", oobReset.Handle)
	r.POST("/signin-oob", oobSignin.Handle)
	r.POST("/tenants/:tenantId/oob/send", oobDispatch.Handle)

	svc.jwksFn = func(ctx context.Context) (map[string]any, error) { return nil, errors.New("x") }
	rec := performJSON(t, r, http.MethodGet, "/jwks", nil, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("jwks err: expected 500, got %d", rec.Code)
	}
	svc.jwksFn = func(ctx context.Context) (map[string]any, error) { return map[string]any{"keys": []any{}}, nil }
	rec = performJSON(t, r, http.MethodGet, "/jwks", nil, "")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") == "" {
		t.Fatalf("jwks ok unexpected: %d %v", rec.Code, rec.Header())
	}

	rec = performJSON(t, r, http.MethodPost, "/validate", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("validate missing auth: expected 401, got %d", rec.Code)
	}
	admin := "Bearer " + signRoleAccessToken(t, key, jwt.MapClaims{
		"sub": "platform-admin", "role": string(domain.RoleAdmin), "scope": platformTenantAdminScope, "tid": "home",
		domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	rec = performJSON(t, r, http.MethodPost, "/validate", nil, admin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("validate bad req: expected 400, got %d", rec.Code)
	}
	svc.validateAccessTokenFn = func(ctx context.Context, tok string, iss string, aud string) (jwt.MapClaims, error) {
		return nil, errors.New("x")
	}
	rec = performJSON(t, r, http.MethodPost, "/validate", map[string]any{"token": "x", "audience": "a"}, admin)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("validate err: expected 401, got %d", rec.Code)
	}
	svc.validateAccessTokenFn = func(ctx context.Context, tok string, iss string, aud string) (jwt.MapClaims, error) {
		return jwt.MapClaims{"sub": "u1"}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/validate", map[string]any{"token": "x", "audience": "a"}, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("validate ok: expected 200, got %d", rec.Code)
	}

	rec = performJSON(t, r, http.MethodPost, "/send-oob", nil, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("send-oob bad req: expected 400, got %d", rec.Code)
	}
	svc.sendOobFn = func(ctx context.Context, req domain.SendOobReq) (*domain.SendOobResp, error) {
		return nil, domain.ErrInvalidArgument
	}
	rec = performJSON(t, r, http.MethodPost, "/send-oob", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"}, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("send-oob invalid arg: expected 400, got %d", rec.Code)
	}
	svc.sendOobFn = func(ctx context.Context, req domain.SendOobReq) (*domain.SendOobResp, error) {
		return nil, domain.ErrNotFound
	}
	rec = performJSON(t, r, http.MethodPost, "/send-oob", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"}, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("send-oob not found: expected 404, got %d", rec.Code)
	}
	svc.sendOobFn = func(context.Context, domain.SendOobReq) (*domain.SendOobResp, error) {
		return nil, errors.New("dial redis.internal:6379 credential=send-oob-canary")
	}
	rec = performJSON(t, r, http.MethodPost, "/send-oob", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"}, "")
	assertAuthenticationErrorRedacted(t, rec, http.StatusInternalServerError, "send-oob-canary")
	svc.sendOobFn = func(ctx context.Context, req domain.SendOobReq) (*domain.SendOobResp, error) {
		return &domain.SendOobResp{OobCode: "c1"}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/send-oob", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"}, "")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Tikti-OOB-Delivery") != "external-required" {
		t.Fatalf("send-oob compatibility contract unexpected: %d headers=%v", rec.Code, rec.Header())
	}

	rec = performJSON(t, r, http.MethodPost, "/reset-oob", nil, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("reset-oob bad req: expected 400, got %d", rec.Code)
	}
	svc.resetPasswordFn = func(ctx context.Context, req domain.ResetPwdReq) error { return domain.ErrInvalidArgument }
	rec = performJSON(t, r, http.MethodPost, "/reset-oob", domain.ResetPwdReq{OobCode: "x", NewPassword: "p"}, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("reset-oob invalid arg: expected 400, got %d", rec.Code)
	}
	svc.resetPasswordFn = func(ctx context.Context, req domain.ResetPwdReq) error { return domain.ErrNotFound }
	rec = performJSON(t, r, http.MethodPost, "/reset-oob", domain.ResetPwdReq{OobCode: "x", NewPassword: "p"}, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("reset-oob not found: expected 404, got %d", rec.Code)
	}
	svc.resetPasswordFn = func(context.Context, domain.ResetPwdReq) error {
		return errors.New("dial redis.internal:6379 credential=reset-oob-canary")
	}
	rec = performJSON(t, r, http.MethodPost, "/reset-oob", domain.ResetPwdReq{OobCode: "x", NewPassword: "p"}, "")
	assertAuthenticationErrorRedacted(t, rec, http.StatusInternalServerError, "reset-oob-canary")
	svc.resetPasswordFn = func(ctx context.Context, req domain.ResetPwdReq) error { return nil }
	rec = performJSON(t, r, http.MethodPost, "/reset-oob", domain.ResetPwdReq{OobCode: "x", NewPassword: "p"}, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "SetAccountPasswordResponse") {
		t.Fatalf("reset-oob ok unexpected: %d %s", rec.Code, rec.Body.String())
	}

	rec = performJSON(t, r, http.MethodPost, "/signin-oob", nil, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("signin-oob bad req: expected 400, got %d", rec.Code)
	}
	assertSensitiveResponseHeaders(t, rec)
	svc.signInWithOobCodeFn = func(ctx context.Context, req domain.SignInWithOobCodeReq) (*domain.SignInResp, error) {
		return nil, domain.ErrInvalidArgument
	}
	rec = performJSON(t, r, http.MethodPost, "/signin-oob", domain.SignInWithOobCodeReq{Email: "u@x.com", OobCode: "c"}, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("signin-oob invalid arg: expected 400, got %d", rec.Code)
	}
	svc.signInWithOobCodeFn = func(ctx context.Context, req domain.SignInWithOobCodeReq) (*domain.SignInResp, error) {
		return nil, domain.ErrInvalidOob
	}
	rec = performJSON(t, r, http.MethodPost, "/signin-oob", domain.SignInWithOobCodeReq{Email: "u@x.com", OobCode: "c"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("signin-oob invalid code: expected 401, got %d", rec.Code)
	}
	svc.signInWithOobCodeFn = func(ctx context.Context, req domain.SignInWithOobCodeReq) (*domain.SignInResp, error) {
		return nil, errors.New("dial tcp redis.internal.example:6379: connection refused")
	}
	rec = performJSON(t, r, http.MethodPost, "/signin-oob", domain.SignInWithOobCodeReq{Email: "u@x.com", OobCode: "c"}, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("signin-oob default err: expected 500, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "redis.internal") || !strings.Contains(rec.Body.String(), "authentication unavailable") {
		t.Fatalf("signin-oob leaked internal error: %s", rec.Body.String())
	}
	svc.signInWithOobCodeFn = func(ctx context.Context, req domain.SignInWithOobCodeReq) (*domain.SignInResp, error) {
		return &domain.SignInResp{IdToken: "tok"}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/signin-oob", domain.SignInWithOobCodeReq{Email: "u@x.com", OobCode: "c"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("signin-oob ok: expected 200, got %d", rec.Code)
	}
	assertSensitiveResponseHeaders(t, rec)

	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/oob/send", nil, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oob-dispatch bad req: expected 400, got %d", rec.Code)
	}
	svc.sendOobForTenantFn = func(ctx context.Context, tenantID string, req domain.SendOobReq) (*domain.SendOobTenantResp, error) {
		return nil, domain.ErrInvalidTenant
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/oob/send", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"}, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oob-dispatch invalid tenant: expected 400, got %d", rec.Code)
	}
	svc.sendOobForTenantFn = func(ctx context.Context, tenantID string, req domain.SendOobReq) (*domain.SendOobTenantResp, error) {
		return nil, domain.ErrInvalidCreds
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/oob/send", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("oob-dispatch invalid creds: expected 403, got %d", rec.Code)
	}
	svc.sendOobForTenantFn = func(ctx context.Context, tenantID string, req domain.SendOobReq) (*domain.SendOobTenantResp, error) {
		return nil, domain.ErrNotFound
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/oob/send", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"}, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("oob-dispatch not found: expected 404, got %d", rec.Code)
	}
	svc.sendOobForTenantFn = func(ctx context.Context, tenantID string, req domain.SendOobReq) (*domain.SendOobTenantResp, error) {
		return nil, errors.New("dial tcp redis.internal.example:6379: credential=canary")
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/oob/send", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"}, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("oob-dispatch default err: expected 500, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "redis.internal") || strings.Contains(rec.Body.String(), "canary") ||
		!strings.Contains(rec.Body.String(), domain.ErrAuthenticationUnavailable.Error()) {
		t.Fatalf("oob-dispatch leaked internal error: %s", rec.Body.String())
	}
	svc.sendOobForTenantFn = func(ctx context.Context, tenantID string, req domain.SendOobReq) (*domain.SendOobTenantResp, error) {
		return &domain.SendOobTenantResp{OobCode: "x"}, nil
	}
	rec = performJSON(t, r, http.MethodPost, "/tenants/t1/oob/send", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "u@x.com"}, "")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Tikti-OOB-Delivery") != "external-required" {
		t.Fatalf("oob-dispatch compatibility contract unexpected: %d headers=%v", rec.Code, rec.Header())
	}
}

func assertSensitiveResponseHeaders(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := recorder.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", got)
	}
}

func assertAuthenticationErrorRedacted(t *testing.T, recorder *httptest.ResponseRecorder, status int, canary string) {
	t.Helper()
	if recorder.Code != status || strings.Contains(recorder.Body.String(), canary) ||
		strings.Contains(recorder.Body.String(), "redis.internal") ||
		!strings.Contains(recorder.Body.String(), domain.ErrAuthenticationUnavailable.Error()) {
		t.Fatalf("authentication error was not redacted: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
