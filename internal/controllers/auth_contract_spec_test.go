package controllers

import (
	"context"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestAuthContractSpec_SignIn_ResponseShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{}
	svc.signInFn = func(ctx context.Context, req domain.SignInReq) (*domain.SignInResp, error) {
		if req.Email != "user@company.com" || req.Password != "secret" || !req.ReturnSecureToken {
			t.Fatalf("unexpected signIn input: %+v", req)
		}
		return &domain.SignInResp{
			IdToken:   "jwt-id-token",
			Email:     "user@company.com",
			LocalId:   "user-1",
			ExpiresIn: 3600,
		}, nil
	}

	r := gin.New()
	r.POST("/v1/accounts/signIn", NewSignInController(svc, &config.Config{}).Handle)

	rec := performJSON(t, r, http.MethodPost, "/v1/accounts/signIn", domain.SignInReq{
		Email:             "user@company.com",
		Password:          "secret",
		ReturnSecureToken: true,
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeJSONBody[domain.SignInResp](t, rec)
	if resp.IdToken == "" || resp.Email == "" || resp.LocalId == "" || resp.ExpiresIn != 3600 {
		t.Fatalf("invalid signIn response contract: %+v", resp)
	}
}

func TestAuthContractSpec_SignInWithOob_ResponseShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{}
	svc.signInWithOobCodeFn = func(ctx context.Context, req domain.SignInWithOobCodeReq) (*domain.SignInResp, error) {
		if req.Email != "user@company.com" || req.OobCode != "123456" || !req.ReturnSecureToken {
			t.Fatalf("unexpected signInWithOob input: %+v", req)
		}
		return &domain.SignInResp{
			IdToken:   "jwt-id-token",
			Email:     "user@company.com",
			LocalId:   "user-1",
			ExpiresIn: 3600,
		}, nil
	}

	r := gin.New()
	r.POST("/v1/accounts/signInWithOobCode", NewOobSignInController(svc).Handle)

	rec := performJSON(t, r, http.MethodPost, "/v1/accounts/signInWithOobCode", domain.SignInWithOobCodeReq{
		Email:             "user@company.com",
		OobCode:           "123456",
		ReturnSecureToken: true,
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeJSONBody[domain.SignInResp](t, rec)
	if resp.IdToken == "" || resp.Email != "user@company.com" || resp.LocalId != "user-1" || resp.ExpiresIn != 3600 {
		t.Fatalf("invalid signInWithOob contract: %+v", resp)
	}
}

func TestAuthContractSpec_SendOob_ResponseShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{}
	svc.sendOobFn = func(ctx context.Context, req domain.SendOobReq) (*domain.SendOobResp, error) {
		if req.RequestType != "EMAIL_SIGNIN" || req.Email != "user@company.com" {
			t.Fatalf("unexpected sendOob input: %+v", req)
		}
		return &domain.SendOobResp{
			Kind:    "identitytoolkit#GetOobConfirmationCodeResponse",
			Email:   req.Email,
			OobCode: "oob-code-1",
		}, nil
	}

	r := gin.New()
	r.POST("/v1/accounts/sendOobCode", NewOobSendController(svc, &config.Config{}).Handle)

	rec := performJSON(t, r, http.MethodPost, "/v1/accounts/sendOobCode", domain.SendOobReq{
		RequestType: "EMAIL_SIGNIN",
		Email:       "user@company.com",
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" || rec.Header().Get("X-Tikti-OOB-Delivery") != "external-required" {
		t.Fatalf("sendOob response must identify external delivery and disable caching: %v", rec.Header())
	}
	resp := decodeJSONBody[domain.SendOobResp](t, rec)
	if resp.Kind != "identitytoolkit#GetOobConfirmationCodeResponse" || resp.Email != "user@company.com" || resp.OobCode == "" {
		t.Fatalf("invalid sendOob response contract: %+v", resp)
	}
}

func TestAuthContractSpec_TokenExchange_ResponseShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{}
	svc.tokenExchangeFn = func(ctx context.Context, req domain.TokenExchangeReq) (*domain.TokenExchangeResp, error) {
		if req.IdToken != "id-token" || req.Audience != "codeq-worker" || req.TenantID != "tenant-1" {
			t.Fatalf("unexpected tokenExchange input: %+v", req)
		}
		return &domain.TokenExchangeResp{
			AccessToken: "rs256-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}, nil
	}

	r := gin.New()
	r.POST("/v1/accounts/token/exchange", NewTokenExchangeController(svc).Handle)

	rec := performJSON(t, r, http.MethodPost, "/v1/accounts/token/exchange", domain.TokenExchangeReq{
		IdToken:    "id-token",
		Audience:   "codeq-worker",
		TenantID:   "tenant-1",
		Scopes:     []string{"codeq:claim"},
		EventTypes: []string{"render_video"},
		TTLSeconds: 3600,
		Subject:    "worker-1",
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeJSONBody[domain.TokenExchangeResp](t, rec)
	if resp.AccessToken == "" || resp.TokenType != "Bearer" || resp.ExpiresIn != 3600 {
		t.Fatalf("invalid tokenExchange response contract: %+v", resp)
	}
}

func TestAuthContractSpec_TenantTargetDiscoveryShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{tokenExchangeFn: func(_ context.Context, req domain.TokenExchangeReq) (*domain.TokenExchangeResp, error) {
		if !req.DiscoverTenantTargetsV1 || req.TenantID != "bereia" || len(req.ScopeCeilingV1) != 1 {
			t.Fatalf("unexpected discovery input: %+v", req)
		}
		return &domain.TokenExchangeResp{
			AccessToken: "access", TokenType: "Bearer", ExpiresIn: 300, PrincipalTenantID: "local-tenant",
			AuthorizedTenants: []string{"bereia", "local-tenant"}, Scopes: []string{"code-admin:workloads:read"},
		}, nil
	}}
	router := gin.New()
	router.POST("/exchange", NewTokenExchangeController(svc).Handle)
	recorder := performJSON(t, router, http.MethodPost, "/exchange", domain.TokenExchangeReq{
		IdToken: "id", Audience: domain.CodeAdminAudienceClientID, TenantID: "bereia",
		DiscoverTenantTargetsV1: true, ScopeCeilingV1: []string{"code-admin:workloads:read"},
	}, "")
	response := decodeJSONBody[domain.TokenExchangeResp](t, recorder)
	if recorder.Code != http.StatusOK || response.PrincipalTenantID != "local-tenant" ||
		len(response.AuthorizedTenants) != 2 || response.AuthorizedTenants[0] != "bereia" ||
		len(response.Scopes) != 1 || response.Scopes[0] != "code-admin:workloads:read" {
		t.Fatalf("unexpected discovery response: %d %+v", recorder.Code, response)
	}
}

func TestAuthContractSpec_Lookup_ResponseFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeUserService{}
	svc.lookupFn = func(ctx context.Context, req domain.LookupReq) (*domain.LookupResp, error) {
		if req.IdToken != "id-token" {
			t.Fatalf("unexpected lookup input: %+v", req)
		}
		return &domain.LookupResp{
			Users: []domain.UserInfo{{
				LocalId: "user-1",
				Email:   "admin@company.com",
				Role:    "ADMIN",
				Tenant:  "tenant-1",
				Status:  "ACTIVE",
			}},
		}, nil
	}

	r := gin.New()
	r.POST("/v1/accounts/lookup", NewLookupController(svc, &config.Config{}).Handle)

	rec := performJSON(t, r, http.MethodPost, "/v1/accounts/lookup", domain.LookupReq{IdToken: "id-token"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeJSONBody[domain.LookupResp](t, rec)
	if len(resp.Users) != 1 {
		t.Fatalf("expected one user in lookup response, got %+v", resp)
	}
	u := resp.Users[0]
	if u.LocalId != "user-1" || u.Email != "admin@company.com" || u.Role != "ADMIN" || u.Tenant != "tenant-1" || u.Status != "ACTIVE" {
		t.Fatalf("invalid lookup response fields: %+v", u)
	}
}
