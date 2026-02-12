package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestUserServiceSpec_SendOob_EmailSignin_AntiEnumerationContract(t *testing.T) {
	repo := &mockUserRepo{}
	saveCalls := 0
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return nil, nil
	}
	repo.saveOobCodeFn = func(ctx context.Context, code, email, reqType string) error {
		saveCalls++
		return nil
	}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)

	resp, err := svc.SendOob(context.Background(), domain.SendOobReq{
		RequestType: "email_signin",
		Email:       "  missing@x.com  ",
	})
	if err != nil {
		t.Fatalf("expected anti-enumeration success, got %v", err)
	}
	if resp.Kind != "identitytoolkit#GetOobConfirmationCodeResponse" {
		t.Fatalf("unexpected kind: %s", resp.Kind)
	}
	if resp.Email != "missing@x.com" {
		t.Fatalf("expected trimmed email in response, got %q", resp.Email)
	}
	if _, err := uuid.Parse(resp.OobCode); err != nil {
		t.Fatalf("expected UUID oobCode, got %q (%v)", resp.OobCode, err)
	}
	if saveCalls != 0 {
		t.Fatalf("EMAIL_SIGNIN anti-enumeration must not persist unknown user code; got %d saves", saveCalls)
	}
}

func TestUserServiceSpec_SendOob_PasswordReset_PersistenceContract(t *testing.T) {
	repo := &mockUserRepo{}
	seen := struct {
		code    string
		email   string
		reqType string
		calls   int
	}{}
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		if email != "user@x.com" {
			t.Fatalf("service must lookup normalized email, got %q", email)
		}
		return &domain.User{Id: "u1", Email: "user@x.com", Status: domain.UserStatusActive}, nil
	}
	repo.saveOobCodeFn = func(ctx context.Context, code, email, reqType string) error {
		seen.calls++
		seen.code = code
		seen.email = email
		seen.reqType = reqType
		return nil
	}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)

	resp, err := svc.SendOob(context.Background(), domain.SendOobReq{
		RequestType: "password_reset",
		Email:       " user@x.com ",
	})
	if err != nil {
		t.Fatalf("expected password reset oob success, got %v", err)
	}
	if resp.Kind != "identitytoolkit#GetOobConfirmationCodeResponse" {
		t.Fatalf("unexpected kind: %s", resp.Kind)
	}
	if resp.Email != "user@x.com" {
		t.Fatalf("unexpected email: %q", resp.Email)
	}
	if resp.OobCode == "" {
		t.Fatalf("expected non-empty oobCode")
	}
	if seen.calls != 1 {
		t.Fatalf("expected exactly one persistence call, got %d", seen.calls)
	}
	if seen.email != "user@x.com" || seen.reqType != "PASSWORD_RESET" {
		t.Fatalf("unexpected persisted metadata: email=%q reqType=%q", seen.email, seen.reqType)
	}
	if seen.code != resp.OobCode {
		t.Fatalf("response oobCode must match persisted code")
	}
}

func TestUserServiceSpec_TokenExchange_WorkerClaimsContract(t *testing.T) {
	repo := &mockUserRepo{}
	membership := &mockMembershipRepo{}
	clientSvc := &mockClientService{}

	expectedUser := &domain.User{
		Id:           "user-1",
		Email:        "user@company.com",
		Role:         domain.RoleCompanyEmployee,
		Status:       domain.UserStatusActive,
		TokenVersion: 7,
	}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		if email != "user@company.com" {
			return nil, nil
		}
		return expectedUser, nil
	}
	membership.listTenantIDsByUser = func(ctx context.Context, userID string) ([]string, error) {
		if userID != "user-1" {
			t.Fatalf("unexpected user id for membership lookup: %s", userID)
		}
		return []string{"tenant-1"}, nil
	}
	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		if tenantID != "tenant-1" || clientID != "codeq-worker" {
			t.Fatalf("unexpected client lookup inputs tenant=%q client=%q", tenantID, clientID)
		}
		return &domain.Client{
			Id:            "codeq-worker",
			Status:        "ACTIVE",
			DefaultScopes: []string{"codeq:claim", "codeq:result", "codeq:subscribe"},
		}, nil
	}

	svc := NewUserService(repo, membership, nil, clientSvc, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid-2026").(*userService)
	idToken := signIDToken(t, "secret", "user@company.com")

	resp, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken:    idToken,
		Audience:   "codeq-worker",
		Scopes:     []string{"codeq:claim", "codeq:result"},
		EventTypes: []string{"render_video", "generate_master"},
		TTLSeconds: 1800,
		Subject:    "worker-1",
		TenantID:   "tenant-1",
	})
	if err != nil {
		t.Fatalf("expected token exchange success, got %v", err)
	}
	if resp.TokenType != "Bearer" {
		t.Fatalf("unexpected token type: %s", resp.TokenType)
	}
	if resp.ExpiresIn != 1800 {
		t.Fatalf("unexpected ttl: %d", resp.ExpiresIn)
	}
	if resp.AccessToken == "" {
		t.Fatalf("expected access token")
	}

	key, err := svc.getRSAPrivateKey()
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	priv := key.(*rsa.PrivateKey)
	claims, err := utils.ValidateRS256(resp.AccessToken, &priv.PublicKey, "https://api.storifly.ai", "codeq-worker")
	if err != nil {
		t.Fatalf("token must validate against public key/issuer/audience: %v", err)
	}

	if claims["sub"] != "worker-1" {
		t.Fatalf("unexpected sub: %v", claims["sub"])
	}
	if claims["tid"] != "tenant-1" {
		t.Fatalf("unexpected tenant claim: %v", claims["tid"])
	}
	if claims["email"] != "user@company.com" {
		t.Fatalf("unexpected email claim: %v", claims["email"])
	}
	if claims["scope"] != "codeq:claim codeq:result" {
		t.Fatalf("unexpected scope: %v", claims["scope"])
	}
	if claims["ver"] != float64(7) {
		t.Fatalf("unexpected token version claim: %v", claims["ver"])
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		t.Fatalf("expected non-empty jti claim")
	}
	eventTypes, ok := claims["eventTypes"].([]interface{})
	if !ok || len(eventTypes) != 2 || eventTypes[0] != "render_video" || eventTypes[1] != "generate_master" {
		t.Fatalf("unexpected eventTypes claim: %#v", claims["eventTypes"])
	}
	iat := int64(claims["iat"].(float64))
	exp := int64(claims["exp"].(float64))
	if exp-iat < 1700 || exp-iat > 1805 {
		t.Fatalf("unexpected token lifetime window (exp-iat=%d)", exp-iat)
	}

	parsed, err := jwt.Parse(resp.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return &priv.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse token with header: %v", err)
	}
	if kid, _ := parsed.Header["kid"].(string); kid != "kid-2026" {
		t.Fatalf("expected kid header from service config, got %q", kid)
	}
}

func TestUserServiceSpec_TokenExchange_DefaultSubject_MustBeValidatable(t *testing.T) {
	repo := &mockUserRepo{}
	membership := &mockMembershipRepo{}
	clientSvc := &mockClientService{}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		switch email {
		case "user@company.com":
			return &domain.User{
				Id:           "user-1",
				Email:        "user@company.com",
				Role:         domain.RoleCompanyEmployee,
				Status:       domain.UserStatusActive,
				TokenVersion: 2,
			}, nil
		case "user-1":
			// Simulates repo keyed by email only.
			return nil, nil
		default:
			return nil, nil
		}
	}
	membership.listTenantIDsByUser = func(ctx context.Context, userID string) ([]string, error) {
		return []string{"tenant-1"}, nil
	}
	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		return &domain.Client{Id: clientID, Status: "ACTIVE", DefaultScopes: []string{"codeq:claim"}}, nil
	}

	svc := NewUserService(repo, membership, nil, clientSvc, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)
	idToken := signIDToken(t, "secret", "user@company.com")

	resp, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken:  idToken,
		Audience: "codeq-worker",
		Scopes:   []string{"codeq:claim"},
		// Subject intentionally empty: service should apply default.
		EventTypes: []string{"render_video"},
		TenantID:   "tenant-1",
	})
	if err != nil {
		t.Fatalf("expected token exchange success, got %v", err)
	}

	claims, err := svc.ValidateAccessToken(context.Background(), resp.AccessToken, "https://api.storifly.ai", "codeq-worker")
	if err != nil {
		t.Fatalf("issued token must be validatable by the same service contract, got %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Fatalf("expected default subject to be user id, got %v", claims["sub"])
	}
	if claims["email"] != "user@company.com" {
		t.Fatalf("expected email claim for fallback verification, got %v", claims["email"])
	}
}

func TestUserServiceSpec_RevokeTokens_ResponseContract(t *testing.T) {
	repo := &mockUserRepo{}
	repo.incrementTokenVersionFn = func(ctx context.Context, email string) (int, *domain.User, error) {
		if email != "ops@company.com" {
			t.Fatalf("expected trimmed email, got %q", email)
		}
		return 5, &domain.User{Id: "u-ops", Email: email}, nil
	}

	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)
	resp, err := svc.RevokeTokens(context.Background(), "  ops@company.com  ", "tenant-1", "tenant")
	if err != nil {
		t.Fatalf("expected revoke success, got %v", err)
	}
	if resp.LocalId != "u-ops" || resp.Email != "ops@company.com" || resp.TokenVersion != 5 {
		t.Fatalf("unexpected revoke response: %+v", resp)
	}
	if _, err := time.Parse(time.RFC3339, resp.RevokedAt); err != nil {
		t.Fatalf("revokedAt must be RFC3339, got %q (%v)", resp.RevokedAt, err)
	}
}

func TestUserServiceSpec_RevokeTokens_ScopeValidationContract(t *testing.T) {
	repo := &mockUserRepo{}
	calls := 0
	repo.incrementTokenVersionFn = func(ctx context.Context, email string) (int, *domain.User, error) {
		calls++
		if email != "ops@company.com" {
			t.Fatalf("expected trimmed email, got %q", email)
		}
		return 2, &domain.User{Id: "u1", Email: email}, nil
	}

	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)

	if _, err := svc.RevokeTokens(context.Background(), "ops@company.com", "", "invalid-scope"); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for invalid scope, got %v", err)
	}
	if _, err := svc.RevokeTokens(context.Background(), "ops@company.com", "", "tenant"); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument when tenant scope misses tenantId, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("repo should not be called on invalid revoke requests, got %d calls", calls)
	}

	resp, err := svc.RevokeTokens(context.Background(), "  ops@company.com  ", "", "")
	if err != nil {
		t.Fatalf("expected success for default global scope, got %v", err)
	}
	if resp.TokenVersion != 2 || resp.Email != "ops@company.com" {
		t.Fatalf("unexpected revoke response: %+v", resp)
	}
	if calls != 1 {
		t.Fatalf("expected one repo call after valid revoke, got %d", calls)
	}
}

func TestUserServiceSpec_SetStatus_RejectsBlankEmailAfterTrim(t *testing.T) {
	repo := &mockUserRepo{}
	calls := 0
	repo.setStatusFn = func(ctx context.Context, email string, status domain.UserStatus) (*domain.User, error) {
		calls++
		return &domain.User{Id: "u1", Email: email, Status: status}, nil
	}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)

	if _, err := svc.SetStatus(context.Background(), "   ", "ACTIVE"); err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for blank email, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("repo.SetStatus must not be called for invalid input, got %d calls", calls)
	}
}

func TestUserServiceSpec_ResetPassword_RejectsMalformedPayload(t *testing.T) {
	repo := &mockUserRepo{}
	consumeCalls := 0
	repo.consumeOobCodeFn = func(ctx context.Context, code, expectedReqType string) (string, error) {
		consumeCalls++
		return "user@company.com", nil
	}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)

	err := svc.ResetPassword(context.Background(), domain.ResetPwdReq{OobCode: " ", NewPassword: "new-pass"})
	if err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for blank oobCode, got %v", err)
	}
	err = svc.ResetPassword(context.Background(), domain.ResetPwdReq{OobCode: "oob-1", NewPassword: "  "})
	if err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for blank newPassword, got %v", err)
	}
	if consumeCalls != 0 {
		t.Fatalf("consume must not run for malformed payload, got %d calls", consumeCalls)
	}
}

func TestUserServiceSpec_SignUp_RepositoryLookupFailurePropagates(t *testing.T) {
	repo := &mockUserRepo{}
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return nil, errors.New("repo unavailable")
	}

	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)
	_, err := svc.SignUp(context.Background(), domain.SignUpReq{
		Email:    "new@company.com",
		Password: "secret",
	})
	if err == nil || err.Error() != "repo unavailable" {
		t.Fatalf("expected repository lookup error to propagate, got %v", err)
	}
}

func TestUserServiceSpec_SignInWithOobCode_SingleUseContract(t *testing.T) {
	repo := newFakeUserRepo()
	repo.usersByEmail["user@company.com"] = &domain.User{
		Id:     "user-1",
		Email:  "user@company.com",
		Role:   domain.RoleCompanyEmployee,
		Status: domain.UserStatusActive,
	}
	repo.oobs["code-1"] = fakeOob{email: "user@company.com", reqType: "EMAIL_SIGNIN"}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid")

	first, err := svc.SignInWithOobCode(context.Background(), domain.SignInWithOobCodeReq{
		Email:             "user@company.com",
		OobCode:           "code-1",
		ReturnSecureToken: true,
	})
	if err != nil {
		t.Fatalf("first consume must succeed, got %v", err)
	}
	if first.Email != "user@company.com" || first.LocalId != "user-1" || first.ExpiresIn != 3600 || first.IdToken == "" {
		t.Fatalf("unexpected signInWithOob response: %+v", first)
	}

	second, err := svc.SignInWithOobCode(context.Background(), domain.SignInWithOobCodeReq{
		Email:             "user@company.com",
		OobCode:           "code-1",
		ReturnSecureToken: true,
	})
	if err != domain.ErrInvalidOob {
		t.Fatalf("second consume must fail as single-use code, got resp=%+v err=%v", second, err)
	}
}

func TestUserServiceSpec_TokenExchange_TTLBoundaries(t *testing.T) {
	repo := &mockUserRepo{}
	membership := &mockMembershipRepo{}
	clientSvc := &mockClientService{}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		if email != "user@company.com" {
			return nil, nil
		}
		return &domain.User{
			Id:           "u1",
			Email:        "user@company.com",
			Role:         domain.RoleCompanyEmployee,
			Status:       domain.UserStatusActive,
			TokenVersion: 1,
		}, nil
	}
	membership.listTenantIDsByUser = func(ctx context.Context, userID string) ([]string, error) {
		return []string{"tenant-1"}, nil
	}
	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		return &domain.Client{Id: clientID, Status: "ACTIVE", DefaultScopes: []string{"codeq:claim"}}, nil
	}

	svc := NewUserService(repo, membership, nil, clientSvc, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)
	idToken := signIDToken(t, "secret", "user@company.com")

	cases := []struct {
		name      string
		ttlIn     int
		ttlExpect int
	}{
		{name: "default_when_zero", ttlIn: 0, ttlExpect: 3600},
		{name: "default_when_negative", ttlIn: -10, ttlExpect: 3600},
		{name: "max_cap", ttlIn: 99999, ttlExpect: 86400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
				IdToken:    idToken,
				Audience:   "codeq-worker",
				Scopes:     []string{"codeq:claim"},
				EventTypes: []string{"render_video"},
				TenantID:   "tenant-1",
				TTLSeconds: tc.ttlIn,
			})
			if err != nil {
				t.Fatalf("expected token exchange success, got %v", err)
			}
			if resp.ExpiresIn != tc.ttlExpect {
				t.Fatalf("expected expiresIn=%d, got %d", tc.ttlExpect, resp.ExpiresIn)
			}
		})
	}
}

func TestUserServiceSpec_TokenExchange_EventTypesContract(t *testing.T) {
	repo := &mockUserRepo{}
	membership := &mockMembershipRepo{}
	clientSvc := &mockClientService{}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		if email != "user@company.com" {
			return nil, nil
		}
		return &domain.User{
			Id:           "u1",
			Email:        "user@company.com",
			Role:         domain.RoleCompanyEmployee,
			Status:       domain.UserStatusActive,
			TokenVersion: 1,
		}, nil
	}
	membership.listTenantIDsByUser = func(ctx context.Context, userID string) ([]string, error) {
		return []string{"tenant-1"}, nil
	}
	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		return &domain.Client{Id: clientID, Status: "ACTIVE", DefaultScopes: []string{"codeq:claim"}}, nil
	}
	svc := NewUserService(repo, membership, nil, clientSvc, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)
	idToken := signIDToken(t, "secret", "user@company.com")

	_, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken:  idToken,
		Audience: "codeq-worker",
		Scopes:   []string{"codeq:claim"},
		TenantID: "tenant-1",
	})
	if err != domain.ErrInvalidArgument {
		t.Fatalf("worker audience must require eventTypes, got %v", err)
	}

	resp, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken:    idToken,
		Audience:   "codeq-worker",
		Scopes:     []string{"codeq:claim"},
		EventTypes: []string{"render_video", "  ", "generate_master"},
		TenantID:   "tenant-1",
	})
	if err != nil {
		t.Fatalf("expected success with non-empty event types, got %v", err)
	}

	key, err := svc.getRSAPrivateKey()
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	priv := key.(*rsa.PrivateKey)
	claims, err := utils.ValidateRS256(resp.AccessToken, &priv.PublicKey, "https://api.storifly.ai", "codeq-worker")
	if err != nil {
		t.Fatalf("validate worker token: %v", err)
	}
	got, _ := claims["eventTypes"].([]interface{})
	want := []interface{}{"render_video", "generate_master"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("eventTypes must be normalized and preserved, got=%v want=%v", got, want)
	}
}

func signIDTokenWithClaims(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign id token with custom claims: %v", err)
	}
	return signed
}

func TestUserServiceSpec_TokenExchange_IdTokenIssuerMismatchRejected(t *testing.T) {
	repo := &mockUserRepo{}
	membership := &mockMembershipRepo{}
	clientSvc := &mockClientService{}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		if email != "user@company.com" {
			return nil, nil
		}
		return &domain.User{Id: "u1", Email: email, Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive}, nil
	}
	membership.listTenantIDsByUser = func(ctx context.Context, userID string) ([]string, error) {
		return []string{"tenant-1"}, nil
	}
	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		return &domain.Client{Id: clientID, Status: "ACTIVE", DefaultScopes: []string{"codeq:claim"}}, nil
	}

	svc := NewUserService(repo, membership, nil, clientSvc, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)
	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"sub":   "u1",
		"email": "user@company.com",
		"iss":   "https://evil.example.com",
		"aud":   "tikti",
	})

	_, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken:    idToken,
		Audience:   "codeq-worker",
		Scopes:     []string{"codeq:claim"},
		EventTypes: []string{"render_video"},
		TenantID:   "tenant-1",
	})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for issuer mismatch, got %v", err)
	}
}

func TestUserServiceSpec_TokenExchange_IdTokenAudienceMismatchRejected(t *testing.T) {
	repo := &mockUserRepo{}
	membership := &mockMembershipRepo{}
	clientSvc := &mockClientService{}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		if email != "user@company.com" {
			return nil, nil
		}
		return &domain.User{Id: "u1", Email: email, Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive}, nil
	}
	membership.listTenantIDsByUser = func(ctx context.Context, userID string) ([]string, error) {
		return []string{"tenant-1"}, nil
	}
	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		return &domain.Client{Id: clientID, Status: "ACTIVE", DefaultScopes: []string{"codeq:claim"}}, nil
	}

	svc := NewUserService(repo, membership, nil, clientSvc, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)
	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"sub":   "u1",
		"email": "user@company.com",
		"iss":   "https://api.storifly.ai",
		"aud":   "another-audience",
	})

	_, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken:    idToken,
		Audience:   "codeq-worker",
		Scopes:     []string{"codeq:claim"},
		EventTypes: []string{"render_video"},
		TenantID:   "tenant-1",
	})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for audience mismatch, got %v", err)
	}
}

func TestUserServiceSpec_TokenExchange_IdTokenAudienceTypeRejected(t *testing.T) {
	repo := &mockUserRepo{}
	membership := &mockMembershipRepo{}
	clientSvc := &mockClientService{}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		if email != "user@company.com" {
			return nil, nil
		}
		return &domain.User{Id: "u1", Email: email, Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive}, nil
	}
	membership.listTenantIDsByUser = func(ctx context.Context, userID string) ([]string, error) {
		return []string{"tenant-1"}, nil
	}
	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		return &domain.Client{Id: clientID, Status: "ACTIVE", DefaultScopes: []string{"codeq:claim"}}, nil
	}

	svc := NewUserService(repo, membership, nil, clientSvc, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)
	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"sub":   "u1",
		"email": "user@company.com",
		"iss":   "https://api.storifly.ai",
		"aud":   12345,
	})

	_, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken:    idToken,
		Audience:   "codeq-worker",
		Scopes:     []string{"codeq:claim"},
		EventTypes: []string{"render_video"},
		TenantID:   "tenant-1",
	})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for invalid audience type, got %v", err)
	}
}

func TestUserServiceSpec_Lookup_MissingEmailClaimRejected(t *testing.T) {
	repo := &mockUserRepo{}
	lookupCalls := 0
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		lookupCalls++
		return nil, nil
	}

	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)
	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"sub": "u-1",
	})

	_, err := svc.Lookup(context.Background(), domain.LookupReq{IdToken: idToken})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for missing email claim, got %v", err)
	}
	if lookupCalls != 0 {
		t.Fatalf("repository lookup must not run when email claim is missing, got %d calls", lookupCalls)
	}
}

func TestUserServiceSpec_UpdateUser_MissingEmailClaimRejected(t *testing.T) {
	repo := &mockUserRepo{}
	lookupCalls := 0
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		lookupCalls++
		return nil, nil
	}

	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)
	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"sub": "u-1",
	})

	_, err := svc.UpdateUser(context.Background(), domain.UpdateReq{
		IdToken:  idToken,
		Email:    "new@company.com",
		Password: "new-secret",
	})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for missing email claim, got %v", err)
	}
	if lookupCalls != 0 {
		t.Fatalf("repository lookup must not run when email claim is missing, got %d calls", lookupCalls)
	}
}

func TestUserServiceSpec_DeleteUser_MissingEmailClaimRejected(t *testing.T) {
	repo := &mockUserRepo{}
	deleteCalls := 0
	repo.deleteByEmailFn = func(ctx context.Context, email string) error {
		deleteCalls++
		return nil
	}

	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)
	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"sub": "u-1",
	})

	err := svc.DeleteUser(context.Background(), domain.DeleteReq{IdToken: idToken})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for missing email claim, got %v", err)
	}
	if deleteCalls != 0 {
		t.Fatalf("delete must not run when email claim is missing, got %d calls", deleteCalls)
	}
}

func TestUserServiceSpec_TokenExchange_MissingSubClaimRejected(t *testing.T) {
	repo := &mockUserRepo{}
	lookupCalls := 0
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		lookupCalls++
		return nil, nil
	}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)

	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"email": "user@company.com",
		"iss":   "https://api.storifly.ai",
		"aud":   "tikti",
	})
	_, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken:    idToken,
		Audience:   "codeq-worker",
		Scopes:     []string{"codeq:claim"},
		EventTypes: []string{"render_video"},
		TenantID:   "tenant-1",
	})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for missing sub claim, got %v", err)
	}
	if lookupCalls != 0 {
		t.Fatalf("repo lookup must not run for malformed idToken, got %d calls", lookupCalls)
	}
}

func TestUserServiceSpec_Lookup_MissingSubClaimRejected(t *testing.T) {
	repo := &mockUserRepo{}
	lookupCalls := 0
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		lookupCalls++
		return nil, nil
	}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)

	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"email": "user@company.com",
	})
	_, err := svc.Lookup(context.Background(), domain.LookupReq{IdToken: idToken})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for missing sub claim, got %v", err)
	}
	if lookupCalls != 0 {
		t.Fatalf("repo lookup must not run for malformed idToken, got %d calls", lookupCalls)
	}
}

func TestUserServiceSpec_UpdateUser_MissingSubClaimRejected(t *testing.T) {
	repo := &mockUserRepo{}
	lookupCalls := 0
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		lookupCalls++
		return nil, nil
	}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)

	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"email": "user@company.com",
	})
	_, err := svc.UpdateUser(context.Background(), domain.UpdateReq{
		IdToken: idToken,
		Email:   "new@company.com",
	})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for missing sub claim, got %v", err)
	}
	if lookupCalls != 0 {
		t.Fatalf("repo lookup must not run for malformed idToken, got %d calls", lookupCalls)
	}
}

func TestUserServiceSpec_DeleteUser_MissingSubClaimRejected(t *testing.T) {
	repo := &mockUserRepo{}
	deleteCalls := 0
	repo.deleteByEmailFn = func(ctx context.Context, email string) error {
		deleteCalls++
		return nil
	}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)

	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"email": "user@company.com",
	})
	err := svc.DeleteUser(context.Background(), domain.DeleteReq{IdToken: idToken})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for missing sub claim, got %v", err)
	}
	if deleteCalls != 0 {
		t.Fatalf("delete must not run for malformed idToken, got %d calls", deleteCalls)
	}
}

func TestUserServiceSpec_TokenExchange_SubMismatchRejected(t *testing.T) {
	repo := &mockUserRepo{}
	membership := &mockMembershipRepo{}
	clientSvc := &mockClientService{}

	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{
			Id:     "user-1",
			Email:  "user@company.com",
			Role:   domain.RoleCompanyEmployee,
			Status: domain.UserStatusActive,
		}, nil
	}
	membership.listTenantIDsByUser = func(ctx context.Context, userID string) ([]string, error) {
		return []string{"tenant-1"}, nil
	}
	clientLookups := 0
	clientSvc.getClientFn = func(ctx context.Context, tenantID string, clientID string) (*domain.Client, error) {
		clientLookups++
		return &domain.Client{Id: clientID, Status: "ACTIVE", DefaultScopes: []string{"codeq:claim"}}, nil
	}
	svc := NewUserService(repo, membership, nil, clientSvc, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)

	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"sub":   "attacker-sub",
		"email": "user@company.com",
		"iss":   "https://api.storifly.ai",
		"aud":   "tikti",
	})
	_, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken:    idToken,
		Audience:   "codeq-worker",
		Scopes:     []string{"codeq:claim"},
		EventTypes: []string{"render_video"},
		TenantID:   "tenant-1",
	})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for sub mismatch, got %v", err)
	}
	if clientLookups != 0 {
		t.Fatalf("client lookup must not run for malformed idToken, got %d calls", clientLookups)
	}
}

func TestUserServiceSpec_Lookup_SubMismatchRejected(t *testing.T) {
	repo := &mockUserRepo{}
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "user-1", Email: "user@company.com"}, nil
	}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)

	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"sub":   "attacker-sub",
		"email": "user@company.com",
	})
	_, err := svc.Lookup(context.Background(), domain.LookupReq{IdToken: idToken})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for sub mismatch, got %v", err)
	}
}

func TestUserServiceSpec_UpdateUser_SubMismatchRejected(t *testing.T) {
	repo := &mockUserRepo{}
	updateCalls := 0
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "user-1", Email: "user@company.com"}, nil
	}
	repo.updateUserFn = func(ctx context.Context, user *domain.User) error {
		updateCalls++
		return nil
	}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)

	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"sub":   "attacker-sub",
		"email": "user@company.com",
	})
	_, err := svc.UpdateUser(context.Background(), domain.UpdateReq{
		IdToken: idToken,
		Email:   "new@company.com",
	})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for sub mismatch, got %v", err)
	}
	if updateCalls != 0 {
		t.Fatalf("update must not run for malformed idToken, got %d calls", updateCalls)
	}
}

func TestUserServiceSpec_DeleteUser_SubMismatchRejected(t *testing.T) {
	repo := &mockUserRepo{}
	deleteCalls := 0
	repo.findByEmailFn = func(ctx context.Context, email string) (*domain.User, error) {
		return &domain.User{Id: "user-1", Email: "user@company.com"}, nil
	}
	repo.deleteByEmailFn = func(ctx context.Context, email string) error {
		deleteCalls++
		return nil
	}
	svc := NewUserService(repo, nil, nil, nil, "secret", "https://api.storifly.ai", "tikti", makePEMKey(t), "kid").(*userService)

	idToken := signIDTokenWithClaims(t, "secret", jwt.MapClaims{
		"sub":   "attacker-sub",
		"email": "user@company.com",
	})
	err := svc.DeleteUser(context.Background(), domain.DeleteReq{IdToken: idToken})
	if err != domain.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for sub mismatch, got %v", err)
	}
	if deleteCalls != 0 {
		t.Fatalf("delete must not run for malformed idToken, got %d calls", deleteCalls)
	}
}
