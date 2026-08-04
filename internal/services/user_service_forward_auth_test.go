package services

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestValidateIDTokenEnforcesIdentityIssuerAudienceStatusAndVersion(t *testing.T) {
	user := &domain.User{
		Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleCompanyEmployee, TokenVersion: 3,
	}
	repo := &mockUserRepo{
		findByEmailFn: func(_ context.Context, email string) (*domain.User, error) {
			if email != user.Email {
				return nil, nil
			}
			copy := *user
			return &copy, nil
		},
	}
	svc := NewUserService(repo, nil, nil, nil, "session-secret", "https://identity.example.com", "tikti", makePEMKey(t), "kid").(*userService)

	valid := signForwardAuthIDToken(t, jwt.MapClaims{
		"sub": user.Id, "email": user.Email, "iss": "https://identity.example.com",
		"aud": "tikti", "ver": float64(3), "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := svc.ValidateIDToken(context.Background(), valid, "https://identity.example.com", "tikti"); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}

	tests := []struct {
		name   string
		claims jwt.MapClaims
		mutate func()
	}{
		{name: "issuer", claims: jwt.MapClaims{
			"sub": user.Id, "email": user.Email, "iss": "https://attacker.example.com",
			"aud": "tikti", "ver": float64(3), "exp": time.Now().Add(time.Hour).Unix(),
		}},
		{name: "audience", claims: jwt.MapClaims{
			"sub": user.Id, "email": user.Email, "iss": "https://identity.example.com",
			"aud": "another-api", "ver": float64(3), "exp": time.Now().Add(time.Hour).Unix(),
		}},
		{name: "version", claims: jwt.MapClaims{
			"sub": user.Id, "email": user.Email, "iss": "https://identity.example.com",
			"aud": "tikti", "ver": float64(2), "exp": time.Now().Add(time.Hour).Unix(),
		}},
		{name: "missing version", claims: jwt.MapClaims{
			"sub": user.Id, "email": user.Email, "iss": "https://identity.example.com",
			"aud": "tikti", "exp": time.Now().Add(time.Hour).Unix(),
		}},
		{name: "suspended", claims: jwt.MapClaims{
			"sub": user.Id, "email": user.Email, "iss": "https://identity.example.com",
			"aud": "tikti", "ver": float64(3), "exp": time.Now().Add(time.Hour).Unix(),
		}, mutate: func() { user.Status = domain.UserStatusSuspended }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			originalStatus := user.Status
			if test.mutate != nil {
				test.mutate()
			}
			defer func() { user.Status = originalStatus }()
			token := signForwardAuthIDToken(t, test.claims)
			if _, err := svc.ValidateIDToken(context.Background(), token, "https://identity.example.com", "tikti"); err == nil {
				t.Fatal("expected token rejection")
			}
		})
	}
}

func TestValidateAccessTokenAcceptsBoundShortLivedWorkloadIdentity(t *testing.T) {
	t.Parallel()
	svc := NewUserService(
		&mockUserRepo{}, nil, nil, nil, "session-secret",
		"https://identity.example.com", "tikti", makePEMKey(t), "kid",
	).(*userService)
	key, err := svc.getRSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://identity.example.com", "aud": "payments-api",
		"sub": "system:serviceaccount:workload-payments:payments-web",
		"tid": "payments", "scope": "payments:read",
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := svc.ValidateAccessToken(
		context.Background(), signed, "https://identity.example.com", "payments-api",
	)
	if err != nil || claims["tid"] != "payments" {
		t.Fatalf("workload token claims=%#v err=%v", claims, err)
	}
	delete(token.Claims.(jwt.MapClaims), "tid")
	signed, err = token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidateAccessToken(
		context.Background(), signed, "https://identity.example.com", "payments-api",
	); err == nil {
		t.Fatal("tenantless workload token was accepted")
	}
}

func TestSignInAcceptsImportedArgon2idPassword(t *testing.T) {
	salt := []byte("0123456789abcdef")
	hash := argon2.IDKey([]byte("correct-password"), salt, 3, 64*1024, 4, 32)
	encoded := "$argon2id$v=19$m=65536,t=3,p=4$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(hash)
	repo := &mockUserRepo{
		findByEmailFn: func(context.Context, string) (*domain.User, error) {
			return &domain.User{
				Id: "user-1", Email: "admin@codecloud.local", Password: encoded,
				Role: domain.RoleAdmin, Status: domain.UserStatusActive,
			}, nil
		},
	}
	svc := NewUserService(repo, nil, nil, nil, "session-secret", "https://identity.example.com", "tikti", makePEMKey(t), "kid").(*userService)
	response, err := svc.SignIn(context.Background(), domain.SignInReq{
		Email: "admin@codecloud.local", Password: "correct-password",
	})
	if err != nil || response.IdToken == "" {
		t.Fatalf("imported Argon2id login failed: response=%#v err=%v", response, err)
	}
	if _, err := svc.SignIn(context.Background(), domain.SignInReq{
		Email: "admin@codecloud.local", Password: "wrong-password",
	}); err != domain.ErrInvalidCreds {
		t.Fatalf("wrong imported password must fail, got %v", err)
	}
}

func signForwardAuthIDToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("session-secret"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}
