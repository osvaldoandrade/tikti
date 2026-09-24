package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestCompanyAdminCannotImpersonateAnotherServiceSubject(t *testing.T) {
	repo := newFakeUserRepo()
	companyID := "default"
	user := &domain.User{Id: "company-admin", Email: "admin@certiface.example", Role: domain.RoleCompanyAdmin, Status: domain.UserStatusActive, CompanyId: &companyID}
	repo.usersByEmail[user.Email] = user
	svc := NewUserService(repo, nil, nil, nil, "secret", "issuer", "tikti", "", "")
	idToken, _, err := svc.(*userService).issueIDToken(user)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ audience, subject string }{
		{"employee-service", "platform-admin"},
		{"analytics-service", "someone@other-company.test"},
	} {
		_, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{IdToken: idToken, TenantID: "default", Audience: tc.audience, Scopes: []string{"employee:read"}, Subject: tc.subject})
		if !errors.Is(err, domain.ErrUnauthorizedScope) {
			t.Fatalf("%s accepted another subject: %v", tc.audience, err)
		}
	}
}

func TestCompanyAdminAnalyticsTokenCarriesIdentityAndEmail(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	repo := newFakeUserRepo()
	companyID := "default"
	user := &domain.User{Id: "company-admin", Email: "admin@certiface.example", Role: domain.RoleCompanyAdmin, Status: domain.UserStatusActive, CompanyId: &companyID}
	repo.usersByEmail[user.Email] = user
	svc := NewUserService(repo, nil, nil, nil, "secret", "issuer", "tikti", string(encodedKey), "kid")
	idToken, _, err := svc.(*userService).issueIDToken(user)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := svc.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken: idToken, TenantID: "default", Audience: "analytics-service",
		Scopes: []string{"employee:read", "analytics:read"}, Subject: user.Email,
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.Parse(issued.AccessToken, func(*jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("invalid analytics token: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["sub"] != user.Id || claims["email"] != user.Email {
		t.Fatalf("analytics identity claims missing: sub=%v email=%v", claims["sub"], claims["email"])
	}
}

func TestCompanyAdminScopeAllowlist(t *testing.T) {
	svc := &userService{}
	user := &domain.User{Role: domain.RoleCompanyAdmin, Email: "admin@certiface.example"}
	if !svc.scopesAllowed(context.Background(), "default", user, []string{"employee:read", "employee:write", "question:admin"}) {
		t.Fatal("company admin scopes denied")
	}
	if svc.scopesAllowed(context.Background(), "default", user, []string{"employee:read", "user:admin"}) {
		t.Fatal("global administrative scope allowed")
	}
	other := &domain.User{Role: domain.RoleCompanyAdmin, Email: "admin@other.test"}
	if svc.scopesAllowed(context.Background(), "default", other, []string{"user:admin"}) {
		t.Fatal("another company admin escaped the scope")
	}
}
