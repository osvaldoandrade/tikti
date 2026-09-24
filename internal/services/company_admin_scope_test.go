package services

import (
	"context"
	"errors"
	"testing"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestCompanyAdminCannotImpersonateAnotherServiceSubject(t *testing.T) {
	repo := newFakeUserRepo()
	companyID := "default"
	user := &domain.User{Id: "conveste-admin", Email: "fernando.machado@conveste.com.br", Role: domain.RoleCompanyAdmin, Status: domain.UserStatusActive, CompanyId: &companyID}
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

func TestCompanyAdminScopeAllowlist(t *testing.T) {
	svc := &userService{}
	user := &domain.User{Role: domain.RoleCompanyAdmin, Email: "fernando.machado@conveste.com.br"}
	if !svc.scopesAllowed(context.Background(), "default", user, []string{"employee:read", "employee:write", "question:admin"}) {
		t.Fatal("Conveste admin scopes denied")
	}
	if svc.scopesAllowed(context.Background(), "default", user, []string{"employee:read", "user:admin"}) {
		t.Fatal("global administrative scope allowed")
	}
	other := &domain.User{Role: domain.RoleCompanyAdmin, Email: "admin@other.test"}
	if !svc.scopesAllowed(context.Background(), "default", other, []string{"user:admin"}) {
		t.Fatal("unrelated company admin behavior changed")
	}
	linked := &userService{convesteAdminLookup: func(context.Context) (string, error) { return "replacement-admin", nil }}
	replacement := &domain.User{Id: "replacement-admin", Role: domain.RoleCompanyAdmin, Email: "new-admin@conveste.test"}
	if linked.scopesAllowed(context.Background(), "default", replacement, []string{"user:admin"}) {
		t.Fatal("newly linked Conveste admin escaped the scope")
	}
}
