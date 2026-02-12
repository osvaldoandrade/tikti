package services

import (
	"context"
	"errors"
	"testing"

	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeUserRepo struct {
	usersByEmail map[string]*domain.User
	oobs         map[string]fakeOob
	updateCalls  int
	findErr      error
}

type fakeOob struct {
	email   string
	reqType string
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{
		usersByEmail: map[string]*domain.User{},
		oobs:         map[string]fakeOob{},
	}
}

func (r *fakeUserRepo) CreateUser(ctx context.Context, user *domain.User) error {
	return domain.ErrInvalidArgument
}

func (r *fakeUserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	if r.findErr != nil {
		return nil, r.findErr
	}
	if u, ok := r.usersByEmail[email]; ok {
		return u, nil
	}
	return nil, nil
}

func (r *fakeUserRepo) UpdateUser(ctx context.Context, user *domain.User) error {
	r.updateCalls++
	if user != nil && user.Email != "" {
		r.usersByEmail[user.Email] = user
	}
	return nil
}

func (r *fakeUserRepo) DeleteByEmail(ctx context.Context, email string) error {
	return nil
}

func (r *fakeUserRepo) SetStatus(ctx context.Context, email string, status domain.UserStatus) (*domain.User, error) {
	return nil, domain.ErrInvalidArgument
}

func (r *fakeUserRepo) IncrementTokenVersion(ctx context.Context, email string) (int, *domain.User, error) {
	return 0, nil, domain.ErrInvalidArgument
}

func (r *fakeUserRepo) SaveOobCode(ctx context.Context, code, email, reqType string) error {
	if code == "" || email == "" || reqType == "" {
		return domain.ErrInvalidArgument
	}
	r.oobs[code] = fakeOob{email: email, reqType: reqType}
	return nil
}

func (r *fakeUserRepo) ConsumeOobCode(ctx context.Context, code string, expectedReqType string) (string, error) {
	oob, ok := r.oobs[code]
	if !ok {
		return "", domain.ErrInvalidOob
	}
	if oob.reqType != expectedReqType {
		return "", domain.ErrInvalidOob
	}
	delete(r.oobs, code)
	return oob.email, nil
}

func (r *fakeUserRepo) GetAllUsers(ctx context.Context) ([]*domain.User, error) {
	return []*domain.User{}, nil
}

func TestUserService_SignInWithOobCode_Success(t *testing.T) {
	repo := newFakeUserRepo()
	repo.usersByEmail["user@company.com"] = &domain.User{
		Id:     "user-1",
		Email:  "user@company.com",
		Role:   domain.RoleCompanyEmployee,
		Status: domain.UserStatusActive,
	}
	repo.oobs["code-1"] = fakeOob{email: "user@company.com", reqType: "EMAIL_SIGNIN"}

	svc := NewUserService(repo, nil, nil, nil, "secret", "http://issuer", "tikti", "pem", "kid")
	resp, err := svc.SignInWithOobCode(context.Background(), domain.SignInWithOobCodeReq{
		Email:             "user@company.com",
		OobCode:           "code-1",
		ReturnSecureToken: true,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if resp == nil {
		t.Fatalf("expected response")
	}
	if resp.IdToken == "" {
		t.Fatalf("expected idToken")
	}
	if resp.Email != "user@company.com" {
		t.Fatalf("unexpected email: %s", resp.Email)
	}
	if resp.LocalId != "user-1" {
		t.Fatalf("unexpected localId: %s", resp.LocalId)
	}
	if resp.ExpiresIn != 3600 {
		t.Fatalf("unexpected expiresIn: %d", resp.ExpiresIn)
	}

	claims, parseErr := utils.ParseToken(resp.IdToken, "secret")
	if parseErr != nil {
		t.Fatalf("expected parseable token, got %v", parseErr)
	}
	if got, _ := claims["email"].(string); got != "user@company.com" {
		t.Fatalf("unexpected token email claim: %v", claims["email"])
	}
	if got, _ := claims["sub"].(string); got != "user-1" {
		t.Fatalf("unexpected token sub claim: %v", claims["sub"])
	}
}

func TestUserService_SignInWithOobCode_EmailMismatch(t *testing.T) {
	repo := newFakeUserRepo()
	repo.usersByEmail["user@company.com"] = &domain.User{
		Id:     "user-1",
		Email:  "user@company.com",
		Role:   domain.RoleCompanyEmployee,
		Status: domain.UserStatusActive,
	}
	repo.oobs["code-1"] = fakeOob{email: "user@company.com", reqType: "EMAIL_SIGNIN"}

	svc := NewUserService(repo, nil, nil, nil, "secret", "http://issuer", "tikti", "pem", "kid")
	_, err := svc.SignInWithOobCode(context.Background(), domain.SignInWithOobCodeReq{
		Email:   "other@company.com",
		OobCode: "code-1",
	})
	if err != domain.ErrInvalidOob {
		t.Fatalf("expected ErrInvalidOob, got %v", err)
	}
}

func TestUserService_SignInWithOobCode_UserSuspended(t *testing.T) {
	repo := newFakeUserRepo()
	repo.usersByEmail["user@company.com"] = &domain.User{
		Id:     "user-1",
		Email:  "user@company.com",
		Role:   domain.RoleCompanyEmployee,
		Status: domain.UserStatusSuspended,
	}
	repo.oobs["code-1"] = fakeOob{email: "user@company.com", reqType: "EMAIL_SIGNIN"}

	svc := NewUserService(repo, nil, nil, nil, "secret", "http://issuer", "tikti", "pem", "kid")
	_, err := svc.SignInWithOobCode(context.Background(), domain.SignInWithOobCodeReq{
		Email:   "user@company.com",
		OobCode: "code-1",
	})
	if err != domain.ErrInvalidCreds {
		t.Fatalf("expected ErrInvalidCreds, got %v", err)
	}
}

func TestUserService_SignInWithOobCode_InvalidArgument(t *testing.T) {
	svc := NewUserService(newFakeUserRepo(), nil, nil, nil, "secret", "http://issuer", "tikti", "pem", "kid")

	_, err := svc.SignInWithOobCode(context.Background(), domain.SignInWithOobCodeReq{
		Email:   " ",
		OobCode: "code-1",
	})
	if err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for empty email, got %v", err)
	}

	_, err = svc.SignInWithOobCode(context.Background(), domain.SignInWithOobCodeReq{
		Email:   "user@company.com",
		OobCode: " ",
	})
	if err != domain.ErrInvalidArgument {
		t.Fatalf("expected ErrInvalidArgument for empty code, got %v", err)
	}
}

func TestUserService_SignInWithOobCode_ConsumeAndLookupErrors(t *testing.T) {
	repo := newFakeUserRepo()
	repo.oobs["code-1"] = fakeOob{email: "user@company.com", reqType: "EMAIL_SIGNIN"}
	svc := NewUserService(repo, nil, nil, nil, "secret", "http://issuer", "tikti", "pem", "kid")

	_, err := svc.SignInWithOobCode(context.Background(), domain.SignInWithOobCodeReq{
		Email:   "user@company.com",
		OobCode: "missing-code",
	})
	if err != domain.ErrInvalidOob {
		t.Fatalf("expected ErrInvalidOob, got %v", err)
	}

	_, err = svc.SignInWithOobCode(context.Background(), domain.SignInWithOobCodeReq{
		Email:   "user@company.com",
		OobCode: "code-1",
	})
	if err != domain.ErrInvalidCreds {
		t.Fatalf("expected ErrInvalidCreds for missing user, got %v", err)
	}

	repo.oobs["code-2"] = fakeOob{email: "user@company.com", reqType: "EMAIL_SIGNIN"}
	repo.findErr = errors.New("find-fail")
	_, err = svc.SignInWithOobCode(context.Background(), domain.SignInWithOobCodeReq{
		Email:   "user@company.com",
		OobCode: "code-2",
	})
	if err != domain.ErrInvalidCreds {
		t.Fatalf("expected ErrInvalidCreds for lookup error, got %v", err)
	}
}

func TestUserService_ResetPassword_RequiresPasswordResetType(t *testing.T) {
	repo := newFakeUserRepo()
	repo.usersByEmail["user@company.com"] = &domain.User{
		Id:     "user-1",
		Email:  "user@company.com",
		Role:   domain.RoleCompanyEmployee,
		Status: domain.UserStatusActive,
	}
	repo.oobs["code-1"] = fakeOob{email: "user@company.com", reqType: "EMAIL_SIGNIN"}

	svc := NewUserService(repo, nil, nil, nil, "secret", "http://issuer", "tikti", "pem", "kid")
	err := svc.ResetPassword(context.Background(), domain.ResetPwdReq{
		OobCode:     "code-1",
		NewPassword: "new-secret",
	})
	if err != domain.ErrInvalidOob {
		t.Fatalf("expected ErrInvalidOob, got %v", err)
	}
	if repo.updateCalls != 0 {
		t.Fatalf("expected UpdateUser not to be called, got %d calls", repo.updateCalls)
	}
}
