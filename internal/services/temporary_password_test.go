package services

import (
	"context"
	"errors"
	"testing"

	"github.com/osvaldoandrade/tikti/pkg/domain"
	"golang.org/x/crypto/bcrypt"
)

func TestTemporaryPasswordRequiresRotationBeforeSignIn(t *testing.T) {
	repo := newFakeUserRepo()
	hash, err := bcrypt.GenerateFromPassword([]byte("original-password-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	repo.usersByEmail["user@conveste.example"] = &domain.User{
		Id: "user-1", Email: "user@conveste.example", Password: string(hash),
		Status: domain.UserStatusActive, Role: domain.RoleCompanyEmployee,
	}
	service := NewUserService(repo, nil, nil, nil, "secret", "http://issuer", "tikti", "pem", "kid")
	temporary := service.(TemporaryPasswordService)
	ctx := context.Background()
	if err := temporary.SetTemporaryPassword(ctx, domain.AdminTemporaryPasswordReq{
		Email: "user@conveste.example", UserID: "user-1", TemporaryPassword: "temporary-password-123",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SignIn(ctx, domain.SignInReq{Email: "user@conveste.example", Password: "temporary-password-123"}); !errors.Is(err, domain.ErrPasswordChangeRequired) {
		t.Fatalf("temporary sign-in error = %v", err)
	}
	if _, err := service.SignIn(ctx, domain.SignInReq{Email: "user@conveste.example", Password: "original-password-123"}); !errors.Is(err, domain.ErrInvalidCreds) {
		t.Fatalf("old password sign-in error = %v", err)
	}
	if err := temporary.ChangeTemporaryPassword(ctx, domain.TemporaryPasswordChangeReq{
		Email: "user@conveste.example", TemporaryPassword: "wrong-password", NewPassword: "replacement-password-123",
	}); !errors.Is(err, domain.ErrInvalidCreds) {
		t.Fatalf("wrong temporary password = %v", err)
	}
	if err := temporary.ChangeTemporaryPassword(ctx, domain.TemporaryPasswordChangeReq{
		Email: "user@conveste.example", TemporaryPassword: "temporary-password-123", NewPassword: "replacement-password-123",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SignIn(ctx, domain.SignInReq{Email: "user@conveste.example", Password: "replacement-password-123"}); err != nil {
		t.Fatalf("new password sign-in failed: %v", err)
	}
	user := repo.usersByEmail["user@conveste.example"]
	if user.PasswordChangeRequired || user.TokenVersion != 2 || repo.updateCalls != 2 {
		t.Fatalf("rotation state incorrect: required=%t version=%d updates=%d", user.PasswordChangeRequired, user.TokenVersion, repo.updateCalls)
	}
}

func TestTemporaryPasswordRejectsMismatchedUserID(t *testing.T) {
	repo := newFakeUserRepo()
	repo.usersByEmail["user@conveste.example"] = &domain.User{Id: "right-user", Email: "user@conveste.example", Status: domain.UserStatusActive}
	temporary := NewUserService(repo, nil, nil, nil, "secret", "issuer", "tikti", "pem", "kid").(TemporaryPasswordService)
	err := temporary.SetTemporaryPassword(context.Background(), domain.AdminTemporaryPasswordReq{Email: "user@conveste.example", UserID: "other-user", TemporaryPassword: "temporary-password-123"})
	if !errors.Is(err, domain.ErrNotFound) || repo.updateCalls != 0 {
		t.Fatalf("mismatched identity modified: %v", err)
	}
}
