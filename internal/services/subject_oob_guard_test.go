package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestSubjectOOBGuardBindsOriginalUIDBeforeAccountReplacement(t *testing.T) {
	for _, request := range []string{"EMAIL_SIGNIN", "PASSWORD_RESET"} {
		t.Run(request, func(t *testing.T) {
			server := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: server.Addr()})
			t.Cleanup(func() { _ = client.Close() })
			ctx := context.Background()
			users := repository.NewRedisRepo(client)
			user := &domain.User{Id: "old-user", Email: "reused@example.com", Password: "old-hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now().UTC()}
			if err := users.CreateUser(ctx, user); err != nil {
				t.Fatal(err)
			}
			service := NewUserService(users, nil, nil, nil, "jwt-secret", "https://issuer", "tikti", "", "")
			response, err := service.SendOob(ctx, domain.SendOobReq{Email: user.Email, RequestType: request})
			if err != nil {
				t.Fatal(err)
			}
			if err = users.DeleteByEmail(ctx, user.Email); err != nil {
				t.Fatal(err)
			}
			user.Id = "new-user"
			user.Password = "new-hash"
			if err = users.CreateUser(ctx, user); err != nil {
				t.Fatal(err)
			}
			if request == "EMAIL_SIGNIN" {
				if result, err := service.SignInWithOobCode(ctx, domain.SignInWithOobCodeReq{Email: user.Email, OobCode: response.OobCode}); result != nil || !errors.Is(err, domain.ErrInvalidOob) {
					t.Fatalf("old sign in bound replacement: result=%v err=%v", result != nil, err)
				}
			} else if err = service.ResetPassword(ctx, domain.ResetPwdReq{OobCode: response.OobCode, NewPassword: "replacement-password-123"}); !errors.Is(err, domain.ErrInvalidOob) {
				t.Fatalf("old reset bound replacement: %v", err)
			}
			current, err := users.FindByEmail(ctx, user.Email)
			if err != nil || current == nil || current.Password != "new-hash" {
				t.Fatal("replacement credentials changed")
			}
		})
	}
}
