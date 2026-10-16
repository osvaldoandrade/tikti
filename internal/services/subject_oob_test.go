package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type afterSubjectOOBRepository struct {
	repository.UserRepository
	repository.UserIDRepository
	repository.SubjectBoundOOBRepository
	afterConsume func()
}

func (r *afterSubjectOOBRepository) ConsumeSubjectOobCode(ctx context.Context, code, request string) (repository.OOBSubject, error) {
	proof, err := r.SubjectBoundOOBRepository.ConsumeSubjectOobCode(ctx, code, request)
	if err == nil {
		r.afterConsume()
	}
	return proof, err
}

func TestSubjectOOBNeverAuthenticatesRecreatedEmail(t *testing.T) {
	for _, request := range []string{"EMAIL_SIGNIN", "PASSWORD_RESET"} {
		for _, timing := range []string{"before consume", "after consume"} {
			t.Run(request+" "+timing, func(t *testing.T) {
				_, users, directory, service, admin := deletionServiceFixture(t)
				ctx := context.Background()
				target := &domain.User{Id: "original-user", Email: "reused@example.com", Password: "old-hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now().UTC()}
				if err := users.CreateUser(ctx, target); err != nil {
					t.Fatal(err)
				}
				response, err := service.SendOob(ctx, domain.SendOobReq{Email: target.Email, RequestType: request})
				if err != nil {
					t.Fatal(err)
				}
				replace := func() {
					if _, err := directory.DeleteDirectoryUser(ctx, target.Id, 1, domain.DirectoryDeletionActor{UserID: admin.Id}); err != nil {
						t.Fatal(err)
					}
					target.Id = "replacement-user"
					target.Password = "replacement-hash"
					if err := users.CreateUser(ctx, target); err != nil {
						t.Fatal(err)
					}
				}
				if timing == "before consume" {
					replace()
				} else {
					service.repo = &afterSubjectOOBRepository{UserRepository: users, UserIDRepository: users.(repository.UserIDRepository), SubjectBoundOOBRepository: users.(repository.SubjectBoundOOBRepository), afterConsume: replace}
				}
				if request == "EMAIL_SIGNIN" {
					if result, err := service.SignInWithOobCode(ctx, domain.SignInWithOobCodeReq{Email: target.Email, OobCode: response.OobCode}); result != nil || !errors.Is(err, domain.ErrInvalidOob) {
						t.Fatalf("stale OOB sign in=%#v err=%v", result, err)
					}
				} else if err := service.ResetPassword(ctx, domain.ResetPwdReq{OobCode: response.OobCode, NewPassword: "replacement-password-123"}); !errors.Is(err, domain.ErrInvalidOob) {
					t.Fatalf("stale OOB reset=%v", err)
				}
				replacement, err := users.FindByEmail(ctx, target.Email)
				if err != nil || replacement == nil || replacement.Id != "replacement-user" || replacement.Password != "replacement-hash" {
					t.Fatalf("replacement changed=%#v err=%v", replacement, err)
				}
			})
		}
	}
}

func TestSubjectOOBRejectsLegacyAndRevokedCredentials(t *testing.T) {
	for _, scenario := range []string{"legacy", "revoked", "suspended", "SAML", "replay"} {
		t.Run(scenario, func(t *testing.T) {
			_, users, _, service, user := deletionServiceFixture(t)
			ctx := context.Background()
			bound := users.(repository.SubjectBoundOOBRepository)
			if scenario == "legacy" {
				if err := users.SaveOobCode(ctx, "code", user.Email, "EMAIL_SIGNIN"); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := bound.SaveSubjectOobCode(ctx, "code", repository.OOBSubject{UserID: user.Id, Email: user.Email, TokenVersion: user.TokenVersion}, "EMAIL_SIGNIN"); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "revoked":
					user.TokenVersion++
				case "suspended":
					user.Status = domain.UserStatusSuspended
				case "SAML":
					user.AuthSource = domain.AuthSourceSAML
					user.ExternalSubject = "external"
				}
				if scenario == "replay" {
					if _, err := service.SignInWithOobCode(ctx, domain.SignInWithOobCodeReq{Email: user.Email, OobCode: "code"}); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := users.UpdateUser(ctx, user); err != nil {
						t.Fatal(err)
					}
				}
			}
			if result, err := service.SignInWithOobCode(ctx, domain.SignInWithOobCodeReq{Email: user.Email, OobCode: "code"}); result != nil || !errors.Is(err, domain.ErrInvalidOob) {
				t.Fatalf("rejected credential=%#v err=%v", result, err)
			}
		})
	}
}
