package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func deletionServiceFixture(t *testing.T) (*redis.Client, repository.UserRepository, repository.IdentityDirectoryRepository, *userService, *domain.User) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	users := repository.NewRedisRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	user := &domain.User{Id: "admin-actor", Email: "admin@example.com", Password: "hash", Role: domain.RoleAdmin, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now().UTC()}
	if err := users.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.Backfill(context.Background()); err != nil {
		t.Fatal(err)
	}
	tokens := NewUserService(users, nil, nil, nil, "jwt-secret", "https://issuer", "code-admin", makePEMKey(t), "kid", WithIdentityDirectoryAccess(directory)).(*userService)
	return client, users, directory, tokens, user
}

func deletionBearer(t *testing.T, service *userService, user *domain.User, mutate func(jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{"sub": user.Id, "email": user.Email, "role": "ADMIN", "scope": domain.PlatformTenantAdminScope, domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin, "ver": user.TokenVersion, "tid": domain.MasterTenantID, "iss": "https://issuer", "aud": "code-admin", "exp": time.Now().Add(time.Hour).Unix()}
	if user.CompanyId != nil {
		claims["principal_tid"] = *user.CompanyId
	}
	if mutate != nil {
		mutate(claims)
	}
	key, err := service.getRSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestDirectoryDeletionAuthorityRequiresCurrentPlatformProvenance(t *testing.T) {
	for _, scenario := range []string{"current", "missing scope", "missing privilege", "wrong role", "revoked", "suspended", "temporary password", "SAML current allowlist", "SAML removed allowlist"} {
		t.Run(scenario, func(t *testing.T) {
			_, users, _, service, user := deletionServiceFixture(t)
			ctx := context.Background()
			if scenario == "SAML current allowlist" || scenario == "SAML removed allowlist" {
				user.AuthSource = domain.AuthSourceSAML
				user.ExternalSubject = "external-admin"
				home := domain.MasterTenantID
				user.CompanyId = &home
				if err := users.UpdateUser(ctx, user); err != nil {
					t.Fatal(err)
				}
				service.platformAuthorityConfigured = true
				if scenario == "SAML current allowlist" {
					service.platformAdministrators = map[string]struct{}{currentPlatformAdministratorKey(home, user.Email): {}}
				}
			}
			token := deletionBearer(t, service, user, func(claims jwt.MapClaims) {
				switch scenario {
				case "missing scope":
					delete(claims, "scope")
				case "missing privilege":
					delete(claims, domain.PlatformPrivilegeClaim)
				case "wrong role":
					claims["role"] = "COMPANY_ADMIN"
				}
			})
			switch scenario {
			case "revoked":
				user.TokenVersion++
			case "suspended":
				user.Status = domain.UserStatusSuspended
			case "temporary password":
				user.PasswordChangeRequired = true
			}
			if scenario == "revoked" || scenario == "suspended" || scenario == "temporary password" {
				if err := users.UpdateUser(ctx, user); err != nil {
					t.Fatal(err)
				}
			}
			actor, err := service.CurrentDirectoryDeletionActor(ctx, token, "https://issuer", "code-admin")
			if scenario == "current" || scenario == "SAML current allowlist" {
				if err != nil || actor.UserID != user.Id || actor.Revision != user.Revision || actor.TokenVersion != user.TokenVersion {
					t.Fatalf("actor=%#v err=%v", actor, err)
				}
			} else if !errors.Is(err, domain.ErrDirectoryDeletionDenied) {
				t.Fatalf("actor accepted=%#v err=%v", actor, err)
			}
		})
	}
}

func TestDirectoryUserDeletionInvalidatesExistingTokensAfterEmailReuse(t *testing.T) {
	_, users, directory, service, admin := deletionServiceFixture(t)
	ctx := context.Background()
	target := &domain.User{Id: "deleted-subject", Email: "same@example.com", Password: "hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: time.Now().UTC()}
	if err := users.CreateUser(ctx, target); err != nil {
		t.Fatal(err)
	}
	access := deletionBearer(t, service, target, func(claims jwt.MapClaims) {
		claims["role"] = "COMPANY_EMPLOYEE"
		delete(claims, domain.PlatformPrivilegeClaim)
		claims["scope"] = ""
	})
	idToken, _, err := service.issueIDToken(target, nil)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.CurrentDirectoryDeletionActor(ctx, deletionBearer(t, service, admin, nil), "https://issuer", "code-admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = directory.DeleteDirectoryUser(ctx, target.Id, 1, actor); err != nil {
		t.Fatal(err)
	}
	target.Id = "replacement-subject"
	if err = users.CreateUser(ctx, target); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ValidateAccessToken(ctx, access, "https://issuer", "code-admin"); err == nil {
		t.Fatal("deleted access token authenticated replacement")
	}
	if _, err = service.ValidateIDToken(ctx, idToken, "https://issuer", "code-admin"); err == nil {
		t.Fatal("deleted identity token authenticated replacement")
	}
}
