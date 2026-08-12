package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func membershipV2IntegratedConfig(t *testing.T, redisAddr string) *config.Config {
	t.Helper()
	return &config.Config{
		RedisAddr: redisAddr, JwtSecret: "legacy-secret", ApiKey: "api-key",
		IssuerBaseURL: "https://tikti", DefaultAudience: "code-admin", JwksPrivateKey: applicationTestPrivateKey(t, 2048), JwksKeyID: "kid",
		TenantScopedTokenClaimsV1: true, TenantScopedTokenClaimsV1Tenants: []string{"bereia"},
		ExactMembershipReadRoutesV1: true, ExactMembershipReadRoutesV1Tenants: []string{"bereia"}, ExactMembershipPageTokenSecret: strings.Repeat("p", 32),
		MembershipV2WriteRoutesV1: true, MembershipV2WriteRoutesV1Tenants: []string{"bereia"},
	}
}

func TestMembershipV2CompanyAdminCannotEscalateToForeignTarget(t *testing.T) {
	server := miniredis.RunT(t)
	cfg := membershipV2IntegratedConfig(t, server.Addr())
	application, err := NewApplication(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Redis.Close() })

	home := "home"
	user := &domain.User{
		Id: "company-admin", Email: "company-admin@example.com", Role: domain.RoleCompanyAdmin,
		Status: domain.UserStatusActive, CompanyId: &home, Password: "stored-hash", CreatedAt: time.Now().UTC(), AuthSource: domain.AuthSourcePassword,
	}
	if err := repository.NewRedisRepo(application.Redis).CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if _, err := application.MemberSvc.Create(context.Background(), home, domain.MembershipCreateReq{Email: user.Email, Roles: []string{"company-admin"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := application.ClientSvc.Create(context.Background(), home, domain.ClientCreateReq{
		ClientId: cfg.DefaultAudience, Type: string(domain.ClientTypeService),
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)}, DefaultScopes: []string{domain.PlatformTenantAdminScope},
	}); err != nil {
		t.Fatal(err)
	}
	idToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.Id, "email": user.Email, "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(cfg.JwtSecret))
	if err != nil {
		t.Fatal(err)
	}
	response, err := application.UserService.TokenExchange(context.Background(), domain.TokenExchangeReq{
		IdToken: idToken, Audience: cfg.DefaultAudience, TenantID: home, Scopes: []string{domain.PlatformTenantAdminScope},
	})
	if response != nil || !errors.Is(err, domain.ErrUnauthorizedScope) {
		t.Fatalf("company-admin issuance = %+v, %v", response, err)
	}

	legacyLooking := applicationRoleToken(t, cfg.JwksPrivateKey, jwt.MapClaims{
		"sub": user.Id, "scope": domain.PlatformTenantAdminScope, "role": string(domain.RoleCompanyAdmin),
		"tid": home, domain.PlatformPrivilegeClaim: domain.PlatformPrivilegeAdmin,
	})
	request := httptest.NewRequest(http.MethodPut, "/v1/admin/tenants/bereia/memberships/foreign-user", strings.NewReader(`{"roles":["reader"]}`))
	request.Header.Set("Authorization", "Bearer "+legacyLooking)
	request.Header.Set("X-API-Key", cfg.ApiKey)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	application.Engine.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("foreign membership target = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestMembershipV2ApplicationGuardKeepsMixedRouteModesAtomic(t *testing.T) {
	server := miniredis.RunT(t)
	application, err := NewApplication(membershipV2IntegratedConfig(t, server.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Redis.Close() })
	legacyConfig := membershipV2IntegratedConfig(t, server.Addr())
	legacyConfig.MembershipV2WriteRoutesV1 = false
	legacyApplication, err := NewApplication(legacyConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = legacyApplication.Redis.Close() })
	ctx := context.Background()
	user := &domain.User{
		Id: "user-1", Email: "user@example.com", Role: domain.RoleCompanyEmployee,
		Status: domain.UserStatusActive, Password: "stored-hash", CreatedAt: time.Now().UTC(), AuthSource: domain.AuthSourcePassword,
	}
	if err := repository.NewRedisRepo(application.Redis).CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	v2 := repository.NewMembershipV2Repo(application.Redis)
	created, wasCreated, err := v2.Ensure(ctx, "bereia", user.Id, []string{"reader"})
	if err != nil || !wasCreated || created == nil {
		t.Fatalf("v2 create = %+v, %t, %v", created, wasCreated, err)
	}
	for _, mutation := range []struct {
		name string
		run  func() error
	}{
		{name: "legacy create", run: func() error {
			_, err := legacyApplication.MemberSvc.Create(ctx, "bereia", domain.MembershipCreateReq{Email: user.Email, Roles: []string{"reader"}})
			return err
		}},
		{name: "legacy update", run: func() error {
			_, err := legacyApplication.MemberSvc.Create(ctx, "bereia", domain.MembershipCreateReq{Email: user.Email, Roles: []string{"writer"}})
			return err
		}},
		{name: "legacy delete", run: func() error {
			_, err := legacyApplication.MemberSvc.Remove(ctx, "bereia", domain.MembershipRemoveReq{Email: user.Email})
			return err
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if err := mutation.run(); !errors.Is(err, domain.ErrMembershipConflict) {
				t.Fatalf("mutation error = %v", err)
			}
			v2Value, v2Err := v2.GetExact(ctx, "bereia", user.Id)
			legacyValue, legacyErr := repository.NewMembershipRepo(application.Redis).Get(ctx, "bereia", user.Id)
			if v2Err != nil || legacyErr != nil || !reflect.DeepEqual(v2Value, created) || !reflect.DeepEqual(legacyValue, created) {
				t.Fatalf("projections diverged: v2=%+v legacy=%+v errors=%v/%v", v2Value, legacyValue, v2Err, legacyErr)
			}
		})
	}

	if _, err := legacyApplication.MemberSvc.Create(ctx, "legacy", domain.MembershipCreateReq{Email: user.Email, Roles: []string{"reader"}}); err != nil {
		t.Fatalf("legacy-only create: %v", err)
	}
	if _, err := legacyApplication.MemberSvc.Create(ctx, "legacy", domain.MembershipCreateReq{Email: user.Email, Roles: []string{"writer"}}); err != nil {
		t.Fatalf("legacy-only update: %v", err)
	}
	legacyOnly, err := repository.NewMembershipRepo(application.Redis).Get(ctx, "legacy", user.Id)
	if err != nil || legacyOnly == nil || !reflect.DeepEqual(legacyOnly.Roles, []string{"writer"}) {
		t.Fatalf("legacy-only projection = %+v, %v", legacyOnly, err)
	}
	if _, err := legacyApplication.MemberSvc.Remove(ctx, "legacy", domain.MembershipRemoveReq{Email: user.Email}); err != nil {
		t.Fatalf("legacy-only delete: %v", err)
	}
	if legacyOnly, err = repository.NewMembershipRepo(application.Redis).Get(ctx, "legacy", user.Id); err != nil || legacyOnly != nil {
		t.Fatalf("legacy-only delete projection = %+v, %v", legacyOnly, err)
	}
}
