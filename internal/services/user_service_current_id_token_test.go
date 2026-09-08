package services

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type interleavingUserRepository struct {
	repository.UserRepository
	once         sync.Once
	beforeUpdate func()
}

func (r *interleavingUserRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	r.once.Do(r.beforeUpdate)
	return r.UserRepository.UpdateUser(ctx, user)
}

func TestTemporaryPasswordSignInSharesDistributedAttemptLimit(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	users := repository.NewRedisRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	creator := NewIdentityDirectoryService(directory, users, nil, nil, false)
	created, err := creator.CreateUser(ctx, domain.DirectoryUserCreateReq{
		Email: "limited@example.com", TemporaryPassword: "temporary-1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	tokens := NewUserService(
		users, nil, nil, nil, "jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithIdentityDirectoryAccess(directory),
	)
	for attempt := 0; attempt < temporaryPasswordChangeAttemptLimit; attempt++ {
		if _, err = tokens.SignIn(ctx, domain.SignInReq{Email: created.Email, Password: "incorrect-password"}); !errors.Is(err, domain.ErrInvalidCreds) {
			t.Fatalf("attempt %d = %v, want invalid credentials", attempt+1, err)
		}
	}
	if _, err = tokens.SignIn(ctx, domain.SignInReq{Email: created.Email, Password: "temporary-1234"}); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("sixth temporary-password attempt = %v, want rate limit", err)
	}
}

func TestTokenExchangeRequiresCurrentCanonicalIDToken(t *testing.T) {
	tenantID := "bereia"
	stored := &domain.User{
		Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleCompanyEmployee, CompanyId: &tenantID, TokenVersion: 2,
	}
	users := &mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) {
		copy := *stored
		return &copy, nil
	}}
	memberships := &mockMembershipRepo{listTenantIDsByUser: func(context.Context, string) ([]string, error) {
		return []string{tenantID}, nil
	}}
	clients := &mockClientService{getClientFn: func(context.Context, string, string) (*domain.Client, error) {
		return &domain.Client{Id: "codeq-worker", Status: "ACTIVE", DefaultScopes: []string{"codeq:claim"}}, nil
	}}
	service := NewUserService(
		users, memberships, nil, clients, "jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
	).(*userService)
	base := jwt.MapClaims{
		"sub": stored.Id, "email": stored.Email, "role": string(stored.Role),
		"iss": "https://issuer", "aud": "tikti", "ver": stored.TokenVersion,
	}
	request := domain.TokenExchangeReq{
		Audience: "codeq-worker", TenantID: tenantID, Scopes: []string{"codeq:claim"},
		EventTypes: []string{"render_video"},
	}

	tests := []struct {
		name   string
		mutate func(jwt.MapClaims)
	}{
		{name: "revoked version", mutate: func(claims jwt.MapClaims) { claims["ver"] = stored.TokenVersion - 1 }},
		{name: "missing issuer", mutate: func(claims jwt.MapClaims) { delete(claims, "iss") }},
		{name: "missing audience", mutate: func(claims jwt.MapClaims) { delete(claims, "aud") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := jwt.MapClaims{}
			for key, value := range base {
				claims[key] = value
			}
			test.mutate(claims)
			request.IdToken = signIDTokenWithClaims(t, "jwt-secret", claims)
			if response, err := service.TokenExchange(context.Background(), request); err != domain.ErrInvalidToken || response != nil {
				t.Fatalf("exchange accepted non-current idToken: response=%#v err=%v", response, err)
			}
		})
	}
}

func TestTokenExchangeCannotOverrideAuthenticatedSubject(t *testing.T) {
	tenantID := "bereia"
	stored := &domain.User{
		Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleCompanyEmployee, CompanyId: &tenantID,
	}
	users := &mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) {
		copy := *stored
		return &copy, nil
	}}
	memberships := &mockMembershipRepo{listTenantIDsByUser: func(context.Context, string) ([]string, error) {
		return []string{tenantID}, nil
	}}
	clients := &mockClientService{getClientFn: func(context.Context, string, string) (*domain.Client, error) {
		return &domain.Client{Id: "codeq-worker", Status: "ACTIVE", DefaultScopes: []string{"codeq:claim"}}, nil
	}}
	service := NewUserService(
		users, memberships, nil, clients, "jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
	).(*userService)
	var request domain.TokenExchangeReq
	payload := `{"idToken":"` + signCurrentIDToken(t, "jwt-secret", stored.Email, "https://issuer", "tikti", 0) +
		`","audience":"codeq-worker","tenantId":"bereia","scopes":["codeq:claim"],` +
		`"eventTypes":["render_video"],"subject":"system:serviceaccount:victim:controller"}`
	if err := json.Unmarshal([]byte(payload), &request); err != nil {
		t.Fatal(err)
	}
	response, err := service.TokenExchange(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	key, err := service.getRSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	claims, err := utils.ValidateRS256(response.AccessToken, &key.(*rsa.PrivateKey).PublicKey, "https://issuer", "codeq-worker")
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != stored.Id {
		t.Fatalf("token exchange subject = %v, want authenticated user %q", claims["sub"], stored.Id)
	}
}

func TestRevokedIDTokenCannotReadMutateOrDeleteUser(t *testing.T) {
	stored := &domain.User{
		Id: "user-1", Email: "user@example.com", Status: domain.UserStatusActive,
		Role: domain.RoleCompanyEmployee, TokenVersion: 3,
	}
	updateCalls := 0
	deleteCalls := 0
	users := &mockUserRepo{
		findByEmailFn: func(context.Context, string) (*domain.User, error) {
			copy := *stored
			return &copy, nil
		},
		updateUserFn: func(context.Context, *domain.User) error {
			updateCalls++
			return nil
		},
		deleteByEmailFn: func(context.Context, string) error {
			deleteCalls++
			return nil
		},
	}
	service := NewUserService(
		users, nil, nil, nil, "jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
	).(*userService)
	stale := signIDTokenWithClaims(t, "jwt-secret", jwt.MapClaims{
		"sub": stored.Id, "email": stored.Email, "role": string(stored.Role),
		"iss": "https://issuer", "aud": "tikti", "ver": stored.TokenVersion - 1,
	})

	if response, err := service.Lookup(context.Background(), domain.LookupReq{IdToken: stale}); err != domain.ErrInvalidToken || response != nil {
		t.Fatalf("revoked token read user: response=%#v err=%v", response, err)
	}
	if response, err := service.UpdateUser(context.Background(), domain.UpdateReq{IdToken: stale, Password: "new-password"}); err != domain.ErrInvalidToken || response != nil {
		t.Fatalf("revoked token updated user: response=%#v err=%v", response, err)
	}
	if err := service.DeleteUser(context.Background(), domain.DeleteReq{IdToken: stale}); err != domain.ErrInvalidToken {
		t.Fatalf("revoked token deleted user: err=%v", err)
	}
	if updateCalls != 0 || deleteCalls != 0 {
		t.Fatalf("revoked token reached persistence: updates=%d deletes=%d", updateCalls, deleteCalls)
	}
}

func TestUpdateUserCannotRevertConcurrentSuspensionAndRevocation(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	canonical := repository.NewRedisRepo(client)
	user := &domain.User{
		Id: "user-update-cas", Email: "update-cas@example.com", Password: bcryptHash(t, "old-password-123"),
		Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword,
	}
	if err := canonical.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	interleaved := &interleavingUserRepository{UserRepository: canonical}
	interleaved.beforeUpdate = func() {
		if _, _, err := canonical.IncrementTokenVersion(ctx, user.Email); err != nil {
			t.Errorf("concurrent revoke: %v", err)
		}
		if _, err := canonical.SetStatus(ctx, user.Email, domain.UserStatusSuspended); err != nil {
			t.Errorf("concurrent suspend: %v", err)
		}
	}
	service := NewUserService(
		interleaved, nil, nil, nil, "jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
	).(*userService)
	token := signCurrentIDToken(t, "jwt-secret", user.Email, "https://issuer", "tikti", 0)

	if response, err := service.UpdateUser(ctx, domain.UpdateReq{
		IdToken: token, Password: "replacement-password-123",
	}); !errors.Is(err, domain.ErrVersionConflict) || response != nil {
		t.Fatalf("stale update response=%#v err=%v", response, err)
	}
	stored, err := canonical.FindByEmail(ctx, user.Email)
	if err != nil || stored == nil {
		t.Fatalf("stored user = %#v, %v", stored, err)
	}
	if stored.Status != domain.UserStatusSuspended || stored.TokenVersion != 2 ||
		!utils.VerifyPassword(stored.Password, "old-password-123") {
		t.Fatalf("stale update reverted security state: %#v", stored)
	}
}

func TestStatusTransitionsPermanentlyRevokeExistingSessions(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	repo := repository.NewRedisRepo(client)
	user := &domain.User{
		Id: "user-status-revoke", Email: "status-revoke@example.com", Password: bcryptHash(t, "password-1234"),
		Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword,
	}
	if err := repo.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	service := NewUserService(
		repo, nil, nil, nil, "jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
	).(*userService)
	oldToken := signIDTokenWithClaims(t, "jwt-secret", jwt.MapClaims{
		"sub": user.Id, "email": user.Email, "role": string(user.Role),
		"iss": "https://issuer", "aud": "tikti", "ver": 0,
	})
	if _, err := service.ValidateIDToken(ctx, oldToken, "https://issuer", "tikti"); err != nil {
		t.Fatalf("fresh token did not validate: %v", err)
	}
	if _, err := service.SetStatus(ctx, user.Email, string(domain.UserStatusSuspended)); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if _, err := service.ValidateIDToken(ctx, oldToken, "https://issuer", "tikti"); !errors.Is(err, domain.ErrInvalidCreds) {
		t.Fatalf("suspended user token error=%v, want ErrInvalidCreds", err)
	}
	if _, err := service.SetStatus(ctx, user.Email, string(domain.UserStatusActive)); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if _, err := service.ValidateIDToken(ctx, oldToken, "https://issuer", "tikti"); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("pre-suspension token revived after reactivation: %v", err)
	}
}

func TestResetPasswordCannotRevertConcurrentSuspensionAndRevocation(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	canonical := repository.NewRedisRepo(client)
	user := &domain.User{
		Id: "user-reset-cas", Email: "reset-cas@example.com", Password: bcryptHash(t, "old-password-123"),
		Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword,
	}
	if err := canonical.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := canonical.SaveOobCode(ctx, "reset-code", user.Email, "PASSWORD_RESET"); err != nil {
		t.Fatal(err)
	}
	interleaved := &interleavingUserRepository{UserRepository: canonical}
	interleaved.beforeUpdate = func() {
		if _, _, err := canonical.IncrementTokenVersion(ctx, user.Email); err != nil {
			t.Errorf("concurrent revoke: %v", err)
		}
		if _, err := canonical.SetStatus(ctx, user.Email, domain.UserStatusSuspended); err != nil {
			t.Errorf("concurrent suspend: %v", err)
		}
	}
	service := NewUserService(
		interleaved, nil, nil, nil, "jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
	).(*userService)

	if err := service.ResetPassword(ctx, domain.ResetPwdReq{
		OobCode: "reset-code", NewPassword: "replacement-password-123",
	}); !errors.Is(err, domain.ErrVersionConflict) {
		t.Fatalf("stale reset error = %v, want ErrVersionConflict", err)
	}
	stored, err := canonical.FindByEmail(ctx, user.Email)
	if err != nil || stored == nil {
		t.Fatalf("stored user = %#v, %v", stored, err)
	}
	if stored.Status != domain.UserStatusSuspended || stored.TokenVersion != 2 ||
		!utils.VerifyPassword(stored.Password, "old-password-123") {
		t.Fatalf("stale reset reverted security state: %#v", stored)
	}
}
