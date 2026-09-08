package services

import (
	"context"
	"crypto/rsa"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type synchronizedDirectoryUserLookup struct {
	repository.UserRepository
	reads   atomic.Int32
	release chan struct{}
	once    sync.Once
}

func (r *synchronizedDirectoryUserLookup) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	user, err := r.UserRepository.FindByEmail(ctx, email)
	if r.reads.Add(1) == 2 {
		r.once.Do(func() { close(r.release) })
	}
	select {
	case <-r.release:
		return user, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestIdentityDirectoryServiceTemporaryPasswordLifecycle(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	users := repository.NewRedisRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	service := NewIdentityDirectoryService(directory, users, nil, nil, false)

	created, err := service.CreateUser(context.Background(), domain.DirectoryUserCreateReq{Email: " NEW@Example.COM ", TemporaryPassword: "temporary-1234"})
	if err != nil || created.Email != "new@example.com" || !created.PasswordChangeRequired {
		t.Fatalf("create = %#v, %v", created, err)
	}
	stored, err := users.FindByEmail(context.Background(), created.Email)
	if err != nil || stored == nil || stored.Password == "temporary-1234" || !utils.VerifyPassword(stored.Password, "temporary-1234") || stored.CompanyId != nil {
		t.Fatalf("stored temporary user = %#v, %v", stored, err)
	}
	tokens := NewUserService(
		users, nil, nil, nil, "jwt-secret", "https://tikti", "tikti", "", "",
		WithIdentityDirectoryAccess(directory),
	)
	if response, signInErr := tokens.SignIn(context.Background(), domain.SignInReq{Email: created.Email, Password: "temporary-1234"}); response != nil || !errors.Is(signInErr, domain.ErrPasswordChangeRequired) {
		t.Fatalf("temporary sign-in = %#v, %v", response, signInErr)
	}
	if _, err = service.CreateUser(context.Background(), domain.DirectoryUserCreateReq{Email: "NEW@example.com", TemporaryPassword: "temporary-5678"}); !errors.Is(err, domain.ErrEmailExists) {
		t.Fatalf("duplicate = %v", err)
	}
	if err = service.ChangeTemporaryPassword(context.Background(), domain.TemporaryPasswordChangeReq{Email: created.Email, TemporaryPassword: "wrong-password", NewPassword: "permanent-1234"}); !errors.Is(err, domain.ErrInvalidCreds) {
		t.Fatalf("wrong temporary password = %v", err)
	}
	if err = service.ChangeTemporaryPassword(context.Background(), domain.TemporaryPasswordChangeReq{Email: created.Email, TemporaryPassword: "temporary-1234", NewPassword: "permanent-1234"}); err != nil {
		t.Fatalf("change = %v", err)
	}
	stored, err = users.FindByEmail(context.Background(), created.Email)
	if err != nil || stored.PasswordChangeRequired || stored.TokenVersion != 1 || !utils.VerifyPassword(stored.Password, "permanent-1234") {
		t.Fatalf("rotated user = %#v, %v", stored, err)
	}
	if response, signInErr := tokens.SignIn(context.Background(), domain.SignInReq{Email: created.Email, Password: "permanent-1234"}); signInErr != nil || response == nil || response.IdToken == "" {
		t.Fatalf("normal sign-in after rotation = %#v, %v", response, signInErr)
	}
}

func TestIdentityDirectoryUserCanExchangeAfterPasswordChangeAndDirectAssignment(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	users := repository.NewRedisRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	tenants := repository.NewTenantRepo(client)
	roles := repository.NewRoleRepo(client)
	memberships := repository.NewMembershipRepo(client)
	if err := tenants.Create(ctx, &domain.Tenant{
		Id: "bereia", Slug: "bereia", Name: "Bereia", Status: domain.TenantStatusActive, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := roles.Create(ctx, "bereia", &domain.Role{
		Name: "reader", Scope: domain.RoleScopeTenant, TenantId: "bereia",
		Permissions: []string{
			"code-admin:environments:read",
			"code-admin:repositories:read",
			"code-admin:services:read",
		},
	}); err != nil {
		t.Fatal(err)
	}
	directoryService := NewIdentityDirectoryService(
		directory,
		users,
		tenants.(repository.ExactTenantRepository),
		roles.(repository.ExactRoleBatchRepository),
		false,
	)
	created, err := directoryService.CreateUser(ctx, domain.DirectoryUserCreateReq{
		Email: "global-user@example.com", TemporaryPassword: "temporary-1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = directoryService.ChangeTemporaryPassword(ctx, domain.TemporaryPasswordChangeReq{
		Email: created.Email, TemporaryPassword: "temporary-1234", NewPassword: "permanent-1234",
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = directoryService.PutAssignment(
		ctx, "bereia", domain.AccessPrincipalUser, created.ID, []string{"reader"}, "",
	); err != nil {
		t.Fatal(err)
	}
	stored, err := users.FindByEmail(ctx, created.Email)
	if err != nil || stored == nil || stored.CompanyId != nil {
		t.Fatalf("directory user gained a legacy home or membership: user=%#v err=%v", stored, err)
	}
	if membership, membershipErr := memberships.Get(ctx, "bereia", created.ID); membershipErr != nil || membership != nil {
		t.Fatalf("direct assignment wrote a legacy membership: membership=%#v err=%v", membership, membershipErr)
	}

	directoryAudienceScopes := append([]string(nil), managedAudienceScopes...)
	directoryAudienceScopes = append(directoryAudienceScopes,
		"code-admin:environments:read",
		"code-admin:repositories:read",
	)
	slices.Sort(directoryAudienceScopes)
	clients := discoveryClientService(t, false)
	getClient := clients.getClientFn
	clients.getClientFn = func(ctx context.Context, tenantID, clientID string) (*domain.Client, error) {
		client, getErr := getClient(ctx, tenantID, clientID)
		if client != nil {
			client.DefaultScopes = append([]string(nil), directoryAudienceScopes...)
		}
		return client, getErr
	}
	tokens := NewUserService(
		users,
		memberships,
		NewRoleService(roles),
		clients,
		"jwt-secret",
		"https://issuer",
		"tikti",
		makePEMKey(t),
		"kid",
		WithIdentityDirectoryAccess(directory),
		WithTenantTargetDiscoveryV2(true, []string{"local-tenant"}, tenants),
	).(*userService)
	signIn, err := tokens.SignIn(ctx, domain.SignInReq{Email: created.Email, Password: "permanent-1234"})
	if err != nil || signIn == nil || signIn.IdToken == "" {
		t.Fatalf("normal sign-in = %#v, %v", signIn, err)
	}
	idClaims, err := utils.ParseToken(signIn.IdToken, "jwt-secret")
	if err != nil || idClaims["tid"] != nil {
		t.Fatalf("global directory ID token must not forge a legacy home: claims=%v err=%v", idClaims, err)
	}
	directoryRequestedScopes := []string{
		"code-admin:environments:read",
		"code-admin:repositories:read",
		"code-admin:services:read",
	}
	exchange, err := tokens.TokenExchange(ctx, domain.TokenExchangeReq{
		IdToken: signIn.IdToken, Audience: domain.CodeAdminAudienceClientID, TenantID: "bereia",
		DiscoverTenantTargetsV2: true,
		ScopeCeilingV1:          directoryAudienceScopes,
		Scopes:                  directoryRequestedScopes,
		TTLSeconds:              300,
	})
	if err != nil {
		t.Fatalf("assigned global user exchange: %v", err)
	}
	if exchange.PrincipalTenantID != "bereia" ||
		!slices.Equal(exchange.AuthorizedTenants, []string{"bereia"}) ||
		!slices.Equal(exchange.Scopes, directoryRequestedScopes) {
		t.Fatalf("unexpected directory authority: %#v", exchange)
	}
	forgedClaims := idClaims
	forgedClaims["tid"] = "bereia"
	forgedRequest := domain.TokenExchangeReq{
		IdToken:                 signIDTokenWithClaims(t, "jwt-secret", forgedClaims),
		Audience:                domain.CodeAdminAudienceClientID,
		TenantID:                "bereia",
		DiscoverTenantTargetsV2: true,
		ScopeCeilingV1:          append([]string(nil), managedAudienceScopes...),
		Scopes:                  []string{"code-admin:services:read"},
		TTLSeconds:              300,
	}
	if forgedExchange, forgedErr := tokens.TokenExchange(ctx, forgedRequest); !errors.Is(forgedErr, domain.ErrInvalidTenant) || forgedExchange != nil {
		t.Fatalf("directory principal supplied a forged home: response=%#v err=%v", forgedExchange, forgedErr)
	}
	key, err := tokens.getRSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	accessClaims, err := utils.ValidateRS256(
		exchange.AccessToken,
		&key.(*rsa.PrivateKey).PublicKey,
		"https://issuer",
		domain.CodeAdminAudienceClientID,
	)
	if err != nil || accessClaims["tid"] != "bereia" || accessClaims["role"] != nil ||
		!slices.Equal(accessClaims["roles"].([]interface{}), []interface{}{"reader"}) {
		t.Fatalf("unexpected assigned access claims=%v err=%v", accessClaims, err)
	}
}

func TestIdentityDirectoryUserRequiresAssignmentForEveryTokenExchange(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	users := repository.NewRedisRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	tenants := repository.NewTenantRepo(client)
	roles := repository.NewRoleRepo(client)
	if err := tenants.Create(ctx, &domain.Tenant{
		Id: "bereia", Slug: "bereia", Name: "Bereia", Status: domain.TenantStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := roles.Create(ctx, "bereia", &domain.Role{
		Name: "worker", Scope: domain.RoleScopeTenant, TenantId: "bereia",
		Permissions: []string{"codeq:claim"},
	}); err != nil {
		t.Fatal(err)
	}
	directoryService := NewIdentityDirectoryService(
		directory, users, tenants.(repository.ExactTenantRepository), roles.(repository.ExactRoleBatchRepository), false,
	)
	created, err := directoryService.CreateUser(ctx, domain.DirectoryUserCreateReq{
		Email: "worker@example.com", TemporaryPassword: "temporary-1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = directoryService.ChangeTemporaryPassword(ctx, domain.TemporaryPasswordChangeReq{
		Email: created.Email, TemporaryPassword: "temporary-1234", NewPassword: "permanent-1234",
	}); err != nil {
		t.Fatal(err)
	}
	audienceClient := &domain.Client{
		Id: "codeq-worker", TenantId: "bereia", Status: domain.ClientStatusActive,
		DefaultScopes: []string{"codeq:claim"},
	}
	clients := &mockClientService{getClientFn: func(_ context.Context, tenantID, clientID string) (*domain.Client, error) {
		if tenantID != "bereia" || clientID != "codeq-worker" {
			t.Fatalf("unexpected client lookup tenant=%q client=%q", tenantID, clientID)
		}
		copy := *audienceClient
		return &copy, nil
	}}
	tokens := NewUserService(
		users, nil, NewRoleService(roles), clients, "jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithIdentityDirectoryAccess(directory),
		WithTenantTargetDiscoveryV2(true, []string{domain.MasterTenantID}, tenants),
	).(*userService)
	signIn, err := tokens.SignIn(ctx, domain.SignInReq{Email: created.Email, Password: "permanent-1234"})
	if err != nil {
		t.Fatal(err)
	}
	request := domain.TokenExchangeReq{
		IdToken: signIn.IdToken, Audience: "codeq-worker", TenantID: "bereia",
		Scopes: []string{"codeq:claim"}, EventTypes: []string{"render_video"},
	}
	if response, exchangeErr := tokens.TokenExchange(ctx, request); !errors.Is(exchangeErr, domain.ErrInvalidTenant) || response != nil {
		t.Fatalf("unassigned directory user exchanged token: response=%#v err=%v", response, exchangeErr)
	}
	assignment, _, err := directoryService.PutAssignment(
		ctx, "bereia", domain.AccessPrincipalUser, created.ID, []string{"worker"}, "",
	)
	if err != nil || assignment == nil {
		t.Fatalf("assignment=%#v err=%v", assignment, err)
	}
	issued, exchangeErr := tokens.TokenExchange(ctx, request)
	if exchangeErr != nil || issued == nil {
		t.Fatalf("assigned directory user exchange: response=%#v err=%v", issued, exchangeErr)
	}
	if claims, validateErr := tokens.ValidateAccessToken(ctx, issued.AccessToken, "https://issuer", "codeq-worker"); validateErr != nil || claims == nil {
		t.Fatalf("fresh assigned access token did not validate: claims=%#v err=%v", claims, validateErr)
	}
	if err = tenants.Create(ctx, &domain.Tenant{
		Id: "bereia", Slug: "bereia", Name: "Bereia", Status: domain.TenantStatusDisabled,
	}); err != nil {
		t.Fatal(err)
	}
	if claims, validateErr := tokens.ValidateAccessToken(ctx, issued.AccessToken, "https://issuer", "codeq-worker"); !errors.Is(validateErr, domain.ErrInvalidToken) || claims != nil {
		t.Fatalf("access token remained valid after tenant disable: claims=%#v err=%v", claims, validateErr)
	}
	if err = tenants.Create(ctx, &domain.Tenant{
		Id: "bereia", Slug: "bereia", Name: "Bereia", Status: domain.TenantStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	audienceClient.Status = "DISABLED"
	if claims, validateErr := tokens.ValidateAccessToken(ctx, issued.AccessToken, "https://issuer", "codeq-worker"); !errors.Is(validateErr, domain.ErrInvalidToken) || claims != nil {
		t.Fatalf("access token remained valid after audience client disable: claims=%#v err=%v", claims, validateErr)
	}
	audienceClient.Status = domain.ClientStatusActive
	audienceClient.DefaultScopes = nil
	if claims, validateErr := tokens.ValidateAccessToken(ctx, issued.AccessToken, "https://issuer", "codeq-worker"); !errors.Is(validateErr, domain.ErrInvalidToken) || claims != nil {
		t.Fatalf("access token retained a scope removed from audience client: claims=%#v err=%v", claims, validateErr)
	}
	audienceClient.DefaultScopes = []string{"codeq:claim"}
	if deleted, deleteErr := directoryService.DeleteAssignment(
		ctx, "bereia", domain.AccessPrincipalUser, created.ID, repository.IdentityETag(assignment.Version),
	); deleteErr != nil || !deleted {
		t.Fatalf("delete assignment=%v err=%v", deleted, deleteErr)
	}
	if response, exchangeErr := tokens.TokenExchange(ctx, request); !errors.Is(exchangeErr, domain.ErrInvalidTenant) || response != nil {
		t.Fatalf("revoked directory user exchanged token: response=%#v err=%v", response, exchangeErr)
	}
	if claims, validateErr := tokens.ValidateAccessToken(ctx, issued.AccessToken, "https://issuer", "codeq-worker"); !errors.Is(validateErr, domain.ErrInvalidToken) || claims != nil {
		t.Fatalf("access token issued before assignment revoke remained valid: claims=%#v err=%v", claims, validateErr)
	}
}

func TestAccessTokenAuthorityTracksGroupAndRoleChanges(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	users := repository.NewRedisRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	tenants := repository.NewTenantRepo(client)
	roleRepository := repository.NewRoleRepo(client)
	if err := tenants.Create(ctx, &domain.Tenant{
		Id: "bereia", Slug: "bereia", Name: "Bereia", Status: domain.TenantStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	writeRole := func(permission string) {
		t.Helper()
		if err := roleRepository.Create(ctx, "bereia", &domain.Role{
			Name: "worker", Scope: domain.RoleScopeTenant, TenantId: "bereia", Permissions: []string{permission},
		}); err != nil {
			t.Fatal(err)
		}
	}
	writeRole("codeq:claim")
	directoryService := NewIdentityDirectoryService(
		directory, users, tenants.(repository.ExactTenantRepository), roleRepository.(repository.ExactRoleBatchRepository), true,
	)
	created, err := directoryService.CreateUser(ctx, domain.DirectoryUserCreateReq{
		Email: "group-worker@example.com", TemporaryPassword: "temporary-1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = directoryService.ChangeTemporaryPassword(ctx, domain.TemporaryPasswordChangeReq{
		Email: created.Email, TemporaryPassword: "temporary-1234", NewPassword: "permanent-1234",
	}); err != nil {
		t.Fatal(err)
	}
	tokens := NewUserService(
		users, nil, NewRoleService(roleRepository), &mockClientService{getClientFn: func(_ context.Context, tenantID, clientID string) (*domain.Client, error) {
			return &domain.Client{Id: clientID, TenantId: tenantID, Status: domain.ClientStatusActive, DefaultScopes: []string{"codeq:claim"}}, nil
		}}, "jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid", WithIdentityDirectoryAccess(directory),
	).(*userService)
	signIn, err := tokens.SignIn(ctx, domain.SignInReq{Email: created.Email, Password: "permanent-1234"})
	if err != nil {
		t.Fatal(err)
	}
	issue := func() string {
		t.Helper()
		response, exchangeErr := tokens.TokenExchange(ctx, domain.TokenExchangeReq{
			IdToken: signIn.IdToken, Audience: "codeq-worker", TenantID: "bereia",
			Scopes: []string{"codeq:claim"}, EventTypes: []string{"render_video"},
		})
		if exchangeErr != nil || response == nil {
			t.Fatalf("issue access token: response=%#v err=%v", response, exchangeErr)
		}
		return response.AccessToken
	}
	requireRevoked := func(token, mutation string) {
		t.Helper()
		claims, validateErr := tokens.ValidateAccessToken(ctx, token, "https://issuer", "codeq-worker")
		if !errors.Is(validateErr, domain.ErrInvalidToken) || claims != nil {
			t.Fatalf("token survived %s: claims=%#v err=%v", mutation, claims, validateErr)
		}
	}

	group, err := directoryService.CreateGroup(ctx, domain.IdentityGroupCreateReq{Name: "Workers"})
	if err != nil {
		t.Fatal(err)
	}
	group, _, err = directoryService.PutGroupMember(ctx, group.ID, created.ID, repository.IdentityETag(group.Version))
	if err != nil {
		t.Fatal(err)
	}
	assignment, _, err := directoryService.PutAssignment(ctx, "bereia", domain.AccessPrincipalGroup, group.ID, []string{"worker"}, "")
	if err != nil {
		t.Fatal(err)
	}
	memberToken := issue()
	group, _, err = directoryService.DeleteGroupMember(ctx, group.ID, created.ID, repository.IdentityETag(group.Version))
	if err != nil {
		t.Fatal(err)
	}
	requireRevoked(memberToken, "group member removal")

	group, _, err = directoryService.PutGroupMember(ctx, group.ID, created.ID, repository.IdentityETag(group.Version))
	if err != nil {
		t.Fatal(err)
	}
	assignmentToken := issue()
	if deleted, deleteErr := directoryService.DeleteAssignment(ctx, "bereia", domain.AccessPrincipalGroup, group.ID, repository.IdentityETag(assignment.Version)); deleteErr != nil || !deleted {
		t.Fatalf("delete group assignment=%v err=%v", deleted, deleteErr)
	}
	requireRevoked(assignmentToken, "group assignment removal")

	assignment, _, err = directoryService.PutAssignment(ctx, "bereia", domain.AccessPrincipalGroup, group.ID, []string{"worker"}, "")
	if err != nil {
		t.Fatal(err)
	}
	disableToken := issue()
	disabled := domain.IdentityGroupStatusDisabled
	group, err = directoryService.PatchGroup(ctx, group.ID, domain.IdentityGroupPatchReq{Status: &disabled}, repository.IdentityETag(group.Version))
	if err != nil {
		t.Fatal(err)
	}
	requireRevoked(disableToken, "group disable")

	active := domain.IdentityGroupStatusActive
	group, err = directoryService.PatchGroup(ctx, group.ID, domain.IdentityGroupPatchReq{Status: &active}, repository.IdentityETag(group.Version))
	if err != nil {
		t.Fatal(err)
	}
	deleteToken := issue()
	if deleted, deleteErr := directoryService.DeleteGroup(ctx, group.ID, repository.IdentityETag(group.Version)); deleteErr != nil || !deleted {
		t.Fatalf("delete group=%v err=%v", deleted, deleteErr)
	}
	requireRevoked(deleteToken, "group deletion")

	if _, _, err = directoryService.PutAssignment(ctx, "bereia", domain.AccessPrincipalUser, created.ID, []string{"worker"}, ""); err != nil {
		t.Fatal(err)
	}
	roleToken := issue()
	writeRole("codeq:nack")
	requireRevoked(roleToken, "role permission change")
}

func TestIdentityDirectoryServiceRateLimitsTemporaryPasswordChangesPerNormalizedEmail(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	users := repository.NewRedisRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	service := NewIdentityDirectoryService(directory, users, nil, nil, false)
	created, err := service.CreateUser(context.Background(), domain.DirectoryUserCreateReq{
		Email: "Rate-Limit@Example.com", TemporaryPassword: "temporary-1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 5; attempt++ {
		err = service.ChangeTemporaryPassword(context.Background(), domain.TemporaryPasswordChangeReq{
			Email: " RATE-LIMIT@example.COM ", TemporaryPassword: "wrong-password", NewPassword: "permanent-1234",
		})
		if !errors.Is(err, domain.ErrInvalidCreds) {
			t.Fatalf("attempt %d = %v", attempt, err)
		}
	}
	err = service.ChangeTemporaryPassword(context.Background(), domain.TemporaryPasswordChangeReq{
		Email: created.Email, TemporaryPassword: "temporary-1234", NewPassword: "permanent-1234",
	})
	if !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("sixth attempt = %v", err)
	}
	for _, key := range server.Keys() {
		if strings.Contains(key, "auth:temporary-password") && strings.Contains(strings.ToLower(key), "rate-limit@example.com") {
			t.Fatalf("rate-limit key exposes email: %q", key)
		}
	}
}

func TestIdentityDirectoryServiceAlwaysPerformsOneCostMatchedPasswordCheck(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	users := repository.NewRedisRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	service := NewIdentityDirectoryService(directory, users, nil, nil, false).(*identityDirectoryService)
	checkedHashes := []string{}
	service.verifyPassword = func(hash, _ string) bool {
		checkedHashes = append(checkedHashes, hash)
		return false
	}

	request := domain.TemporaryPasswordChangeReq{
		Email: "unknown@example.com", TemporaryPassword: "temporary-1234", NewPassword: "permanent-1234",
	}
	if err := service.ChangeTemporaryPassword(context.Background(), request); !errors.Is(err, domain.ErrInvalidCreds) {
		t.Fatalf("unknown account = %v", err)
	}
	created, err := service.CreateUser(context.Background(), domain.DirectoryUserCreateReq{
		Email: "known@example.com", TemporaryPassword: "temporary-1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	request.Email = created.Email
	if err = service.ChangeTemporaryPassword(context.Background(), request); !errors.Is(err, domain.ErrInvalidCreds) {
		t.Fatalf("known account = %v", err)
	}
	if len(checkedHashes) != 2 || checkedHashes[0] != temporaryPasswordDummyHash ||
		checkedHashes[1] == temporaryPasswordDummyHash {
		t.Fatalf("password checks did not use one indistinguishable path: %#v", checkedHashes)
	}
	for _, hash := range checkedHashes {
		cost, costErr := bcrypt.Cost([]byte(hash))
		if costErr != nil || cost != bcrypt.DefaultCost {
			t.Fatalf("password check hash has wrong cost: cost=%d err=%v", cost, costErr)
		}
	}
}

func TestIdentityDirectoryServiceConsumesTemporaryPasswordExactlyOnce(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	baseUsers := repository.NewRedisRepo(client)
	users := &synchronizedDirectoryUserLookup{UserRepository: baseUsers, release: make(chan struct{})}
	directory := repository.NewIdentityDirectoryRepository(client)
	service := NewIdentityDirectoryService(directory, users, nil, nil, false)

	created, err := service.CreateUser(context.Background(), domain.DirectoryUserCreateReq{
		Email: "race@example.com", TemporaryPassword: "temporary-1234",
	})
	if err != nil {
		t.Fatal(err)
	}

	errorsByRequest := make(chan error, 2)
	for _, password := range []string{"permanent-one-1234", "permanent-two-1234"} {
		password := password
		go func() {
			errorsByRequest <- service.ChangeTemporaryPassword(context.Background(), domain.TemporaryPasswordChangeReq{
				Email: created.Email, TemporaryPassword: "temporary-1234", NewPassword: password,
			})
		}()
	}
	first, second := <-errorsByRequest, <-errorsByRequest
	successes, rejected := 0, 0
	for _, changeErr := range []error{first, second} {
		if changeErr == nil {
			successes++
		} else if errors.Is(changeErr, domain.ErrInvalidCreds) {
			rejected++
		} else {
			t.Fatalf("unexpected concurrent change error: %v", changeErr)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("temporary password was not consumed exactly once: successes=%d rejected=%d errors=%v/%v", successes, rejected, first, second)
	}
	stored, err := baseUsers.FindByEmail(context.Background(), created.Email)
	if err != nil || stored == nil || stored.PasswordChangeRequired || stored.TokenVersion != 1 {
		t.Fatalf("stored user after concurrent change = %#v, %v", stored, err)
	}
}

func TestTenantOOBNeverOnboardsUnknownUser(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	users := repository.NewRedisRepo(client)
	legacy := repository.NewMembershipRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	service := NewUserService(users, legacy, nil, nil, "jwt-secret", "https://tikti", "tikti", "", "", WithIdentityDirectoryAccess(directory))

	response, err := service.SendOobForTenant(ctx, "bereia", domain.SendOobReq{RequestType: "EMAIL_SIGNIN", Email: "new@example.com"})
	if err != nil || response == nil || response.OobCode == "" {
		t.Fatalf("tenant OOB onboarding = %#v, %v", response, err)
	}
	user, err := users.FindByEmail(ctx, "new@example.com")
	if err != nil || user != nil {
		t.Fatalf("unknown user was persisted = %#v, %v", user, err)
	}
	assignments, err := directory.ListAccessAssignments(ctx, "bereia", "", 50)
	if err != nil || assignments == nil || len(assignments.Assignments) != 0 {
		t.Fatalf("unknown user gained canonical access = %#v, %v", assignments, err)
	}
	if tenantIDs, legacyErr := legacy.ListTenantIDsByUser(ctx, "unknown-user"); legacyErr != nil || len(tenantIDs) != 0 {
		t.Fatalf("unknown user gained legacy membership = %#v, %v", tenantIDs, legacyErr)
	}
}

func TestIdentityDirectoryServiceValidatesTenantRolesAndDarkGroups(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	users := repository.NewRedisRepo(client)
	directory := repository.NewIdentityDirectoryRepository(client)
	tenants := repository.NewTenantRepo(client)
	roles := repository.NewRoleRepo(client)
	now := time.Now().UTC()
	if err := tenants.Create(context.Background(), &domain.Tenant{Id: "bereia", Slug: "bereia", Name: "Bereia", Status: domain.TenantStatusActive, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := roles.Create(context.Background(), "bereia", &domain.Role{Name: "reader", Scope: domain.RoleScopeTenant, TenantId: "bereia", Permissions: []string{"code-admin:services:read"}}); err != nil {
		t.Fatal(err)
	}
	user, err := directory.CreateDirectoryUser(context.Background(), &domain.User{Id: "user-1", Email: "one@example.com", Password: "hash", Role: domain.RoleCompanyEmployee, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	dark := NewIdentityDirectoryService(directory, users, tenants.(repository.ExactTenantRepository), roles.(repository.ExactRoleBatchRepository), false)
	if _, err = dark.CreateGroup(context.Background(), domain.IdentityGroupCreateReq{Name: "Readers"}); !errors.Is(err, domain.ErrGroupMutationsDisabled) {
		t.Fatalf("dark group = %v", err)
	}
	assignment, created, err := dark.PutAssignment(context.Background(), "bereia", domain.AccessPrincipalUser, user.ID, []string{"reader"}, "")
	if err != nil || !created || assignment.Version != 1 {
		t.Fatalf("direct = %#v %v %v", assignment, created, err)
	}
	if _, _, err = dark.PutAssignment(context.Background(), "bereia", domain.AccessPrincipalUser, user.ID, []string{"missing"}, ""); !errors.Is(err, domain.ErrMembershipDependencyNotFound) {
		t.Fatalf("missing role = %v", err)
	}
}
