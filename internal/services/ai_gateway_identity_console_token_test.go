package services

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/scopepolicy"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// Owner requirement (ADR-0024 Amendment 2): a workload tenant administrator
// enabling AI must obtain code-admin:ai:* in the dynamic Console session,
// which intersects the user's tenant roles with the managed code-admin-api
// ceiling. Before activation the ceiling lacks the AI scopes; after it the
// assigned <tenant>-ai-admin role is effective. Global AI scopes never appear.
func TestAIGatewayActivationMakesTenantAIAdminEffectiveInConsoleToken(t *testing.T) {
	ctx := context.Background()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	users := repository.NewRedisRepo(client)
	tenants := repository.NewTenantRepo(client)
	roles := repository.NewRoleRepo(client)
	clients := repository.NewClientRepo(client)
	directoryRepo := repository.NewIdentityDirectoryRepository(client)
	const tenantID = "workload-1"
	if _, _, err := tenants.CreateIfAbsent(ctx, &domain.Tenant{Id: tenantID, Slug: tenantID, Name: tenantID, Status: domain.TenantStatusActive, CreatedAt: time.Now().Add(-time.Hour).UTC()}); err != nil {
		t.Fatal(err)
	}
	directory := NewIdentityDirectoryService(directoryRepo, users, tenants.(repository.ExactTenantRepository), roles.(repository.ExactRoleBatchRepository), false)
	ai := NewAIGatewayIdentityService(tenants, NewRoleService(roles), clients.(AIGatewayClientStore), directory)
	// A directory administrator of exactly this tenant (no legacy home).
	created, err := directory.CreateUser(ctx, domain.DirectoryUserCreateReq{Email: "tenant-admin@example.com", TemporaryPassword: "temporary-1234"})
	if err != nil {
		t.Fatal(err)
	}
	if err = directory.ChangeTemporaryPassword(ctx, domain.TemporaryPasswordChangeReq{Email: created.Email, TemporaryPassword: "temporary-1234", NewPassword: "permanent-1234"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewRoleService(roles).CreateWithName(ctx, tenantID, "identity-admin", domain.RolePutReq{Permissions: []string{"code-admin:identity:write"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = directory.PutAssignment(ctx, tenantID, domain.AccessPrincipalUser, created.ID, []string{"identity-admin"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := clients.EnsureManagedAudience(ctx, tenantID, managedConsoleClient(tenantID, consoleBaselineScopes)); err != nil {
		t.Fatal(err)
	}

	console := NewUserService(users, repository.NewMembershipRepo(client), NewRoleService(roles), NewClientService(clients),
		"jwt-secret", "https://issuer", "tikti", makePEMKey(t), "kid",
		WithIdentityDirectoryAccess(directoryRepo),
		WithTenantTargetDiscoveryV2(true, []string{domain.MasterTenantID}, tenants),
	).(*userService)
	requestCeiling, ok := scopepolicy.CanonicalAudienceScopes([]string{
		"code-admin:ai:read", "code-admin:ai:write", "code-admin:audit:read", "code-admin:identity:write",
	})
	if !ok {
		t.Fatal("request ceiling fixture is invalid")
	}
	exchange := func() []string {
		t.Helper()
		signIn, err := console.SignIn(ctx, domain.SignInReq{Email: created.Email, Password: "permanent-1234"})
		if err != nil {
			t.Fatalf("sign-in: %v", err)
		}
		out, err := console.TokenExchange(ctx, domain.TokenExchangeReq{
			IdToken:  signIn.IdToken,
			Audience: domain.CodeAdminAudienceClientID, TenantID: tenantID, DiscoverTenantTargetsV2: true,
			ScopeCeilingV1: requestCeiling, TTLSeconds: 300,
		})
		if err != nil {
			t.Fatalf("console exchange: %v", err)
		}
		return out.Scopes
	}
	if scopes := exchange(); slices.Contains(scopes, "code-admin:ai:read") || slices.Contains(scopes, "code-admin:ai:write") {
		t.Fatalf("AI scopes present before activation: %v", scopes)
	}
	if _, created, err := ai.Ensure(ctx, tenantID, created.ID); err != nil || !created {
		t.Fatalf("activation created=%v err=%v", created, err)
	}
	scopes := exchange()
	if !slices.Contains(scopes, "code-admin:ai:read") || !slices.Contains(scopes, "code-admin:ai:write") {
		t.Fatalf("tenant AI admin role is not effective in the Console token: %v", scopes)
	}
	for _, scope := range []string{"code-admin:ai:platform", "code-admin:ai:runtime"} {
		if slices.Contains(scopes, scope) {
			t.Fatalf("global scope %s reached a tenant Console token: %v", scope, scopes)
		}
	}
}
