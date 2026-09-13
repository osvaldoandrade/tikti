package main

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestBootstrapIsIdempotentAndRotatesPassword(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	cfg := settings{
		tenantID: "local-tenant", tenantName: "Local Tenant", email: "admin@local.test",
		password: "initial-password-123", audience: "code-admin-api", scopes: []string{"code-admin:services:read"},
		workloadSubject: "system:serviceaccount:codecloud-control:code-admin-controller-queue",
	}
	if err := bootstrap(context.Background(), data, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.password = "rotated-password-456"
	if err := bootstrap(context.Background(), data, cfg); err != nil {
		t.Fatal(err)
	}
	user, err := data.users.FindByEmail(context.Background(), cfg.email)
	if err != nil {
		t.Fatal(err)
	}
	if user == nil || user.Role != domain.RoleAdmin || user.CompanyId == nil || *user.CompanyId != cfg.tenantID {
		t.Fatalf("unexpected bootstrap user: %#v", user)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(cfg.password)); err != nil {
		t.Fatal("bootstrap did not rotate the password")
	}
	membership, err := data.memberships.Get(context.Background(), cfg.tenantID, user.Id)
	if err != nil || membership == nil || len(membership.Roles) != 1 || membership.Roles[0] != "ADMIN" {
		t.Fatalf("unexpected membership: %#v, %v", membership, err)
	}
	clientRecord, err := data.clients.Get(context.Background(), cfg.tenantID, cfg.audience)
	if err != nil || clientRecord == nil || clientRecord.Status != "ACTIVE" {
		t.Fatalf("unexpected client: %#v, %v", clientRecord, err)
	}
	workload, err := data.workloads.Get(context.Background(), cfg.workloadSubject)
	if err != nil || workload == nil || workload.Namespace != "codecloud-control" ||
		len(workload.Grants) != 1 || workload.Grants[0].TenantID != cfg.tenantID {
		t.Fatalf("unexpected workload binding: %#v, %v", workload, err)
	}
}

func TestBootstrapImportsBoundedArgon2idPasswordHash(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	salt := []byte("0123456789abcdef")
	hash := argon2.IDKey([]byte("correct-password"), salt, 3, 64*1024, 4, 32)
	encoded := "$argon2id$v=19$m=65536,t=3,p=4$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(hash)
	cfg := settings{
		tenantID: "local-tenant", tenantName: "Local Tenant", email: "admin@codecloud.local",
		passwordHash: encoded, audience: "code-admin-api", scopes: []string{"code-admin:services:read"},
	}
	if err := bootstrap(context.Background(), data, cfg); err != nil {
		t.Fatal(err)
	}
	user, err := data.users.FindByEmail(context.Background(), cfg.email)
	if err != nil || user == nil || user.Password != encoded {
		t.Fatalf("unexpected imported password hash: user=%#v err=%v", user, err)
	}
}

func TestBootstrapExistingUserOnlyPreservesCredentialAndAddsMasterAccess(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
		directory: repository.NewIdentityDirectoryRepository(client),
	}
	workloadTenant := "conveste"
	credential, err := bcrypt.GenerateFromPassword([]byte("existing-password-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	user := &domain.User{
		Id: "existing-admin", Email: "admin@example.com", Password: string(credential),
		Role: domain.RoleAdmin, Status: domain.UserStatusActive, CompanyId: &workloadTenant,
		AuthSource: domain.AuthSourcePassword,
	}
	if err = data.users.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if err = data.tenants.Create(context.Background(), &domain.Tenant{
		Id: workloadTenant, Slug: workloadTenant, Name: "Conveste",
		Status: domain.TenantStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err = data.clients.UpsertBootstrap(context.Background(), workloadTenant, &domain.Client{
		Id: domain.CodeAdminAudienceClientID, TenantId: workloadTenant, Type: domain.ClientTypePublic,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     []string{"console:resources:read"}, Status: domain.ClientStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = data.directory.PutAccessAssignment(
		context.Background(), workloadTenant, domain.AccessPrincipalUser, user.Id, []string{"ADMIN"}, "",
	); err != nil {
		t.Fatal(err)
	}

	cfg := settings{
		tenantID: "local-tenant", tenantName: "Code Foundry", email: user.Email,
		existingUserOnly: true, audience: "code-admin-api",
		scopes: []string{
			"code-admin:clusters:read", "code-admin:services:read",
			"console:resources:read", "console:storage:read",
		},
	}
	if err = bootstrap(context.Background(), data, cfg); err != nil {
		t.Fatal(err)
	}

	updated, err := data.users.FindByEmail(context.Background(), user.Email)
	if err != nil || updated == nil {
		t.Fatalf("updated user=%#v err=%v", updated, err)
	}
	if updated.Password != string(credential) || updated.CompanyId == nil || *updated.CompanyId != workloadTenant ||
		updated.AuthSource != domain.AuthSourcePassword || updated.Role != domain.RoleAdmin ||
		updated.Status != domain.UserStatusActive {
		t.Fatalf("existing identity changed unexpectedly: %#v", updated)
	}
	tenantIDs, exceeded, err := data.directory.ListEffectiveTenantIDs(context.Background(), user.Id, 10)
	if err != nil || exceeded || !reflect.DeepEqual(tenantIDs, []string{"conveste", "local-tenant"}) {
		t.Fatalf("effective tenant access=%v exceeded=%t err=%v", tenantIDs, exceeded, err)
	}
	master, err := data.tenants.Get(context.Background(), domain.MasterTenantID)
	if err != nil || master == nil || master.Name != domain.MasterTenantName || master.Status != domain.TenantStatusActive {
		t.Fatalf("master tenant=%#v err=%v", master, err)
	}
	role, err := data.roles.Get(context.Background(), domain.MasterTenantID, "ADMIN")
	if err != nil || role == nil || !reflect.DeepEqual(role.Permissions, []string{"code-admin:services:read"}) {
		t.Fatalf("master role=%#v err=%v", role, err)
	}
	clientRecord, err := data.clients.Get(context.Background(), domain.MasterTenantID, domain.CodeAdminAudienceClientID)
	if err != nil || !domain.IsManagedCodeAdminAudience(domain.MasterTenantID, clientRecord) ||
		!reflect.DeepEqual(clientRecord.DefaultScopes, []string{
			"code-admin:clusters:read", "code-admin:services:read",
			"console:resources:read", "console:storage:read",
		}) {
		t.Fatalf("master audience=%#v err=%v", clientRecord, err)
	}
	homeClient, err := data.clients.Get(context.Background(), workloadTenant, domain.CodeAdminAudienceClientID)
	if err != nil || homeClient == nil || homeClient.Type != domain.ClientTypePublic ||
		homeClient.ManagedBy != "" || !reflect.DeepEqual(homeClient.DefaultScopes, clientRecord.DefaultScopes) {
		t.Fatalf("home audience=%#v err=%v", homeClient, err)
	}
}

func TestAdoptableLegacyHomeAudienceRequiresExactOwnerAndScopeSubset(t *testing.T) {
	desired := &domain.Client{
		Id: domain.CodeAdminAudienceClientID, TenantId: "conveste", Type: domain.ClientTypePublic,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     []string{"console:resources:read", "console:storage:read"},
		Status:            domain.ClientStatusActive,
	}
	valid := *desired
	valid.DefaultScopes = []string{"console:resources:read"}
	if !adoptableLegacyHomeAudience(&valid, desired) {
		t.Fatal("canonical legacy subset was rejected")
	}
	historical := valid
	historical.DefaultScopes = []string{
		"console:storage:read", " console:resources:read ", "console:resources:read",
	}
	if !adoptableLegacyHomeAudience(&historical, desired) {
		t.Fatal("historical non-canonical legacy subset was rejected")
	}
	for name, mutate := range map[string]func(*domain.Client){
		"scope outside ceiling": func(client *domain.Client) {
			client.DefaultScopes = []string{"console:clusters:read"}
		},
		"credential":   func(client *domain.Client) { client.SecretHash = "stored-hash" },
		"wrong tenant": func(client *domain.Client) { client.TenantId = "other" },
		"managed owner": func(client *domain.Client) {
			client.Type = domain.ClientTypeService
			client.ManagedBy = domain.CodeAdminAudienceClientManager
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if adoptableLegacyHomeAudience(&candidate, desired) {
				t.Fatal("unsafe legacy audience was accepted")
			}
		})
	}
}

func TestBootstrapExistingUserOnlyFailsBeforeCreatingTenant(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
		directory: repository.NewIdentityDirectoryRepository(client),
	}
	cfg := settings{
		tenantID: domain.MasterTenantID, tenantName: domain.MasterTenantName,
		email: "missing@example.com", existingUserOnly: true,
		audience: "code-admin-api", scopes: []string{"code-admin:services:read"},
	}
	if err := bootstrap(context.Background(), data, cfg); err == nil {
		t.Fatal("existing-user-only bootstrap accepted a missing user")
	}
	master, err := data.tenants.Get(context.Background(), domain.MasterTenantID)
	if err != nil || master != nil {
		t.Fatalf("missing-user recovery mutated the tenant registry: master=%#v err=%v", master, err)
	}
}

func TestBootstrapExistingUserOnlyRejectsCredentialInput(t *testing.T) {
	cfg := settings{
		tenantID: domain.MasterTenantID, tenantName: domain.MasterTenantName,
		email: "admin@example.com", password: "must-not-be-replaced", existingUserOnly: true,
		audience: "code-admin-api", scopes: []string{"code-admin:services:read"},
	}
	if err := validateSettings(cfg); err == nil {
		t.Fatal("existing-user-only bootstrap accepted credential input")
	}
}

func TestBootstrapExistingUserOnlyRejectsConflictBeforeGrantingAccess(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
		directory: repository.NewIdentityDirectoryRepository(client),
	}
	credential, err := bcrypt.GenerateFromPassword([]byte("existing-password-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	user := &domain.User{
		Id: "existing-admin", Email: "admin@example.com", Password: string(credential),
		Role: domain.RoleAdmin, Status: domain.UserStatusActive, AuthSource: domain.AuthSourcePassword,
	}
	home := "conveste"
	user.CompanyId = &home
	if err = data.users.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if err = data.tenants.Create(context.Background(), &domain.Tenant{
		Id: domain.MasterTenantID, Slug: domain.MasterTenantID, Name: domain.MasterTenantName,
		Status: domain.TenantStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err = data.roles.Create(context.Background(), domain.MasterTenantID, &domain.Role{
		Name: "ADMIN", Scope: domain.RoleScopeTenant, TenantId: domain.MasterTenantID,
		Permissions: []string{"code-admin:services:write"},
	}); err != nil {
		t.Fatal(err)
	}

	cfg := settings{
		tenantID: domain.MasterTenantID, tenantName: domain.MasterTenantName,
		email: user.Email, existingUserOnly: true, audience: domain.CodeAdminAudienceClientID,
		scopes: []string{"code-admin:clusters:read", "code-admin:services:read"},
	}
	if err = bootstrap(context.Background(), data, cfg); err == nil {
		t.Fatal("existing-user-only bootstrap accepted a conflicting MASTER role")
	}
	assignment, readErr := data.directory.GetAccessAssignment(
		context.Background(), domain.MasterTenantID, domain.AccessPrincipalUser, user.Id,
	)
	if readErr != nil || assignment != nil {
		t.Fatalf("conflicting recovery granted access: assignment=%#v err=%v", assignment, readErr)
	}
}

func TestBootstrapFailsClosedForV2OwnedMembership(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	cfg := settings{
		tenantID: "local-tenant", tenantName: "Local Tenant", email: "admin@local.test",
		password: "initial-password-123", audience: "code-admin-api", scopes: []string{"code-admin:services:read"},
	}
	user := &domain.User{
		Id: "bootstrap-user", Email: cfg.email, Password: "stored-hash", Role: domain.RoleAdmin,
		Status: domain.UserStatusActive, CompanyId: &cfg.tenantID, AuthSource: domain.AuthSourcePassword,
	}
	if err := data.users.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	v2 := repository.NewMembershipV2Repo(client)
	created, wasCreated, err := v2.Ensure(context.Background(), cfg.tenantID, user.Id, []string{"ADMIN"})
	if err != nil || !wasCreated || created == nil {
		t.Fatalf("v2 create = %+v, %t, %v", created, wasCreated, err)
	}

	err = bootstrap(context.Background(), data, cfg)
	if !errors.Is(err, domain.ErrMembershipConflict) {
		t.Fatalf("bootstrap v2-owned pair error = %v", err)
	}
	v2Value, v2Err := v2.GetExact(context.Background(), cfg.tenantID, user.Id)
	legacyValue, legacyErr := data.memberships.Get(context.Background(), cfg.tenantID, user.Id)
	if v2Err != nil || legacyErr != nil || !reflect.DeepEqual(v2Value, created) || !reflect.DeepEqual(legacyValue, created) {
		t.Fatalf("bootstrap diverged projections: v2=%+v legacy=%+v errors=%v/%v", v2Value, legacyValue, v2Err, legacyErr)
	}
}

func TestBootstrapRejectsInvalidWorkloadSubject(t *testing.T) {
	err := validateSettings(settings{
		tenantID: "local", tenantName: "Local", email: "admin@example.com",
		password: "long-enough-password", audience: "api", scopes: []string{"read"},
		workloadSubject: "default/controller",
	})
	if err == nil {
		t.Fatal("validateSettings() error = nil")
	}
}

func TestBootstrapRejectsWeakPassword(t *testing.T) {
	err := validateSettings(settings{
		tenantID: "local", tenantName: "Local", email: "admin@example.com",
		password: "short", audience: "api", scopes: []string{"read"},
	})
	if err == nil {
		t.Fatal("validateSettings() error = nil")
	}
}

func TestBootstrapAcceptsEnabledTenantSecretScope(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	cfg := settings{
		tenantID: "local", tenantName: "Local", email: "admin@example.com",
		password: "long-enough-password", audience: "api", scopes: []string{"code-admin:secrets:read"},
	}
	if err := bootstrap(context.Background(), data, cfg); err != nil {
		t.Fatalf("bootstrap rejected enabled tenant secret scope: %v", err)
	}
	if tenant, err := data.tenants.Get(context.Background(), cfg.tenantID); err != nil || tenant == nil {
		t.Fatalf("bootstrap tenant=%#v err=%v", tenant, err)
	}
	if audience, err := data.clients.Get(context.Background(), cfg.tenantID, cfg.audience); err != nil || audience == nil || !reflect.DeepEqual(audience.DefaultScopes, cfg.scopes) {
		t.Fatalf("bootstrap audience=%#v err=%v", audience, err)
	}
}

func TestBootstrapCanonicalizesAudienceScopes(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	cfg := settings{
		tenantID: "local-tenant", tenantName: "Local Tenant", email: "admin@local.test",
		password: "initial-password-123", audience: "code-admin-api",
		scopes: []string{" code-admin:services:read ", "code-admin:clusters:read", "code-admin:services:read"},
	}
	if err := bootstrap(context.Background(), data, cfg); err != nil {
		t.Fatal(err)
	}
	want := []string{"code-admin:clusters:read", "code-admin:services:read"}
	role, err := data.roles.Get(context.Background(), cfg.tenantID, "ADMIN")
	if err != nil || role == nil || !reflect.DeepEqual(role.Permissions, want) {
		t.Fatalf("role scopes=%#v err=%v", role, err)
	}
	audience, err := data.clients.Get(context.Background(), cfg.tenantID, cfg.audience)
	if err != nil || audience == nil || !reflect.DeepEqual(audience.DefaultScopes, want) {
		t.Fatalf("audience scopes=%#v err=%v", audience, err)
	}
}

func TestReconcileManagedCodeAdminAudiencesPropagatesCurrentScopeCeiling(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		tenants: repository.NewTenantRepo(client),
		clients: repository.NewClientRepo(client),
	}
	for _, tenant := range []domain.Tenant{
		{Id: domain.MasterTenantID, Slug: domain.MasterTenantID, Name: domain.MasterTenantName, Status: domain.TenantStatusActive},
		{Id: "itrasnsform", Slug: "itrasnsform", Name: "iTransform", Status: domain.TenantStatusActive},
		{Id: "storifly", Slug: "storifly", Name: "Storifly", Status: domain.TenantStatusActive},
		{Id: "bereia", Slug: "bereia", Name: "Bereia", Status: domain.TenantStatusActive},
		{Id: "legacy-home", Slug: "legacy-home", Name: "Legacy home", Status: domain.TenantStatusActive},
		{Id: "disabled", Slug: "disabled", Name: "Disabled tenant", Status: domain.TenantStatusDisabled},
	} {
		candidate := tenant
		if err := data.tenants.Create(context.Background(), &candidate); err != nil {
			t.Fatal(err)
		}
	}
	staleScopes := []string{"console:catalog:read"}
	if _, _, err := data.clients.EnsureManagedAudience(context.Background(), "itrasnsform", &domain.Client{
		Id: domain.CodeAdminAudienceClientID, TenantId: "itrasnsform", Type: domain.ClientTypeService,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     staleScopes, Status: domain.ClientStatusActive,
		ManagedBy: domain.CodeAdminAudienceClientManager,
	}); err != nil {
		t.Fatal(err)
	}
	if err := data.clients.UpsertBootstrap(context.Background(), "storifly", &domain.Client{
		Id: domain.CodeAdminAudienceClientID, TenantId: "storifly", Type: domain.ClientTypeService,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     staleScopes, Status: domain.ClientStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	master := &domain.Client{
		Id: domain.CodeAdminAudienceClientID, TenantId: domain.MasterTenantID, Type: domain.ClientTypePublic,
		AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)},
		DefaultScopes:     staleScopes, Status: domain.ClientStatusActive,
	}
	if err := data.clients.UpsertBootstrap(context.Background(), domain.MasterTenantID, master); err != nil {
		t.Fatal(err)
	}
	legacyHome := *master
	legacyHome.TenantId = "legacy-home"
	if err := data.clients.UpsertBootstrap(context.Background(), "legacy-home", &legacyHome); err != nil {
		t.Fatal(err)
	}

	wantScopes := []string{"code-admin:environments:read", "console:catalog:read"}
	if err := reconcileManagedCodeAdminAudiences(context.Background(), data, settings{
		audience: domain.CodeAdminAudienceClientID,
		scopes:   wantScopes,
	}); err != nil {
		t.Fatal(err)
	}

	for _, tenantID := range []string{"itrasnsform", "storifly", "bereia"} {
		audience, err := data.clients.Get(context.Background(), tenantID, domain.CodeAdminAudienceClientID)
		if err != nil || !domain.IsManagedCodeAdminAudience(tenantID, audience) ||
			!reflect.DeepEqual(audience.DefaultScopes, wantScopes) {
			t.Fatalf("tenant %s audience=%#v err=%v", tenantID, audience, err)
		}
	}
	unchangedMaster, err := data.clients.Get(context.Background(), domain.MasterTenantID, domain.CodeAdminAudienceClientID)
	if err != nil || unchangedMaster == nil || unchangedMaster.Type != domain.ClientTypePublic ||
		!reflect.DeepEqual(unchangedMaster.DefaultScopes, staleScopes) {
		t.Fatalf("MASTER audience changed unexpectedly: audience=%#v err=%v", unchangedMaster, err)
	}
	unchangedLegacyHome, err := data.clients.Get(context.Background(), "legacy-home", domain.CodeAdminAudienceClientID)
	if err != nil || unchangedLegacyHome == nil || unchangedLegacyHome.Type != domain.ClientTypePublic ||
		!reflect.DeepEqual(unchangedLegacyHome.DefaultScopes, staleScopes) {
		t.Fatalf("legacy home audience changed unexpectedly: audience=%#v err=%v", unchangedLegacyHome, err)
	}
	disabled, err := data.clients.Get(context.Background(), "disabled", domain.CodeAdminAudienceClientID)
	if err != nil || disabled != nil {
		t.Fatalf("disabled tenant audience=%#v err=%v", disabled, err)
	}
}

func TestBootstrapReconcilesWorkloadAccountBFFDependencies(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	if err := data.tenants.Create(context.Background(), &domain.Tenant{
		Id: "bereia", Slug: "bereia", Name: "Bereia", Status: domain.TenantStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	brokers := []accountBrokerSettings{{
		tenantID: "bereia", audience: "bereia-api", role: "bereia-user",
		scopes: []string{"bereia-api:read", "bereia-api:write"},
	}}
	if err := bootstrapAccountBrokers(context.Background(), data, brokers); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapAccountBrokers(context.Background(), data, brokers); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	role, err := data.roles.Get(context.Background(), "bereia", "bereia-user")
	if err != nil || role == nil || !reflect.DeepEqual(role.Permissions, brokers[0].scopes) {
		t.Fatalf("role=%#v err=%v", role, err)
	}
	audience, err := data.clients.Get(context.Background(), "bereia", "bereia-api")
	if err != nil || audience == nil || audience.SecretHash != "" ||
		audience.ManagedBy != domain.WorkloadAccountBFFClientManager ||
		!reflect.DeepEqual(audience.DefaultScopes, brokers[0].scopes) {
		t.Fatalf("audience=%#v err=%v", audience, err)
	}
	retirer := data.tenants.(interface {
		Retire(context.Context, string) error
	})
	if err := retirer.Retire(context.Background(), "bereia"); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapAccountBrokers(context.Background(), data, brokers); err != nil {
		t.Fatalf("a retired legacy broker tenant must not block generic platform deploy: %v", err)
	}
	if tenant, err := data.tenants.Get(context.Background(), "bereia"); err != nil || tenant != nil {
		t.Fatal("bootstrap resurrected a retired broker tenant")
	}
}

func TestBootstrapWorkloadAccountBFFFailsClosed(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	data := stores{
		users: repository.NewRedisRepo(client), tenants: repository.NewTenantRepo(client),
		memberships: repository.NewMembershipRepo(client), roles: repository.NewRoleRepo(client),
		clients: repository.NewClientRepo(client), workloads: repository.NewWorkloadBindingRepo(client),
	}
	if err := bootstrapAccountBrokers(context.Background(), data, []accountBrokerSettings{{
		tenantID: "missing", audience: "missing-api", role: "missing-user", scopes: []string{"missing-api:read"},
	}}); err == nil {
		t.Fatal("missing tenant was accepted")
	}
}
