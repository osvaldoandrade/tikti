package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/internal/nativeauth"
	"github.com/osvaldoandrade/tikti/internal/nativepolicy"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type nativeFixture struct {
	service          *userService
	client           nativepolicy.Client
	directory        repository.IdentityDirectoryRepository
	directoryService IdentityDirectoryService
	users            repository.UserRepository
	roles            repository.RoleRepository
	redis            *redis.Client
	user             *domain.User
	idToken          string
}

func newNativeFixture(t *testing.T) nativeFixture {
	t.Helper()
	ctx := context.Background()
	server := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	c, err := (nativepolicy.Client{ID: "code-forge-desktop-native", Name: "Code Forge", TenantID: "code-forge", IdentityTenantID: "local-tenant", Audience: "code-forge-desktop", RedirectPath: "/oauth/callback", TTLSeconds: 3600,
		BaseRole:        nativepolicy.Role{Name: "code-forge-member", Scopes: []string{"code-forge-desktop:session"}},
		AdditionalRoles: []nativepolicy.Role{{Name: "code-forge-viewer", Scopes: []string{"code-forge:access", "code-forge:workspace:read", "code-forge:planner:read"}}, {Name: "code-forge-ai-operator", Scopes: []string{"code-forge:access", "code-forge:ai:use"}}},
		RequiredScopes:  []string{"code-forge-desktop:session", "code-forge:access", "code-forge:workspace:read", "code-forge:planner:read"}}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := nativepolicy.NewRegistry([]nativepolicy.Client{c})
	if err != nil {
		t.Fatal(err)
	}
	directory := repository.NewIdentityDirectoryRepository(rdb, repository.WithNativeFederationPolicy(registry))
	users := repository.NewRedisRepo(rdb)
	tenants := repository.NewTenantRepo(rdb)
	roles := repository.NewRoleRepo(rdb)
	clients := repository.NewClientRepo(rdb)
	for _, id := range []string{c.IdentityTenantID, c.TenantID} {
		if err := tenants.Create(ctx, &domain.Tenant{Id: id, Slug: id, Name: id, Status: domain.TenantStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range append([]nativepolicy.Role{c.BaseRole}, c.AdditionalRoles...) {
		if err := roles.Create(ctx, c.TenantID, &domain.Role{Name: role.Name, Scope: domain.RoleScopeTenant, TenantId: c.TenantID, Permissions: role.Scopes}); err != nil {
			t.Fatal(err)
		}
	}
	allScopes, _ := c.ScopesForRoles([]string{"code-forge-member", "code-forge-viewer", "code-forge-ai-operator"})
	if err := clients.Create(ctx, c.TenantID, &domain.Client{Id: c.Audience, TenantId: c.TenantID, Type: domain.ClientTypePublic, AllowedGrantTypes: []string{"token_exchange"}, DefaultScopes: allScopes, Status: domain.ClientStatusActive}); err != nil {
		t.Fatal(err)
	}
	home := c.IdentityTenantID
	u := &domain.User{Id: "owner-saml", Email: "owner@example.test", Role: domain.RoleAdmin, Status: domain.UserStatusActive, AuthSource: domain.AuthSourceSAML, ExternalSubject: "idp-subject", CompanyId: &home, CreatedAt: time.Now().UTC()}
	if _, err := directory.CreateDirectoryUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, _, err := directory.PutAccessAssignment(ctx, home, domain.AccessPrincipalUser, u.Id, []string{"ADMIN"}, ""); err != nil {
		t.Fatal(err)
	}
	ds := NewIdentityDirectoryService(directory, users, tenants.(repository.ExactTenantRepository), roles.(repository.ExactRoleBatchRepository), true, WithDirectoryNativeClients(registry))
	if _, _, err := ds.PutAssignment(ctx, c.TenantID, domain.AccessPrincipalUser, u.Id, []string{"code-forge-member", "code-forge-viewer"}, ""); err != nil {
		t.Fatal(err)
	}
	svc := NewUserService(users, nil, NewRoleService(roles), NewClientService(clients), strings.Repeat("session-key-", 4), "https://issuer.example", "tikti", makePEMKey(t), "native-key", WithIdentityDirectoryAccess(directory), WithNativeSAMLClients(registry),
		WithTenantTargetDiscoveryV2(true, []string{home}, tenants), WithCurrentPlatformAdministrators([]config.SAMLPlatformAdministrator{{TenantID: home, Email: u.Email}})).(*userService)
	idToken, _, err := svc.IssueIDTokenWithAMRUntil(u, []string{"saml"}, domain.PlatformPrivilegeAdmin, time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return nativeFixture{svc, c, directory, ds, users, roles, rdb, u, idToken}
}

func (f nativeFixture) grant(t *testing.T) nativeauth.Grant {
	t.Helper()
	i, err := f.service.BrowserIdentity(context.Background(), f.idToken, f.client)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := f.client.Fingerprint()
	return nativeauth.Grant{ClientID: f.client.ID, ClientFingerprint: hash, RedirectURI: "http://127.0.0.1:49152/oauth/callback", Subject: i.Subject, IdentityTenantID: i.IdentityTenantID, IdentityFingerprint: i.Fingerprint(), TokenVersion: i.TokenVersion, ApprovedScopes: i.Scopes, SessionExpiresAt: i.SessionExpiresAt, ExpiresAt: time.Now().Add(time.Minute).Unix()}
}

func TestNativeSAMLUsesExplicitAppRolesAndPreservesHomeAuthority(t *testing.T) {
	f := newNativeFixture(t)
	ctx := context.Background()
	grant := f.grant(t)
	token, err := f.service.IssueNativeToken(ctx, f.client, grant)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := f.service.ValidateAccessToken(ctx, token.AccessToken, "https://issuer.example", f.client.Audience)
	if err != nil {
		t.Fatal(err)
	}
	if claims["role"] != string(domain.RoleCompanyEmployee) || claims["tid"] != f.client.TenantID || claims["principal_tid"] != f.client.IdentityTenantID || claims[domain.PlatformPrivilegeClaim] != nil || claims[platformAuthorityOriginClaim] != nil || strings.Contains(claimStringValue(claims, "scope"), "admin") || strings.Contains(claimStringValue(claims, "scope"), "ai:use") || token.ExpiresIn > 600 {
		t.Fatal("native token inherited platform or unassigned authority")
	}
	home, err := f.directory.GetAccessAssignment(ctx, f.client.IdentityTenantID, domain.AccessPrincipalUser, f.user.Id)
	if err != nil || !slices.Equal(home.Roles, []string{"ADMIN"}) {
		t.Fatal("home grants changed")
	}
	if _, err := f.service.ValidateIDToken(ctx, f.idToken, "https://issuer.example", "tikti"); err != nil {
		t.Fatal("Console SAML session changed")
	}
	// Adding a role after consent cannot enlarge the approved native token.
	if _, _, err := f.directoryService.PutAssignment(ctx, f.client.TenantID, domain.AccessPrincipalUser, f.user.Id, []string{"code-forge-member", "code-forge-viewer", "code-forge-ai-operator"}, `"1"`); err != nil {
		t.Fatal(err)
	}
	second, err := f.service.IssueNativeToken(ctx, f.client, grant)
	if err != nil || strings.Contains(second.Scope, "ai:use") {
		t.Fatal("grant gained permissions after consent")
	}
	secondClaims, err := f.service.ValidateAccessToken(ctx, second.AccessToken, "https://issuer.example", f.client.Audience)
	if err != nil {
		t.Fatal(err)
	}
	signedRoles, valid := canonicalAccessTokenRoles(secondClaims["roles"])
	if !valid || slices.Contains(signedRoles, "code-forge-ai-operator") {
		t.Fatal("role added after consent exceeded the approved ceiling")
	}
}

func TestNativeSAMLRevokesCodesAndTokensWithCurrentAuthority(t *testing.T) {
	for _, change := range []string{"assignment", "role-definition", "source-tenant", "target-tenant", "client-policy", "token-version", "native-client-disabled"} {
		t.Run(change, func(t *testing.T) {
			f := newNativeFixture(t)
			ctx := context.Background()
			grant := f.grant(t)
			token, err := f.service.IssueNativeToken(ctx, f.client, grant)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "assignment":
				_, err = f.directory.DeleteAccessAssignment(ctx, f.client.TenantID, domain.AccessPrincipalUser, f.user.Id, `"1"`)
			case "role-definition":
				err = f.roles.Create(ctx, f.client.TenantID, &domain.Role{Name: "code-forge-viewer", Scope: domain.RoleScopeTenant, TenantId: f.client.TenantID, Permissions: []string{"code-forge:access", "code-forge:workspace:read", "code-forge:planner:read", "code-forge:ai:use"}})
			case "source-tenant", "target-tenant":
				id := f.client.TenantID
				if change == "source-tenant" {
					id = f.client.IdentityTenantID
				}
				err = f.service.tenantRepo.Create(ctx, &domain.Tenant{Id: id, Slug: id, Name: id, Status: domain.TenantStatusDisabled})
			case "client-policy":
				changed := f.client
				changed.TTLSeconds = 300
				f.service.nativeClients, err = nativepolicy.NewRegistry([]nativepolicy.Client{changed})
			case "token-version":
				err = f.service.RevokeIDTokenSubject(ctx, f.user.Id)
			case "native-client-disabled":
				f.service.nativeClients = nil
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.IssueNativeToken(ctx, f.client, grant); err == nil {
				t.Fatal("stale grant retained authority")
			}
			if _, err := f.service.ValidateAccessToken(ctx, token.AccessToken, "https://issuer.example", f.client.Audience); err == nil {
				t.Fatal("issued token retained removed authority")
			}
		})
	}
}

func TestNativeSAMLRejectsForeignRoleEscalationAndCorruptDefinitions(t *testing.T) {
	f := newNativeFixture(t)
	ctx := context.Background()
	for _, roles := range [][]string{{"ADMIN"}, {"code-forge-member", "ADMIN"}, {"unregistered-role"}} {
		if _, _, err := f.directory.PutAccessAssignment(ctx, f.client.TenantID, domain.AccessPrincipalUser, f.user.Id, roles, `"1"`); !errors.Is(err, domain.ErrInvalidTenant) {
			t.Fatal("foreign SAML escalation accepted")
		}
	}
	if err := f.roles.Create(ctx, f.client.TenantID, &domain.Role{Name: "code-forge-viewer", Scope: domain.RoleScopeTenant, TenantId: f.client.TenantID, Permissions: []string{"code-admin:tenants:admin"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.directoryService.PutAssignment(ctx, f.client.TenantID, domain.AccessPrincipalUser, f.user.Id, []string{"code-forge-member", "code-forge-viewer"}, `"1"`); err == nil {
		t.Fatal("foreign role definition mismatch accepted")
	}
	if _, err := f.service.BrowserIdentity(ctx, f.idToken, f.client); err == nil {
		t.Fatal("corrupt role authorized browser")
	}
	defaultDirectory := repository.NewIdentityDirectoryRepository(f.redis)
	if roles, _, err := defaultDirectory.GetEffectiveTenantRoles(ctx, f.user.Id, f.client.TenantID); err != nil || len(roles) != 0 {
		t.Fatal("default-off trust leaked foreign roles")
	}
	ids, _, err := defaultDirectory.ListEffectiveTenantIDs(ctx, f.user.Id, 50)
	if err != nil || slices.Contains(ids, f.client.TenantID) {
		t.Fatal("default-off discovery leaked foreign target")
	}
}

func TestNativeSAMLRejectsSignedPrivilegeAndPolicyConfusion(t *testing.T) {
	f := newNativeFixture(t)
	ctx := context.Background()
	grant := f.grant(t)
	token, err := f.service.IssueNativeToken(ctx, f.client, grant)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := f.service.ValidateAccessToken(ctx, token.AccessToken, "https://issuer.example", f.client.Audience)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := f.service.getRSAPrivateKey()
	for _, change := range []func(jwt.MapClaims){func(c jwt.MapClaims) { c["roles"] = []string{"ADMIN", "code-forge-member"} }, func(c jwt.MapClaims) { c["role"] = "ADMIN" }, func(c jwt.MapClaims) { c[domain.PlatformPrivilegeClaim] = domain.PlatformPrivilegeAdmin }, func(c jwt.MapClaims) { delete(c, "native_policy") }, func(c jwt.MapClaims) { delete(c, "native_client_id") }, func(c jwt.MapClaims) { c["amr"] = []string{"pwd"} }, func(c jwt.MapClaims) { c["scope"] = claimStringValue(c, "scope") + " code-forge:ai:use" }} {
		copy := jwt.MapClaims{}
		for k, v := range claims {
			copy[k] = v
		}
		change(copy)
		forged := jwt.NewWithClaims(jwt.SigningMethodRS256, copy)
		forged.Header["kid"] = "native-key"
		signed, err := forged.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.service.ValidateAccessToken(ctx, signed, "https://issuer.example", f.client.Audience); err == nil {
			t.Fatal("confused native authority accepted")
		}
	}
}

func TestNativeSAMLCompleteBrowserConsentPKCEAndCurrentRS256Authority(t *testing.T) {
	f := newNativeFixture(t)
	ctx := context.Background()
	h, err := nativeauth.NewHandler(nativeauth.HTTPOptions{Issuer: "https://issuer.example", CookieName: "tikti_idt", CSRFKey: []byte(strings.Repeat("k", 32)), Clients: f.service.nativeClients, Store: nativeauth.NewStore(f.redis, nil), Authority: f.service,
		Audit: nativeauth.RedisAuditor{Client: f.redis}, Limiter: f.directory, ResolveIP: func(*http.Request) string { return "127.0.0.1" }, RateRequests: 100, RateWindow: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, form url.Values, cookie bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://issuer.example"+nativeauth.PublicPrefix+path, strings.NewReader(form.Encode()))
		if form != nil {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "https://issuer.example")
		}
		if cookie {
			r.AddCookie(&http.Cookie{Name: "tikti_idt", Value: f.idToken})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge, _ := nativepolicy.S256Challenge(verifier)
	values := url.Values{"client_id": {f.client.ID}, "response_type": {"code"}, "redirect_uri": {"http://127.0.0.1:49152/oauth/callback"}, "state": {strings.Repeat("s", 43)}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	page := call("GET", "authorize?"+values.Encode(), nil, true)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Consultar arquivos e iniciativas") {
		t.Fatalf("consent=%d %s", page.Code, page.Body.String())
	}
	form := url.Values{"decision": {"approve"}}
	for _, field := range []string{"request", "csrf"} {
		match := regexp.MustCompile(`name="` + field + `" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
		if len(match) != 2 {
			t.Fatal("missing consent field")
		}
		form.Set(field, match[1])
	}
	approved := call("POST", "consent", form, true)
	if approved.Code != 303 {
		t.Fatalf("consent=%d %s", approved.Code, approved.Body.String())
	}
	callback, _ := url.Parse(approved.Header().Get("Location"))
	code := callback.Query().Get("code")
	redemption := httptest.NewRequest("POST", "https://issuer.example"+nativeauth.PublicPrefix+"token", strings.NewReader((url.Values{"grant_type": {"authorization_code"}, "client_id": {f.client.ID}, "code": {code}, "redirect_uri": {values.Get("redirect_uri")}, "code_verifier": {verifier}}).Encode()))
	redemption.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, redemption)
	var token nativeauth.Token
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &token) != nil {
		t.Fatalf("token=%d %s", response.Code, response.Body.String())
	}
	if _, err := f.service.ValidateAccessToken(ctx, token.AccessToken, "https://issuer.example", f.client.Audience); err != nil {
		t.Fatal(err)
	}
	auditKeys, err := f.redis.Keys(ctx, "identity:v2:native:audit:*").Result()
	if err != nil || len(auditKeys) != 4 {
		t.Fatal("approval and token audit intent/outcome missing")
	}
	for _, key := range auditKeys {
		raw := f.redis.Get(ctx, key).Val()
		if strings.Contains(raw, code) || strings.Contains(raw, verifier) || strings.Contains(raw, token.AccessToken) || strings.Contains(raw, f.user.Email) {
			t.Fatal("audit leaked credentials or email")
		}
	}
}

func TestNativeSAMLGroupCannotBypassForeignTrustOrGrantPlatformAdmin(t *testing.T) {
	f := newNativeFixture(t)
	ctx := context.Background()
	group, err := f.directory.CreateGroup(ctx, "Mixed roles", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.directory.PutGroupMember(ctx, group.ID, f.user.Id, `"1"`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.directory.PutAccessAssignment(ctx, f.client.TenantID, domain.AccessPrincipalGroup, group.ID, []string{"ADMIN", "code-forge-ai-operator"}, ""); err != nil {
		t.Fatal(err)
	}
	roles, _, err := f.directory.GetEffectiveTenantRoles(ctx, f.user.Id, f.client.TenantID)
	if err != nil || slices.Contains(roles, "ADMIN") || !slices.Contains(roles, "code-forge-ai-operator") {
		t.Fatal("group bypassed registered role boundary")
	}
	defaultDirectory := repository.NewIdentityDirectoryRepository(f.redis)
	if roles, _, err := defaultDirectory.GetEffectiveTenantRoles(ctx, f.user.Id, f.client.TenantID); err != nil || len(roles) != 0 {
		t.Fatal("group bypassed default-off foreign trust")
	}
	if _, _, err := f.directory.PutAccessAssignment(ctx, f.client.TenantID, domain.AccessPrincipalUser, f.user.Id, []string{"code-forge-member"}, `"1"`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.BrowserIdentity(ctx, f.idToken, f.client); err == nil {
		t.Fatal("AI group role substituted for required viewer grant")
	}
}
