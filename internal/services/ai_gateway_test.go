package services

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestAIGatewayAudienceIsReservedWhenDisabled(t *testing.T) {
	for _, audience := range []string{"code-llm-service", " code-llm-service", "CODE-LLM-SERVICE"} {
		t.Run(audience, func(t *testing.T) {
			s, request := trinoUserFixture(t, nil)
			request.Audience = audience
			request.Scopes = nil
			if result, err := s.TokenExchange(context.Background(), request); err == nil || result != nil {
				t.Fatal("disabled AI audience entered the legacy exchange")
			}
		})
	}
}

type aiUserRepo struct {
	*mockUserRepo
	user *domain.User
}

func (r *aiUserRepo) FindByID(context.Context, string) (*domain.User, error) { return r.user, nil }
func (r *aiUserRepo) IncrementTokenVersionByID(context.Context, string) (int, *domain.User, error) {
	r.user.TokenVersion++
	return r.user.TokenVersion, r.user, nil
}

type aiAuthorityStub struct {
	key      *rsa.PrivateKey
	epoch    string
	requests []aigateway.Identity
	mutate   func(*aigateway.Principal)
	err      error
}

func (a *aiAuthorityStub) Authorize(_ context.Context, raw string) (aigateway.Principal, error) {
	if a.err != nil {
		return aigateway.Principal{}, a.err
	}
	token, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return &a.key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(aigateway.AuthorityAudience), jwt.WithIssuer("https://issuer"), jwt.WithExpirationRequired())
	if err != nil {
		return aigateway.Principal{}, err
	}
	c := token.Claims.(jwt.MapClaims)
	if c["sub"] != "tikti" {
		return aigateway.Principal{}, errors.New("wrong assertion subject")
	}
	b, _ := json.Marshal(c["ai_identity"])
	var identity aigateway.Identity
	if err := aigateway.Decode(b, &identity); err != nil {
		return aigateway.Principal{}, err
	}
	a.requests = append(a.requests, identity)
	p := aigateway.Principal{SchemaVersion: aigateway.IdentityVersion, TenantID: identity.TenantID, TenantUID: identity.TenantID, TenantEpoch: a.epoch, Subject: identity.Subject, PrincipalKind: identity.Kind}
	if w := identity.Workload; w != nil {
		p.Workload = &aigateway.Workload{Issuer: w.Issuer, ServiceUID: "service-1", ClusterRef: w.ClusterRef, Namespace: w.Namespace, ServiceAccount: w.ServiceAccount, ServiceAccountUID: w.ServiceAccountUID, PodUID: w.PodUID}
		if identity.Kind == "Workload" {
			p.Subject = "codefoundry:service:service-1"
		}
	}
	if a.mutate != nil {
		a.mutate(&p)
	}
	return p, nil
}

func aiUserFixture(t *testing.T) (*userService, domain.TokenExchangeReq, *aiAuthorityStub, *domain.User, *domain.Tenant) {
	t.Helper()
	u := &domain.User{Id: "user-1", Email: "user@example.test", Status: domain.UserStatusActive, TokenVersion: 3, Role: domain.RoleCompanyEmployee}
	users := &aiUserRepo{mockUserRepo: &mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return u, nil }}, user: u}
	tenant := &domain.Tenant{Id: "tenant-1", Status: domain.TenantStatusActive, CreatedAt: time.Now().Add(-time.Hour).UTC()}
	members := &mockMembershipRepo{listExactFn: func(context.Context, string) ([]string, error) { return []string{tenant.Id}, nil }, getExactFn: func(context.Context, string, string) (*domain.Membership, error) {
		return &domain.Membership{TenantId: tenant.Id, UserId: u.Id, Roles: []string{"ai-user"}}, nil
	}}
	roles := &mockRoleService{getByNameFn: func(context.Context, string, string) (*domain.RoleResp, error) {
		return &domain.RoleResp{Name: "ai-user", Permissions: []string{aigateway.InvokeScope, aigateway.ModelsScope}}, nil
	}}
	clients := &mockClientService{getClientFn: func(context.Context, string, string) (*domain.Client, error) {
		return &domain.Client{Id: aigateway.Audience, Type: domain.ClientTypeService, ManagedBy: domain.AIGatewayAudienceClientManager, TenantId: tenant.Id, Status: domain.ClientStatusActive, AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)}, DefaultScopes: []string{aigateway.InvokeScope, aigateway.ModelsScope, aigateway.UsageScope}}, nil
	}}
	key, pem := workloadTestKey(t)
	a := &aiAuthorityStub{key: key}
	cfg := config.AIGatewayConfig{Enabled: true, AccessTokenTTLSeconds: 300, MaximumConcurrent: 8, PerIdentityPerMinute: 60}
	s := NewUserService(users, members, roles, clients, "fixture-id-signing", "https://issuer", "tikti", pem, "kid", WithTenantScopedTokenClaimsV1(false, nil, &fakeTenantRepo{getFn: func(context.Context, string) (*domain.Tenant, error) { return tenant, nil }}), WithAIGateway(cfg, a, &topicTenantReader{tenant: tenant})).(*userService)
	a.epoch, _ = s.aiGateway.tenant(context.Background(), tenant.Id, time.Now())
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": u.Id, "email": u.Email, "ver": u.TokenVersion, "iss": "https://issuer", "aud": "tikti", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	raw, err := tok.SignedString([]byte("fixture-id-signing"))
	if err != nil {
		t.Fatal(err)
	}
	return s, domain.TokenExchangeReq{IdToken: raw, Audience: aigateway.Audience, TenantID: tenant.Id, Scopes: []string{aigateway.InvokeScope, aigateway.ModelsScope}}, a, u, tenant
}

func TestAIUserCurrentAuthorityAndClosedClaims(t *testing.T) {
	s, r, a, user, tenant := aiUserFixture(t)
	response, err := s.TokenExchange(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.ValidateAIAccessToken(context.Background(), response.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if response.ExpiresIn != 300 || claims.Subject != user.Id || claims.TenantUID != tenant.Id || claims.PrincipalKind != "User" || claims.Version == nil || *claims.Version != 3 || len(a.requests) != 2 {
		t.Fatal("wrong current principal")
	}
	for _, test := range []struct {
		name   string
		mutate func()
	}{
		{"version", func() { user.TokenVersion++ }},
		{"disabled-user", func() { user.Status = domain.UserStatusSuspended }},
		{"retired-tenant", func() { now := time.Now(); tenant.RetiredAt = &now }},
		{"scope-revoked", func() {
			s.roleSvc = &mockRoleService{getByNameFn: func(context.Context, string, string) (*domain.RoleResp, error) {
				return &domain.RoleResp{Name: "ai-user", Permissions: []string{aigateway.ModelsScope}}, nil
			}}
		}},
		{"authority-mismatch", func() { a.mutate = func(p *aigateway.Principal) { p.TenantEpoch = strings.Repeat("f", 64) } }},
	} {
		t.Run(test.name, func(t *testing.T) {
			oldU, oldT, oldRoles, oldMutate := *user, *tenant, s.roleSvc, a.mutate
			defer func() { *user = oldU; *tenant = oldT; s.roleSvc = oldRoles; a.mutate = oldMutate }()
			test.mutate()
			if _, err := s.ValidateAIAccessToken(context.Background(), response.AccessToken); err == nil {
				t.Fatal("stale authority accepted")
			}
		})
	}
}

func TestAIWorkloadDelegationAndMachinePins(t *testing.T) {
	users, request, a, _, tenant := aiUserFixture(t)
	userToken, err := users.TokenExchange(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	verifier := validWorkloadVerifier()
	verifier.subject.Issuer = "https://cluster.example"
	verifier.subject.ClusterRef = "cluster-1"
	verifier.subject.ServiceAccountUID = "sa-1"
	verifier.subject.PodUID = "pod-1"
	verifier.subject.ExpiresAt = time.Now().Add(90 * time.Second)
	cfg := users.aiGateway.cfg
	cfg.InstallationUID = "install-1"
	cfg.RuntimeTenantID = tenant.Id
	cfg.Runtime = config.AIMachineIdentity{Enabled: true, Issuer: verifier.subject.Issuer, ClusterRef: verifier.subject.ClusterRef, Namespace: verifier.subject.Namespace, ServiceAccount: verifier.subject.ServiceAccount, ServiceAccountUID: verifier.subject.ServiceAccountUID}
	s := NewWorkloadIdentityService(nil, verifier, "https://issuer", users.jwksPrivateKey, "kid", time.Hour, WithWorkloadAIGateway(cfg, a, &topicTenantReader{tenant: tenant}, users)).(*workloadIdentityService)
	r := domain.WorkloadTokenExchangeReq{SubjectToken: "projected", SubjectTokenType: domain.WorkloadSubjectTokenType, Audience: aigateway.Audience, TenantID: tenant.Id, Scopes: []string{aigateway.InvokeScope}}
	for _, delegated := range []bool{false, true} {
		r.UserToken = ""
		if delegated {
			r.UserToken = userToken.AccessToken
		}
		response, err := s.Exchange(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := users.ValidateAIAccessToken(context.Background(), response.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		if response.ExpiresIn > 90 || response.ExpiresIn < 85 || delegated != (claims.Actor != nil) || (!delegated) != (claims.Workload != nil) {
			t.Fatal("delegation/expiry shape incorrect")
		}
		if delegated {
			r.UserToken = response.AccessToken
			if _, err := s.Exchange(context.Background(), r); err == nil {
				t.Fatal("nested delegation accepted")
			}
		}
	}
	r.UserToken = ""
	r.AIGrant = "Runtime"
	r.Audience = aigateway.RuntimeAudience
	r.Scopes = []string{aigateway.RuntimeScope}
	if response, err := s.Exchange(context.Background(), r); err != nil || response.ExpiresIn > 60 {
		t.Fatalf("runtime grant refused: %v", err)
	}
	verifier.subject.ServiceAccountUID = "replacement"
	if _, err := s.Exchange(context.Background(), r); err == nil {
		t.Fatal("replacement installation identity accepted")
	}
	verifier.subject.ServiceAccountUID = cfg.Runtime.ServiceAccountUID
	r.LogsGrant = "CefasRuntime"
	if _, err := s.Exchange(context.Background(), r); err == nil {
		t.Fatal("mixed Logs grant accepted")
	}
}

func TestAIUserCeilingNeverBroadensCurrentPermissions(t *testing.T) {
	s, r, _, _, _ := aiUserFixture(t)
	r.Scopes = nil
	r.ScopeCeilingV1 = []string{aigateway.InvokeScope, aigateway.ModelsScope, aigateway.UsageScope}
	s.roleSvc = &mockRoleService{getByNameFn: func(context.Context, string, string) (*domain.RoleResp, error) {
		return &domain.RoleResp{Name: "ai-user", Permissions: []string{aigateway.ModelsScope}}, nil
	}}
	response, err := s.TokenExchange(context.Background(), r)
	if err != nil || len(response.Scopes) != 1 || response.Scopes[0] != aigateway.ModelsScope {
		t.Fatalf("ceiling broadened authority: %v", err)
	}
	r.Scopes = []string{aigateway.InvokeScope}
	if _, err := s.TokenExchange(context.Background(), r); err == nil {
		t.Fatal("ambiguous explicit scopes and ceiling accepted")
	}
	r.ScopeCeilingV1 = nil
	if _, err := s.TokenExchange(context.Background(), r); err == nil {
		t.Fatal("unassigned invoke accepted")
	}
}

func TestAIUsageScopeRequiresCurrentManagementPermission(t *testing.T) {
	s, r, _, _, _ := aiUserFixture(t)
	r.Scopes = []string{aigateway.UsageScope}
	if _, err := s.TokenExchange(context.Background(), r); err == nil {
		t.Fatal("ordinary inference permission granted aggregate usage")
	}
	permissions := []string{"code-admin:ai:read"}
	s.roleSvc = &mockRoleService{getByNameFn: func(context.Context, string, string) (*domain.RoleResp, error) {
		return &domain.RoleResp{Name: "ai-user", Permissions: permissions}, nil
	}}
	response, err := s.TokenExchange(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateAIAccessToken(context.Background(), response.AccessToken); err != nil {
		t.Fatal(err)
	}
	permissions = []string{aigateway.UsageScope}
	if _, err := s.ValidateAIAccessToken(context.Background(), response.AccessToken); err == nil {
		t.Fatal("usage token survived removal of current management permission")
	}
}

func TestAIStoreMachineGrantsCannotSelectLogsOrBroadenScopes(t *testing.T) {
	users, _, a, _, tenant := aiUserFixture(t)
	v := validWorkloadVerifier()
	v.subject.Issuer, v.subject.ClusterRef, v.subject.ServiceAccountUID, v.subject.PodUID = "https://cluster.example", "cluster-1", "ai-runtime-sa", "pod-1"
	v.subject.ExpiresAt = time.Now().Add(time.Minute)
	cfg := users.aiGateway.cfg
	cfg.InstallationUID, cfg.RuntimeTenantID, cfg.StoreAudience = "install-1", tenant.Id, "ai-dedicated-store"
	cfg.StoreRuntime = config.AIMachineIdentity{Enabled: true, Issuer: v.subject.Issuer, ClusterRef: v.subject.ClusterRef, Namespace: v.subject.Namespace, ServiceAccount: v.subject.ServiceAccount, ServiceAccountUID: v.subject.ServiceAccountUID}
	cfg.StoreBootstrap = cfg.StoreRuntime
	cfg.StoreBootstrap.ServiceAccountUID = "ai-bootstrap-sa"
	s := NewWorkloadIdentityService(nil, v, "https://issuer", users.jwksPrivateKey, "kid", time.Hour, WithWorkloadAIGateway(cfg, a, &topicTenantReader{tenant: tenant}, users)).(*workloadIdentityService)
	r := domain.WorkloadTokenExchangeReq{SubjectToken: "projected", SubjectTokenType: domain.WorkloadSubjectTokenType, TenantID: tenant.Id, Audience: cfg.StoreAudience, AIGrant: "CefasRuntime", Scopes: []string{"cefas:item:read:ai-usage", "cefas:item:write:ai-usage", "cefas:query:ai-usage"}}
	response, err := s.Exchange(context.Background(), r)
	if err != nil || !slices.Equal(response.Scopes, r.Scopes) {
		t.Fatalf("exact table-scoped runtime grant refused: %v", err)
	}
	for _, scope := range []string{"cefas:item:delete:ai-usage", "cefas:table:create", "cefas:item:read:logs", "cefas:query:*"} {
		broader := r
		broader.Scopes = append(slices.Clone(r.Scopes), scope)
		if _, err := s.Exchange(context.Background(), broader); err == nil {
			t.Fatal("broader runtime store grant accepted")
		}
	}
	r.Audience = "code-admin-logs-store"
	if _, err := s.Exchange(context.Background(), r); err == nil {
		t.Fatal("AI machine selected Logs store")
	}
	r.Audience, r.AIGrant, r.Scopes = cfg.StoreAudience, "CefasBootstrap", []string{"cefas:table:create", "cefas:table:describe"}
	if _, err := s.Exchange(context.Background(), r); err == nil {
		t.Fatal("runtime identity acquired bootstrap authority")
	}
	v.subject.ServiceAccountUID = cfg.StoreBootstrap.ServiceAccountUID
	if _, err := s.Exchange(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}
