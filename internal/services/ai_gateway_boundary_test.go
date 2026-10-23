package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func TestAIUserAuthorityPinsAreIndependent(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*aigateway.Principal)
	}{
		{"schema", func(p *aigateway.Principal) { p.SchemaVersion = "other/v1" }},
		{"tenant id", func(p *aigateway.Principal) { p.TenantID = "foreign" }},
		{"tenant uid", func(p *aigateway.Principal) { p.TenantUID = "foreign" }},
		{"tenant epoch", func(p *aigateway.Principal) { p.TenantEpoch = strings.Repeat("f", 64) }},
		{"principal class", func(p *aigateway.Principal) { p.PrincipalKind = "Workload" }},
		{"empty subject", func(p *aigateway.Principal) { p.Subject = "" }},
		{"foreign subject", func(p *aigateway.Principal) { p.Subject = "other-user" }},
		{"unexpected workload", func(p *aigateway.Principal) { p.Workload = &aigateway.Workload{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, a, _, _ := aiUserFixture(t)
			if _, err := s.TokenExchange(t.Context(), r); err != nil {
				t.Fatalf("valid control failed: %v", err)
			}
			a.mutate = tc.edit
			if got, err := s.TokenExchange(t.Context(), r); !errors.Is(err, domain.ErrUnauthorizedScope) || got != nil {
				t.Fatalf("authority pin did not independently refuse issuance: %v", err)
			}
		})
	}
}

func TestAIUserAuthorityFailureAndWithdrawal(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{"denied", aigateway.ErrDenied, domain.ErrUnauthorizedScope},
		{"unavailable", aigateway.ErrUnavailable, domain.ErrAuthenticationUnavailable},
		{"cancelled", context.Canceled, domain.ErrAuthenticationUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, a, _, _ := aiUserFixture(t)
			a.err = tc.err
			if got, err := s.TokenExchange(t.Context(), r); !errors.Is(err, tc.want) || got != nil {
				t.Fatalf("authority failure issued identity: %v", err)
			}
		})
	}
	t.Run("withdrawn during callback", func(t *testing.T) {
		s, r, a, _, tenant := aiUserFixture(t)
		a.mutate = func(*aigateway.Principal) { now := time.Now(); tenant.RetiredAt = &now }
		if got, err := s.TokenExchange(t.Context(), r); !errors.Is(err, domain.ErrInvalidTenant) || got != nil {
			t.Fatalf("withdrawal lost to earlier callback: %v", err)
		}
	})
}

func TestAIUserExchangeRejectsMixedContracts(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*domain.TokenExchangeReq)
	}{
		{"no scopes", func(r *domain.TokenExchangeReq) { r.Scopes = nil }},
		{"duplicate scopes", func(r *domain.TokenExchangeReq) { r.Scopes = []string{aigateway.InvokeScope, aigateway.InvokeScope} }},
		{"event discovery", func(r *domain.TokenExchangeReq) { r.EventTypes = []string{"event"} }},
		{"tenant discovery v1", func(r *domain.TokenExchangeReq) { r.DiscoverTenantTargetsV1 = true }},
		{"tenant discovery v2", func(r *domain.TokenExchangeReq) { r.DiscoverTenantTargetsV2 = true }},
		{"negative ttl", func(r *domain.TokenExchangeReq) { r.TTLSeconds = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, _, _, _ := aiUserFixture(t)
			tc.edit(&r)
			if got, err := s.TokenExchange(t.Context(), r); err == nil || got != nil {
				t.Fatal("mixed exchange contract issued token")
			}
		})
	}
	t.Run("caller ttl bound", func(t *testing.T) {
		s, r, _, _, _ := aiUserFixture(t)
		r.TTLSeconds = 1
		got, err := s.TokenExchange(t.Context(), r)
		if err != nil || got.ExpiresIn != 1 {
			t.Fatalf("caller lifetime was broadened: %v", err)
		}
	})
}

func signedAIClaims(t *testing.T, a *aiAuthorityStub, c aigateway.Claims, kid string) string {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m jwt.MapClaims
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, m)
	token.Header["kid"] = kid
	raw, err := token.SignedString(a.key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAICurrentUserTokenClaimsAreClosed(t *testing.T) {
	s, r, a, user, _ := aiUserFixture(t)
	issued, err := s.TokenExchange(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := s.ValidateAIAccessToken(t.Context(), issued.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*aigateway.Claims)
	}{
		{"wrong issuer", func(c *aigateway.Claims) { c.Issuer = "https://foreign.example" }},
		{"wrong audience", func(c *aigateway.Claims) { c.Audience = "other" }},
		{"missing issued time", func(c *aigateway.Claims) { c.IssuedAt = 0 }},
		{"future issued time", func(c *aigateway.Claims) { c.IssuedAt = time.Now().Add(time.Minute).Unix() }},
		{"expired", func(c *aigateway.Claims) { c.ExpiresAt = time.Now().Add(-time.Second).Unix() }},
		{"overlong lifetime", func(c *aigateway.Claims) { c.ExpiresAt = c.IssuedAt + 301 }},
		{"missing token id", func(c *aigateway.Claims) { c.ID = "" }},
		{"unsorted scope", func(c *aigateway.Claims) { c.Scope = aigateway.ModelsScope + " " + aigateway.InvokeScope }},
		{"duplicate scope", func(c *aigateway.Claims) { c.Scope = aigateway.InvokeScope + " " + aigateway.InvokeScope }},
		{"unknown kind", func(c *aigateway.Claims) { c.PrincipalKind = "Administrator" }},
		{"missing version", func(c *aigateway.Claims) { c.Version = nil }},
		{"negative version", func(c *aigateway.Claims) { v := -1; c.Version = &v }},
		{"foreign subject", func(c *aigateway.Claims) { c.Subject = "other-user" }},
		{"foreign tenant uid", func(c *aigateway.Claims) { c.TenantUID = "other-tenant" }},
		{"foreign epoch", func(c *aigateway.Claims) { c.TenantEpoch = strings.Repeat("f", 64) }},
		{"unexpected workload", func(c *aigateway.Claims) { c.Workload = &aigateway.Workload{} }},
		{"unexpected actor", func(c *aigateway.Claims) { c.Actor = &aigateway.Actor{} }},
		{"delegated without actor", func(c *aigateway.Claims) { c.PrincipalKind = "Delegated" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := baseline
			tc.edit(&c)
			if _, err := s.ValidateAIAccessToken(t.Context(), signedAIClaims(t, a, c, "kid")); err == nil {
				t.Fatal("invalid signed token retained current authority")
			}
		})
	}
	for _, raw := range []string{"", "one.two", "one.%.three", "one.e30.three", strings.Repeat("a", 16385), "with whitespace", signedAIClaims(t, a, baseline, "other-kid")} {
		if _, err := s.ValidateAIAccessToken(t.Context(), raw); err == nil {
			t.Fatal("invalid token encoding accepted")
		}
	}
	user.PasswordChangeRequired = true
	if _, err := s.ValidateAIAccessToken(t.Context(), issued.AccessToken); err == nil {
		t.Fatal("password reset did not revoke AI token")
	}
}

func aiWorkloadFixture(t *testing.T) (*workloadIdentityService, domain.WorkloadTokenExchangeReq, *fakeWorkloadVerifier, *aiAuthorityStub, *domain.Tenant) {
	t.Helper()
	u, _, a, _, tenant := aiUserFixture(t)
	v := validWorkloadVerifier()
	v.subject.Issuer, v.subject.ClusterRef, v.subject.ServiceAccountUID, v.subject.PodUID = "https://cluster.example", "cluster-1", "sa-1", "pod-1"
	v.subject.ExpiresAt = time.Now().Add(90 * time.Second)
	cfg := u.aiGateway.cfg
	cfg.InstallationUID, cfg.RuntimeTenantID = "installation-1", tenant.Id
	cfg.Runtime = config.AIMachineIdentity{Enabled: true, Issuer: v.subject.Issuer, ClusterRef: v.subject.ClusterRef, Namespace: v.subject.Namespace, ServiceAccount: v.subject.ServiceAccount, ServiceAccountUID: v.subject.ServiceAccountUID}
	s := NewWorkloadIdentityService(nil, v, "https://issuer", u.jwksPrivateKey, "kid", time.Hour, WithWorkloadAIGateway(cfg, a, &topicTenantReader{tenant: tenant}, u)).(*workloadIdentityService)
	r := domain.WorkloadTokenExchangeReq{SubjectToken: "projected", SubjectTokenType: domain.WorkloadSubjectTokenType, Audience: aigateway.Audience, TenantID: tenant.Id, Scopes: []string{aigateway.InvokeScope}}
	return s, r, v, a, tenant
}

func TestAIWorkloadAuthorityPinsAreIndependent(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*aigateway.Principal)
	}{
		{"missing workload", func(p *aigateway.Principal) { p.Workload = nil }},
		{"invalid service uid", func(p *aigateway.Principal) { p.Workload.ServiceUID = "" }},
		{"issuer", func(p *aigateway.Principal) { p.Workload.Issuer = "https://foreign.example" }},
		{"cluster", func(p *aigateway.Principal) { p.Workload.ClusterRef = "foreign" }},
		{"namespace", func(p *aigateway.Principal) { p.Workload.Namespace = "foreign" }},
		{"service account", func(p *aigateway.Principal) { p.Workload.ServiceAccount = "foreign" }},
		{"service account uid", func(p *aigateway.Principal) { p.Workload.ServiceAccountUID = "replacement" }},
		{"pod uid", func(p *aigateway.Principal) { p.Workload.PodUID = "replacement" }},
		{"subject", func(p *aigateway.Principal) { p.Subject = "codefoundry:service:foreign" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, _, a, _ := aiWorkloadFixture(t)
			if _, err := s.Exchange(t.Context(), r); err != nil {
				t.Fatalf("valid control: %v", err)
			}
			a.mutate = tc.edit
			if got, err := s.Exchange(t.Context(), r); !errors.Is(err, domain.ErrUnauthorizedScope) || got != nil {
				t.Fatalf("authority pin admitted: %v", err)
			}
		})
	}
}

func TestAIMachineInstallationPinsAreIndependent(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config.AIGatewayConfig)
	}{
		{"disabled grant", func(c *config.AIGatewayConfig) { c.Runtime.Enabled = false }},
		{"issuer", func(c *config.AIGatewayConfig) { c.Runtime.Issuer = "https://other.example" }},
		{"cluster", func(c *config.AIGatewayConfig) { c.Runtime.ClusterRef = "other" }},
		{"namespace", func(c *config.AIGatewayConfig) { c.Runtime.Namespace = "other" }},
		{"service account", func(c *config.AIGatewayConfig) { c.Runtime.ServiceAccount = "other" }},
		{"service account uid", func(c *config.AIGatewayConfig) { c.Runtime.ServiceAccountUID = "other" }},
		{"installation uid", func(c *config.AIGatewayConfig) { c.InstallationUID = "" }},
		{"tenant", func(c *config.AIGatewayConfig) { c.RuntimeTenantID = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, _, _, _ := aiWorkloadFixture(t)
			r.AIGrant, r.Audience, r.Scopes = "Runtime", aigateway.RuntimeAudience, []string{aigateway.RuntimeScope}
			if got, err := s.Exchange(t.Context(), r); err != nil || got.ExpiresIn > 60 {
				t.Fatalf("valid machine control: %v", err)
			}
			tc.edit(&s.aiGateway.cfg)
			if got, err := s.Exchange(t.Context(), r); !errors.Is(err, domain.ErrWorkloadBindingDenied) || got != nil {
				t.Fatalf("machine pin admitted: %v", err)
			}
		})
	}
}
