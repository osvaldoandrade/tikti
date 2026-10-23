package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/aigateway"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type aiTenantReaderFailure struct{}

func (aiTenantReaderFailure) GetRetained(context.Context, string, time.Time) (*domain.Tenant, error) {
	return nil, context.DeadlineExceeded
}

type aiAuthorityFunc func(context.Context, string) (aigateway.Principal, error)

func (f aiAuthorityFunc) Authorize(ctx context.Context, raw string) (aigateway.Principal, error) {
	return f(ctx, raw)
}

type aiUserValidatorFunc func(context.Context, string) (aigateway.Claims, error)

func (f aiUserValidatorFunc) ValidateAIAccessToken(ctx context.Context, raw string) (aigateway.Claims, error) {
	return f(ctx, raw)
}

func TestAIUserUnavailableDependenciesFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*userService)
	}{
		{"callback absent", func(s *userService) { s.aiGateway.authority = nil }},
		{"tenant reader absent", func(s *userService) { s.aiGateway.tenants = nil }},
		{"tenant read failed", func(s *userService) { s.aiGateway.tenants = aiTenantReaderFailure{} }},
		{"client service absent", func(s *userService) { s.clientSvc = nil }},
		{"invalid client ceiling", func(s *userService) {
			s.clientSvc = &mockClientService{getClientFn: func(context.Context, string, string) (*domain.Client, error) {
				return &domain.Client{Id: aigateway.Audience, TenantId: "tenant-1", Status: domain.ClientStatusActive, AllowedGrantTypes: []string{string(domain.GrantTypeTokenExchange)}, DefaultScopes: []string{"code-llm:*"}}, nil
			}}
		}},
		{"client unavailable", func(s *userService) {
			s.clientSvc = &mockClientService{getClientFn: func(context.Context, string, string) (*domain.Client, error) { return nil, context.DeadlineExceeded }}
		}},
		{"invalid signing key", func(s *userService) { s.jwksPrivateKey = "invalid" }},
		{"missing signing kid", func(s *userService) { s.jwksKeyID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, _, _, _ := aiUserFixture(t)
			tc.edit(s)
			if got, err := s.TokenExchange(t.Context(), r); err == nil || got != nil {
				t.Fatal("unknown dependency issued AI identity")
			}
		})
	}
}

func TestAIUserAuthorityConcurrencyIsBounded(t *testing.T) {
	s, r, a, _, _ := aiUserFixture(t)
	s.aiGateway.slots = make(chan struct{}, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	s.aiGateway.authority = aiAuthorityFunc(func(ctx context.Context, raw string) (aigateway.Principal, error) {
		close(entered)
		select {
		case <-release:
			return a.Authorize(ctx, raw)
		case <-ctx.Done():
			return aigateway.Principal{}, ctx.Err()
		}
	})
	finished := make(chan error, 1)
	go func() { _, err := s.TokenExchange(t.Context(), r); finished <- err }()
	select {
	case <-entered:
	case err := <-finished:
		t.Fatalf("first request never entered authority: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("first request did not reach authority")
	}
	if got, err := s.TokenExchange(t.Context(), r); !errors.Is(err, domain.ErrAuthenticationUnavailable) || got != nil {
		t.Fatal("saturated authority admitted another request")
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatalf("admitted request failed: %v", err)
	}
}

func TestAIWorkloadRefusesInvalidProjectedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*domain.WorkloadSubject)
	}{
		{"subject syntax", func(s *domain.WorkloadSubject) { s.Subject = "user" }},
		{"namespace mismatch", func(s *domain.WorkloadSubject) { s.Namespace = "foreign" }},
		{"service account mismatch", func(s *domain.WorkloadSubject) { s.ServiceAccount = "foreign" }},
		{"missing issuer", func(s *domain.WorkloadSubject) { s.Issuer = "" }},
		{"invalid cluster", func(s *domain.WorkloadSubject) { s.ClusterRef = "bad:cluster" }},
		{"missing service account uid", func(s *domain.WorkloadSubject) { s.ServiceAccountUID = "" }},
		{"missing pod uid", func(s *domain.WorkloadSubject) { s.PodUID = "" }},
		{"expired", func(s *domain.WorkloadSubject) { s.ExpiresAt = time.Now().Add(-time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, v, _, _ := aiWorkloadFixture(t)
			tc.edit(&v.subject)
			if got, err := s.Exchange(t.Context(), r); !errors.Is(err, domain.ErrWorkloadTokenInvalid) || got != nil {
				t.Fatalf("invalid projected identity: %v", err)
			}
		})
	}
	for _, tc := range []struct {
		name string
		edit func(*domain.WorkloadTokenExchangeReq)
	}{
		{"wrong subject token type", func(r *domain.WorkloadTokenExchangeReq) { r.SubjectTokenType = "wrong" }},
		{"missing projected token", func(r *domain.WorkloadTokenExchangeReq) { r.SubjectToken = "" }},
		{"oversized projected token", func(r *domain.WorkloadTokenExchangeReq) { r.SubjectToken = strings.Repeat("a", 16385) }},
		{"codeq topic", func(r *domain.WorkloadTokenExchangeReq) { r.CodeQTopicID = "topic" }},
		{"logs grant", func(r *domain.WorkloadTokenExchangeReq) { r.LogsGrant = "grant" }},
		{"logs grant kind", func(r *domain.WorkloadTokenExchangeReq) { r.LogsGrantKind = "kind" }},
		{"logs config uid", func(r *domain.WorkloadTokenExchangeReq) { r.LogsConfigUID = "uid" }},
		{"logs config generation", func(r *domain.WorkloadTokenExchangeReq) { r.LogsConfigGeneration = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, _, _, _ := aiWorkloadFixture(t)
			tc.edit(&r)
			if got, err := s.Exchange(t.Context(), r); !errors.Is(err, domain.ErrInvalidArgument) || got != nil {
				t.Fatalf("mixed projected request: %v", err)
			}
		})
	}
	t.Run("verifier denied", func(t *testing.T) {
		s, r, v, _, _ := aiWorkloadFixture(t)
		v.err = domain.ErrWorkloadTokenInvalid
		if _, err := s.Exchange(t.Context(), r); !errors.Is(err, domain.ErrWorkloadTokenInvalid) {
			t.Fatalf("verifier denial lost: %v", err)
		}
	})
	t.Run("rate bound", func(t *testing.T) {
		s, r, _, a, tenant := aiWorkloadFixture(t)
		cfg := s.aiGateway.cfg
		cfg.PerIdentityPerMinute = 1
		s.aiGateway = newAIGatewayExchange(cfg, a, &topicTenantReader{tenant: tenant})
		if _, err := s.Exchange(t.Context(), r); err != nil {
			t.Fatal(err)
		}
		if got, err := s.Exchange(t.Context(), r); !errors.Is(err, domain.ErrRateLimited) || got != nil {
			t.Fatalf("identity rate bypass: %v", err)
		}
	})
	t.Run("usage needs user", func(t *testing.T) {
		s, r, _, _, _ := aiWorkloadFixture(t)
		r.Scopes = []string{aigateway.UsageScope}
		if _, err := s.Exchange(t.Context(), r); !errors.Is(err, domain.ErrWorkloadBindingDenied) {
			t.Fatalf("workload acquired aggregate usage: %v", err)
		}
	})
}

func TestAIDelegationRejectsEveryBroaderActor(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*aigateway.Claims)
	}{
		{"nested class", func(c *aigateway.Claims) { c.PrincipalKind = "Delegated" }},
		{"nested actor", func(c *aigateway.Claims) { c.Actor = &aigateway.Actor{} }},
		{"workload principal", func(c *aigateway.Claims) { c.Workload = &aigateway.Workload{} }},
		{"missing version", func(c *aigateway.Claims) { c.Version = nil }},
		{"foreign tenant", func(c *aigateway.Claims) { c.TenantID = "foreign" }},
		{"narrow user ceiling", func(c *aigateway.Claims) { c.Scope = aigateway.ModelsScope }},
		{"expired user", func(c *aigateway.Claims) { c.ExpiresAt = time.Now().Add(-time.Second).Unix() }},
		{"foreign tenant lifetime", func(c *aigateway.Claims) { c.TenantEpoch = strings.Repeat("b", 64) }},
		{"foreign tenant uid", func(c *aigateway.Claims) { c.TenantUID = "foreign" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, _, a, tenant := aiWorkloadFixture(t)
			version := 3
			u := aigateway.Claims{PrincipalKind: "User", Subject: "user-1", TenantID: tenant.Id, TenantUID: tenant.Id, TenantEpoch: a.epoch, Version: &version, Scope: aigateway.InvokeScope, ExpiresAt: time.Now().Add(time.Minute).Unix()}
			r.UserToken = "synthetic-user"
			s.aiGateway.users = aiUserValidatorFunc(func(context.Context, string) (aigateway.Claims, error) { return u, nil })
			if _, err := s.Exchange(t.Context(), r); err != nil {
				t.Fatalf("valid delegated control: %v", err)
			}
			tc.edit(&u)
			if got, err := s.Exchange(t.Context(), r); err == nil || got != nil {
				t.Fatal("broader or revoked delegated actor accepted")
			}
		})
	}
	t.Run("user authority absent", func(t *testing.T) {
		s, r, _, _, _ := aiWorkloadFixture(t)
		r.UserToken = "synthetic-user"
		s.aiGateway.users = nil
		if _, err := s.Exchange(t.Context(), r); !errors.Is(err, domain.ErrWorkloadBindingDenied) {
			t.Fatalf("missing user authority: %v", err)
		}
	})
}

func TestAIMachineGrantRevocationAndRequestBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*domain.WorkloadTokenExchangeReq)
	}{
		{"delegated machine", func(r *domain.WorkloadTokenExchangeReq) { r.UserToken = "synthetic" }},
		{"unknown grant", func(r *domain.WorkloadTokenExchangeReq) { r.AIGrant = "CefasAdmin" }},
		{"wrong audience", func(r *domain.WorkloadTokenExchangeReq) { r.Audience = "other" }},
		{"missing scope", func(r *domain.WorkloadTokenExchangeReq) { r.Scopes = nil }},
		{"extra scope", func(r *domain.WorkloadTokenExchangeReq) { r.Scopes = append(r.Scopes, "code-admin:*") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, _, _, _ := aiWorkloadFixture(t)
			r.AIGrant, r.Audience, r.Scopes = "Runtime", aigateway.RuntimeAudience, []string{aigateway.RuntimeScope}
			tc.edit(&r)
			if got, err := s.Exchange(t.Context(), r); !errors.Is(err, domain.ErrWorkloadBindingDenied) || got != nil {
				t.Fatalf("machine grant broadened: %v", err)
			}
		})
	}
	t.Run("retired runtime tenant", func(t *testing.T) {
		s, r, _, _, tenant := aiWorkloadFixture(t)
		r.AIGrant, r.Audience, r.Scopes = "Runtime", aigateway.RuntimeAudience, []string{aigateway.RuntimeScope}
		now := time.Now()
		tenant.RetiredAt = &now
		if _, err := s.Exchange(t.Context(), r); !errors.Is(err, domain.ErrInvalidTenant) {
			t.Fatalf("retired tenant obtained machine grant: %v", err)
		}
	})
}
