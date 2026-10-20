package services

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const testLogsStoreAudience = "code-admin-logs-store"

func storeTestScopes(operation string) []string {
	if operation == "CefasBootstrap" {
		return []string{"cefas:table:create", "cefas:table:describe"}
	}
	return []string{"cefas:item:delete:logs-events", "cefas:item:read:logs-events", "cefas:item:read:logs-state", "cefas:item:write:logs-events", "cefas:item:write:logs-state", "cefas:query:logs-events", "cefas:table:describe"}
}

func storeExchangeFixture(t *testing.T, operation string) (*workloadIdentityService, *logsAuthorityFake, domain.WorkloadTokenExchangeReq) {
	t.Helper()
	s, a, r := logsExchangeFixture(t)
	r.LogsGrant, r.Audience, r.Scopes = operation, testLogsStoreAudience, storeTestScopes(operation)
	return s, a, r
}

func TestManagedLogsStoreIssuesOnlyFixedNativeAuthority(t *testing.T) {
	for _, operation := range []string{"CefasBootstrap", "CefasRuntime"} {
		t.Run(operation, func(t *testing.T) {
			s, a, r := storeExchangeFixture(t, operation)
			slices.Reverse(r.Scopes)
			now := time.Now().UTC().Truncate(time.Second)
			s.now = func() time.Time { return now }
			s.verifier.(*fakeWorkloadVerifier).subject.ExpiresAt = now.Add(95 * time.Second)
			response, err := s.Exchange(context.Background(), r)
			if err != nil || response == nil {
				t.Fatalf("fixed store grant refused: %v", err)
			}
			c := verifiedLogsClaims(t, s, response)
			jti, validJTI := c["jti"].(string)
			if c["aud"] != testLogsStoreAudience || c["scope"] != strings.Join(storeTestScopes(operation), " ") || c["sub"] != CodeQBindingSubject(a.request.Identity.ClusterRef, a.request.Identity.Namespace, a.request.Identity.ServiceAccountName, a.request.Identity.PodUID) || !validJTI || jti == "" || c["exp"].(float64)-c["iat"].(float64) != 95 || response.ExpiresIn != 95 {
				t.Fatal("native authority, subject or original expiry changed")
			}
			if !slices.Equal(response.Scopes, storeTestScopes(operation)) || response.TenantID != "" || len(response.EventTypes) != 0 || a.request.Operation != operation || a.request.TenantID != "" || a.request.ConfigUID != "" || a.request.ConfigGeneration != 0 || a.request.GrantKind != "" {
				t.Fatal("native store response or authority request broadened")
			}
			for _, key := range []string{"tid", "role", "roles", "email", "eventTypes", "codeq_binding", "logs_collector", "tenant_epoch", domain.PlatformPrivilegeClaim} {
				if _, exists := c[key]; exists {
					t.Fatalf("native token contains unrelated authority %s", key)
				}
			}
		})
	}
}

func TestManagedLogsStoreRejectsMixedRequestsBeforeAuthority(t *testing.T) {
	for _, operation := range []string{"CefasBootstrap", "CefasRuntime"} {
		for _, kind := range []string{"missing-scopes", "extra-scope", "duplicate-scope", "wildcard", "scope-whitespace", "audience", "tenant", "config-uid", "config-generation", "grant-kind", "topic", "other-operation", "legacy"} {
			t.Run(operation+"/"+kind, func(t *testing.T) {
				s, a, r := storeExchangeFixture(t, operation)
				switch kind {
				case "missing-scopes":
					r.Scopes = r.Scopes[:len(r.Scopes)-1]
				case "extra-scope":
					r.Scopes = append(r.Scopes, "codeq:admin")
				case "duplicate-scope":
					r.Scopes[1] = r.Scopes[0]
				case "wildcard":
					r.Scopes[0] = "cefas:item:read:*"
				case "scope-whitespace":
					r.Scopes[0] += " "
				case "audience":
					r.Audience = "codeq-producer"
				case "tenant":
					r.TenantID = "tenant-a"
				case "config-uid":
					r.LogsConfigUID = "config-uid"
				case "config-generation":
					r.LogsConfigGeneration = 1
				case "grant-kind":
					r.LogsGrantKind = "ObservabilityConfig"
				case "topic":
					r.CodeQTopicID = "tenant-a.cf-logs"
				case "other-operation":
					r.LogsGrant = "Resolve"
				case "legacy":
					r.LogsGrant = ""
				}
				if response, err := s.Exchange(context.Background(), r); err == nil || response != nil {
					t.Fatal("mixed native grant issued a token")
				}
				if a.calls != 0 {
					t.Fatal("invalid native grant reached authority")
				}
			})
		}
	}
}

func TestManagedLogsStoreRefusesUnsafeAuthorityAndExpiry(t *testing.T) {
	for _, kind := range []string{"disabled", "denied", "unavailable", "tenant", "topic", "retention", "grant-uid", "grant-generation", "cluster", "installation", "unbound", "expiring", "expired"} {
		t.Run(kind, func(t *testing.T) {
			s, a, r := storeExchangeFixture(t, "CefasRuntime")
			switch kind {
			case "disabled":
				s.managedLogs.cfg.Enabled = false
			case "denied":
				a.decision.Allowed = false
			case "unavailable":
				a.err = errors.New("test-secret-sentinel")
			case "tenant":
				a.decision.TenantID = "tenant-a"
			case "topic":
				a.decision.TopicID = "tenant-a.cf-logs"
			case "retention":
				a.decision.RetentionSeconds = 604800
			case "grant-uid":
				a.decision.GrantUID = ""
			case "grant-generation":
				a.decision.GrantGeneration = 0
			case "cluster":
				a.decision.ClusterUID = ""
			case "installation":
				a.decision.InstallationID = ""
			case "unbound":
				s.verifier.(*fakeWorkloadVerifier).subject.ServiceAccountUID = ""
			case "expiring":
				s.verifier.(*fakeWorkloadVerifier).subject.ExpiresAt = s.now().Add(29 * time.Second)
			case "expired":
				s.verifier.(*fakeWorkloadVerifier).subject.ExpiresAt = s.now().Add(-time.Second)
			}
			response, err := s.Exchange(context.Background(), r)
			if err == nil || response != nil || strings.Contains(err.Error(), "test-secret-sentinel") {
				t.Fatal("unsafe native store grant issued or leaked dependency data")
			}
		})
	}
	for _, operation := range []string{"CefasBootstrap", "CefasRuntime"} {
		s, _, r := storeExchangeFixture(t, operation)
		response, err := s.Exchange(context.Background(), r)
		if err != nil || response.ExpiresIn != 300 {
			t.Fatal("native store grant exceeded or ignored configured lifetime")
		}
	}
}

func TestManagedLogsStoreAudienceCannotBeIssuedByHumanExchange(t *testing.T) {
	for _, mode := range []string{"admin", "legacy-admin", "custom-client-defaults", "discovery"} {
		t.Run(mode, func(t *testing.T) {
			home := "tenant-logs"
			u := &domain.User{Id: "native-user", Email: "human@example.test", Status: domain.UserStatusActive, Role: domain.RoleAdmin, CompanyId: &home}
			var clients ClientService
			if mode != "legacy-admin" {
				clients = &mockClientService{getClientFn: func(context.Context, string, string) (*domain.Client, error) {
					return &domain.Client{Id: testLogsStoreAudience, TenantId: home, Status: domain.ClientStatusActive, DefaultScopes: storeTestScopes("CefasRuntime")}, nil
				}}
			}
			s := NewUserService(&mockUserRepo{findByEmailFn: func(context.Context, string) (*domain.User, error) { return u, nil }}, nil, nil, clients, "test-session-secret", "https://issuer", "tikti", makePEMKey(t), "kid")
			r := domain.TokenExchangeReq{IdToken: signCurrentIDToken(t, "test-session-secret", u.Email, "https://issuer", "tikti", 0), Audience: testLogsStoreAudience, TenantID: home, Scopes: storeTestScopes("CefasRuntime")}
			if mode == "custom-client-defaults" {
				r.Scopes = nil
			}
			if mode == "discovery" {
				r.DiscoverTenantTargetsV2 = true
			}
			if response, err := s.TokenExchange(context.Background(), r); !errors.Is(err, domain.ErrInvalidAudience) || response != nil {
				t.Fatal("dedicated store audience reached human issuance")
			}
			if mode != "discovery" {
				r.Audience = "existing-custom-cefas"
				r.Scopes = storeTestScopes("CefasRuntime")
				if response, err := s.TokenExchange(context.Background(), r); err != nil || response == nil {
					t.Fatalf("unrelated legacy audience changed: %v", err)
				}
			}
		})
	}
}
