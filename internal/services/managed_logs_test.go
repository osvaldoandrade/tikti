package services

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/internal/managedlogs"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type logsAuthorityFake struct {
	request  managedlogs.Request
	decision managedlogs.Decision
	calls    int
	err      error
}

func (f *logsAuthorityFake) Authorize(_ context.Context, r managedlogs.Request, _ string) (managedlogs.Decision, error) {
	f.request = r
	f.calls++
	d := f.decision
	d.SchemaVersion = managedlogs.Version
	d.RequestID = r.RequestID
	return d, f.err
}

func verifiedLogsClaims(t *testing.T, s *workloadIdentityService, response *domain.WorkloadTokenExchangeResp) jwt.MapClaims {
	t.Helper()
	key, err := s.signingKey()
	if err != nil {
		t.Fatal("signer unavailable")
	}
	token, err := jwt.Parse(response.AccessToken, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(response.Audience), jwt.WithIssuer(s.issuer), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(s.now))
	if err != nil || !token.Valid || token.Header["kid"] != s.keyID {
		t.Fatal("signed Logs token failed verification")
	}
	return token.Claims.(jwt.MapClaims)
}

func TestManagedLogsCollectorTokenHasNoTenantOrAdminAuthority(t *testing.T) {
	s, authority, req := logsExchangeFixture(t)
	response, err := s.Exchange(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	c := verifiedLogsClaims(t, s, response)
	for _, key := range []string{"tid", "role", "eventTypes", "codeq_binding", "tenant_epoch"} {
		if _, ok := c[key]; ok {
			t.Fatalf("forbidden claim %s", key)
		}
	}
	if c["aud"] != "logs-ingest" || c["scope"] != "logs:ingest" || authority.request.Identity.ClusterRef != "cluster-a" {
		t.Fatal("identity not server-derived")
	}
	carrier, ok := c["logs_collector"].(map[string]any)
	if !ok || carrier["installationId"] != "test-installation" || carrier["serviceAccountUid"] != "11111111-1111-4111-8111-111111111111" {
		t.Fatal("collector carrier missing")
	}
}

func TestManagedLogsGrantDoesNotFallThroughOrAcceptTenantInjection(t *testing.T) {
	for _, mutate := range []func(*domain.WorkloadTokenExchangeReq){func(r *domain.WorkloadTokenExchangeReq) { r.TenantID = "other" }, func(r *domain.WorkloadTokenExchangeReq) { r.Scopes = []string{"codeq:admin"} }, func(r *domain.WorkloadTokenExchangeReq) { r.Audience = "codeq-producer" }, func(r *domain.WorkloadTokenExchangeReq) { r.CodeQTopicID = "other.cf-logs" }, func(r *domain.WorkloadTokenExchangeReq) { r.LogsConfigUID = "injected" }, func(r *domain.WorkloadTokenExchangeReq) { r.Scopes = []string{" logs:ingest "} }} {
		s, a, r := logsExchangeFixture(t)
		mutate(&r)
		if _, err := s.Exchange(context.Background(), r); err == nil {
			t.Fatal("mixed grant accepted")
		}
		if a.calls != 0 {
			t.Fatal("invalid request reached authority")
		}
	}
}

func TestManagedLogsResolveAssertionFitsExactServiceContract(t *testing.T) {
	s, _, r := logsExchangeFixture(t)
	r.LogsGrant = "Resolve"
	r.Audience = managedlogs.AuthorityAudience
	r.Scopes = []string{}
	response, err := s.Exchange(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	c := verifiedLogsClaims(t, s, response)
	if c["sub"] != "runtime:logs-api" || c["aud"] != managedlogs.AuthorityAudience || c["exp"].(float64)-c["iat"].(float64) > 60 {
		t.Fatal("service assertion not bounded")
	}
	for _, key := range []string{"scope", "tid", "logs_collector"} {
		if _, ok := c[key]; ok {
			t.Fatalf("service assertion contains %s", key)
		}
	}
}

func TestManagedLogsQueueGrantsStayOnOneTenantTopicAndConfigLifetime(t *testing.T) {
	for _, operation := range []string{"Publish", "Subscribe"} {
		t.Run(operation, func(t *testing.T) {
			s, a, r := logsExchangeFixture(t)
			s.managedLogs.tenants = stubTenantReader{tenant: activeConveste()}
			r.LogsGrant = operation
			r.TenantID = cbTenant
			r.LogsConfigUID = "actual-config-uid"
			r.LogsConfigGeneration = 7
			r.Audience = domain.WorkloadProducerAudience
			r.Scopes = slices.Clone(codeqPublishScopes)
			if operation == "Subscribe" {
				r.Audience = domain.WorkloadWorkerAudience
				r.Scopes = slices.Clone(codeqSubscribeScopes)
			}
			a.decision.GrantUID = r.LogsConfigUID
			a.decision.GrantGeneration = r.LogsConfigGeneration
			a.decision.TenantID = cbTenant
			a.decision.TopicID = cbTenant + ".cf-logs"
			a.decision.RetentionSeconds = 604800
			response, err := s.Exchange(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			c := verifiedLogsClaims(t, s, response)
			b, ok := c["codeq_binding"].(map[string]any)
			if !ok || b["uid"] != r.LogsConfigUID || b["generation"] != float64(7) || b["policy"] != operation || b["topicId"] != cbTenant+".cf-logs" || c["tid"] != cbTenant || c["scope"] != strings.Join(r.Scopes, " ") {
				t.Fatal("queue grant broadened authority")
			}
			for _, field := range []string{"role", "logs_collector", "tenant_epoch"} {
				if _, ok := c[field]; ok {
					t.Fatal("unexpected queue authority carrier")
				}
			}
			if c["exp"].(float64)-c["iat"].(float64) > 300 {
				t.Fatal("queue TTL exceeded limit")
			}
		})
	}
}

func TestManagedLogsFailsClosedForIdentityAndAuthorityFailures(t *testing.T) {
	for _, kind := range []string{"disabled", "unbound", "expiring", "authority-error", "authority-denied", "foreign-tenant", "foreign-config", "inactive-tenant", "noncanonical-subject", "bad-cluster"} {
		t.Run(kind, func(t *testing.T) {
			s, a, r := logsExchangeFixture(t)
			v := s.verifier.(*fakeWorkloadVerifier)
			switch kind {
			case "disabled":
				s.managedLogs.cfg.Enabled = false
			case "unbound":
				v.subject.PodUID = ""
			case "expiring":
				v.subject.ExpiresAt = time.Now().Add(20 * time.Second)
			case "authority-error":
				a.err = errors.New("credential-sentinel")
			case "authority-denied":
				a.decision = managedlogs.Decision{Reason: "NotAuthorized"}
			case "foreign-tenant":
				a.decision.TenantID = "foreign"
			case "foreign-config":
				a.decision.GrantGeneration = 0
			case "inactive-tenant":
				r.LogsGrant = "Publish"
				r.Audience = domain.WorkloadProducerAudience
				r.Scopes = slices.Clone(codeqPublishScopes)
				r.TenantID = cbTenant
				r.LogsConfigUID = "actual-config"
				r.LogsConfigGeneration = 1
				s.managedLogs.tenants = stubTenantReader{tenant: &domain.Tenant{Id: cbTenant, Status: domain.TenantStatusDisabled}}
			case "noncanonical-subject":
				v.subject.Subject = " system:serviceaccount:codecloud-observability:logs-collector "
			case "bad-cluster":
				v.subject.ClusterRef = "INVALID:cluster"
			}
			response, err := s.Exchange(context.Background(), r)
			if err == nil || response != nil {
				t.Fatal("unsafe identity or grant issued token")
			}
			if strings.Contains(err.Error(), "credential-sentinel") {
				t.Fatal("authority error exposed")
			}
		})
	}
}

// logsExchangeFixture uses the same real signer and bound JWT test verifier
// as the existing exchange; no network or token material leaves the process.
func logsExchangeFixture(t *testing.T) (*workloadIdentityService, *logsAuthorityFake, domain.WorkloadTokenExchangeReq) {
	t.Helper()
	s := newManagedLogsTestService(t)
	a := &logsAuthorityFake{decision: managedlogs.Decision{Allowed: true, Reason: "Resolved", InstallationID: "test-installation", ClusterUID: "cluster-uid", GrantUID: "collector-policy", GrantGeneration: 1}}
	WithManagedLogs(ManagedLogsExchangeConfig{Enabled: true, TTL: 300 * time.Second, MaximumConcurrent: 2, PerIdentityPerMinute: 60}, a, nil)(s)
	r := domain.WorkloadTokenExchangeReq{SubjectToken: "test-projected-token", SubjectTokenType: domain.WorkloadSubjectTokenType, Audience: "logs-ingest", Scopes: []string{"logs:ingest"}, LogsGrant: "Ingest"}
	return s, a, r
}

func newManagedLogsTestService(t *testing.T) *workloadIdentityService {
	t.Helper()
	_, privatePEM := workloadTestKey(t)
	subject := domain.WorkloadSubject{Subject: "system:serviceaccount:codecloud-observability:logs-collector", ClusterRef: "cluster-a", Namespace: "codecloud-observability", ServiceAccount: "logs-collector", ServiceAccountUID: "11111111-1111-4111-8111-111111111111", PodUID: "22222222-2222-4222-8222-222222222222", ExpiresAt: time.Now().Add(time.Hour)}
	return NewWorkloadIdentityService(nil, &fakeWorkloadVerifier{subject: subject}, "https://tikti.example.test", privatePEM, "test-logs-key", 5*time.Minute).(*workloadIdentityService)
}

func FuzzManagedLogsAuthorityDecision(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":"managed-logs-authority/v1","allowed":false,"reason":"NotAuthorized"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var d managedlogs.Decision
		_ = managedlogs.Decode(raw, &d)
		_ = managedlogs.ValidDecision(managedlogs.Request{}, d)
	})
}
