package services

import (
	"context"
	"slices"
	"testing"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

func retainedLogsExchangeFixture(t *testing.T) (*workloadIdentityService, *logsAuthorityFake, domain.WorkloadTokenExchangeReq) {
	t.Helper()
	s, a, r := logsExchangeFixture(t)
	s.managedLogs.tenants = stubTenantReader{tenant: activeConveste()}
	r.LogsGrant, r.LogsGrantKind = "Subscribe", "LogRetentionPolicy"
	r.TenantID, r.LogsConfigUID, r.LogsConfigGeneration = cbTenant, "actual-policy-uid", 4
	r.Audience, r.Scopes = domain.WorkloadWorkerAudience, slices.Clone(codeqSubscribeScopes)
	a.decision.GrantUID, a.decision.GrantGeneration = r.LogsConfigUID, r.LogsConfigGeneration
	a.decision.TenantID, a.decision.TopicID, a.decision.RetentionSeconds = cbTenant, cbTenant+".cf-logs", 3600
	return s, a, r
}

func TestManagedLogsRetainedPolicySubscribePinsRealPolicyLifetime(t *testing.T) {
	s, authority, req := retainedLogsExchangeFixture(t)
	response, err := s.Exchange(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if authority.request.GrantKind != "LogRetentionPolicy" || authority.request.ConfigUID != req.LogsConfigUID || authority.request.ConfigGeneration != req.LogsConfigGeneration {
		t.Fatal("retained policy selection not forwarded to real authority")
	}
	claims := verifiedLogsClaims(t, s, response)
	carrier, ok := claims["codeq_binding"].(map[string]any)
	if !ok || carrier["uid"] != req.LogsConfigUID || carrier["generation"] != float64(4) || carrier["policy"] != "Subscribe" || carrier["topicId"] != cbTenant+".cf-logs" || claims["scope"] != "codeq:abandon codeq:claim codeq:heartbeat codeq:nack codeq:result" {
		t.Fatal("retained policy token broadened or lost lifetime")
	}
}

func TestManagedLogsRejectsPolicyKindOutsideSubscribeBeforeAuthority(t *testing.T) {
	for _, operation := range []string{"Publish", "Ingest", "Resolve", ""} {
		t.Run(operation, func(t *testing.T) {
			s, authority, r := retainedLogsExchangeFixture(t)
			r.LogsGrant = operation
			switch operation {
			case "Publish":
				r.Audience, r.Scopes = domain.WorkloadProducerAudience, slices.Clone(codeqPublishScopes)
			case "Ingest":
				r.Audience, r.Scopes = "logs-ingest", []string{"logs:ingest"}
				r.TenantID, r.LogsConfigUID, r.LogsConfigGeneration = "", "", 0
			case "Resolve":
				r.Audience, r.Scopes = "code-admin-logs-authority", []string{}
				r.TenantID, r.LogsConfigUID, r.LogsConfigGeneration = "", "", 0
			case "":
				r.LogsConfigUID, r.LogsConfigGeneration = "", 0
			}
			if response, err := s.Exchange(context.Background(), r); err == nil || response != nil {
				t.Fatal("policy kind issued non-subscribe token")
			}
			if authority.calls != 0 {
				t.Fatal("invalid policy selection reached authority")
			}
		})
	}
}

func TestManagedLogsPolicyGrantRefusesForeignLifetimeAndInactiveTenant(t *testing.T) {
	for _, kind := range []string{"unknown-kind", "foreign-uid", "foreign-generation", "foreign-tenant", "inactive-tenant"} {
		t.Run(kind, func(t *testing.T) {
			s, a, r := retainedLogsExchangeFixture(t)
			switch kind {
			case "unknown-kind":
				r.LogsGrantKind = "QueueTopic"
			case "foreign-uid":
				a.decision.GrantUID = "replaced-policy"
			case "foreign-generation":
				a.decision.GrantGeneration++
			case "foreign-tenant":
				a.decision.TenantID, a.decision.TopicID = "other", "other.cf-logs"
			case "inactive-tenant":
				s.managedLogs.tenants = stubTenantReader{tenant: &domain.Tenant{Id: cbTenant, Status: domain.TenantStatusDisabled}}
			}
			if response, err := s.Exchange(context.Background(), r); err == nil || response != nil {
				t.Fatal("unsafe policy token issued")
			}
			if (kind == "unknown-kind" || kind == "inactive-tenant") && a.calls != 0 {
				t.Fatal("invalid policy selector/tenant reached authority")
			}
		})
	}
}
