package services

import (
	"context"
	"github.com/osvaldoandrade/tikti/pkg/domain"
	"testing"
	"time"
)

type topicTenantReader struct{ tenant *domain.Tenant }

func (r *topicTenantReader) GetRetained(context.Context, string, time.Time) (*domain.Tenant, error) {
	return r.tenant, nil
}
func TestCodeQTopicControllerBindsIdentityAndCurrentTenantEpoch(t *testing.T) {
	_, key := workloadTestKey(t)
	verifier := validWorkloadVerifier()
	verifier.subject.Issuer = "https://master.example"
	verifier.subject.ClusterRef = "master"
	verifier.subject.ServiceAccountUID = "sa-uid"
	verifier.subject.PodUID = "pod-uid"
	policy := CodeQTopicControllerIdentity{Enabled: true, Issuer: verifier.subject.Issuer, ClusterRef: "master", Namespace: verifier.subject.Namespace, ServiceAccount: verifier.subject.ServiceAccount, ServiceAccountUID: "sa-uid"}
	reader := &topicTenantReader{tenant: &domain.Tenant{Id: "payments", CreatedAt: time.Now().Add(-time.Hour), Status: domain.TenantStatusActive}}
	s := NewWorkloadIdentityService(nil, verifier, "https://tikti.example", key, "kid", time.Minute, WithCodeQTopicController(policy, reader)).(*workloadIdentityService)
	req := validWorkloadExchangeRequest()
	req.Scopes = []string{CodeQTopicManageScope}
	token, err := s.Exchange(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ValidateCodeQTopicToken(context.Background(), token.AccessToken); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"issuer", "uid", "cluster", "namespace", "account", "pod"} {
		old := verifier.subject
		switch field {
		case "pod":
			verifier.subject.PodUID = ""
		case "issuer":
			verifier.subject.Issuer = "https://foreign"
		case "uid":
			verifier.subject.ServiceAccountUID = "old-uid"
		case "cluster":
			verifier.subject.ClusterRef = "worker"
		case "namespace":
			verifier.subject.Namespace = "other"
		case "account":
			verifier.subject.ServiceAccount = "other"
		}
		if _, err = s.Exchange(context.Background(), req); err == nil {
			t.Fatal("foreign identity accepted", field)
		}
		verifier.subject = old
	}

	originalScopes := req.Scopes
	req.Scopes = []string{CodeQTopicManageScope, domain.WorkloadAdminScope}
	if _, err = s.Exchange(context.Background(), req); err == nil {
		t.Fatal("mixed scope accepted")
	}
	req.Scopes = originalScopes
	disabled := NewWorkloadIdentityService(nil, verifier, "https://tikti.example", key, "kid", time.Minute)
	if _, err = disabled.Exchange(context.Background(), req); err == nil {
		t.Fatal("reserved scope fell back while disabled")
	}
	reader.tenant.CreatedAt = reader.tenant.CreatedAt.Add(time.Second)
	if _, err = s.ValidateCodeQTopicToken(context.Background(), token.AccessToken); err == nil {
		t.Fatal("stale epoch accepted")
	}
	reader.tenant.Status = domain.TenantStatusDisabled
	if _, err = s.Exchange(context.Background(), req); err == nil {
		t.Fatal("disabled tenant accepted")
	}
	reader.tenant.Status = domain.TenantStatusActive
	retired := time.Now()
	reader.tenant.RetiredAt = &retired
	if _, err = s.Exchange(context.Background(), req); err == nil {
		t.Fatal("retired tenant accepted")
	}
	req.TenantID = "foreign"
	if _, err = s.Exchange(context.Background(), req); err == nil {
		t.Fatal("cross-tenant authority accepted")
	}
}

func TestCodeQTopicControllerNewTenantNeedsNoWorkloadBinding(t *testing.T) {
	_, key := workloadTestKey(t)
	v := validWorkloadVerifier()
	v.subject.Issuer = "https://master.example"
	v.subject.ClusterRef = "master"
	v.subject.ServiceAccountUID = "uid"
	v.subject.PodUID = "pod"
	policy := CodeQTopicControllerIdentity{Enabled: true, Issuer: v.subject.Issuer, ClusterRef: "master", Namespace: v.subject.Namespace, ServiceAccount: v.subject.ServiceAccount, ServiceAccountUID: "uid"}
	reader := &topicTenantReader{tenant: &domain.Tenant{Id: "new-tenant", CreatedAt: time.Now().Add(-time.Minute), Status: domain.TenantStatusActive}}
	service := NewWorkloadIdentityService(nil, v, "https://tikti.example", key, "kid", time.Minute, WithCodeQTopicController(policy, reader))
	req := validWorkloadExchangeRequest()
	req.TenantID = "new-tenant"
	req.Scopes = []string{CodeQTopicManageScope}
	if _, err := service.Exchange(context.Background(), req); err != nil {
		t.Fatal(err)
	}
}
