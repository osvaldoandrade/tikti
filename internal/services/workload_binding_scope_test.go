package services

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	scopedTestSubject = "system:serviceaccount:workload-conveste:cflow-codeq-worker-cf"
	scopedTestSAUID   = "6b0f8a52-4c55-4f3c-9d1e-1a2b3c4d5e6f"
)

// keyedWorkloadBindingRepo stores records exactly like the Redis repository:
// under domain.WorkloadBindingKey(clusterRef, subject).
type keyedWorkloadBindingRepo struct {
	mu      sync.Mutex
	records map[string]domain.WorkloadBinding
	gets    []string
	getErr  error
}

func newKeyedRepo(bindings ...domain.WorkloadBinding) *keyedWorkloadBindingRepo {
	repo := &keyedWorkloadBindingRepo{records: map[string]domain.WorkloadBinding{}}
	for _, binding := range bindings {
		repo.records[domain.WorkloadBindingKey(binding.ClusterRef, binding.Subject)] = binding
	}
	return repo
}

func (r *keyedWorkloadBindingRepo) Upsert(_ context.Context, binding *domain.WorkloadBinding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[domain.WorkloadBindingKey(binding.ClusterRef, binding.Subject)] = *binding
	return nil
}

func (r *keyedWorkloadBindingRepo) Get(_ context.Context, key string) (*domain.WorkloadBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gets = append(r.gets, key)
	if r.getErr != nil {
		return nil, r.getErr
	}
	binding, ok := r.records[key]
	if !ok {
		return nil, nil
	}
	return &binding, nil
}

func (r *keyedWorkloadBindingRepo) Revoke(_ context.Context, key string, at time.Time) (*domain.WorkloadBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	binding, ok := r.records[key]
	if !ok {
		return nil, nil
	}
	binding.Revoked, binding.UpdatedAt = true, at
	r.records[key] = binding
	return &binding, nil
}

func scopedTestBinding(clusterRef, saUID string) domain.WorkloadBinding {
	return domain.WorkloadBinding{
		Subject: scopedTestSubject, Namespace: "workload-conveste", ServiceAccount: "cflow-codeq-worker-cf",
		ClusterRef: clusterRef, ServiceAccountUID: saUID,
		Grants: []domain.WorkloadGrant{{TenantID: "conveste", Audience: domain.WorkloadTargetAudience, Scopes: []string{domain.WorkloadAdminScope}}},
	}
}

func scopedTestVerifier(clusterRef string) *fakeWorkloadVerifier {
	return &fakeWorkloadVerifier{subject: domain.WorkloadSubject{
		Subject: scopedTestSubject, Namespace: "workload-conveste", ServiceAccount: "cflow-codeq-worker-cf",
		Issuer: "https://issuer.example/" + clusterRef, ClusterRef: clusterRef, ServiceAccountUID: scopedTestSAUID,
		PodUID: "0f9e8d7c-6b5a-4f3e-9d2c-1b0a9f8e7d6c",
	}}
}

func scopedTestRequest() domain.WorkloadTokenExchangeReq {
	return domain.WorkloadTokenExchangeReq{
		SubjectToken: "projected", SubjectTokenType: domain.WorkloadSubjectTokenType,
		Audience: domain.WorkloadTargetAudience, Scopes: []string{domain.WorkloadAdminScope}, TenantID: "conveste",
	}
}

func scopedTestService(t *testing.T, repo *keyedWorkloadBindingRepo, verifier *fakeWorkloadVerifier, options ...WorkloadIdentityServiceOption) (*workloadIdentityService, *WorkloadIdentityMetrics) {
	t.Helper()
	_, pem := workloadTestKey(t)
	metrics := NewWorkloadIdentityMetrics(prometheus.NewRegistry())
	options = append([]WorkloadIdentityServiceOption{
		WithTrustedClusterRefs([]string{"conveste-hostgator", "code-cloud"}), WithWorkloadIdentityMetrics(metrics),
	}, options...)
	service := NewWorkloadIdentityService(repo, verifier, "https://tikti.example", pem, "kid", 5*time.Minute, options...).(*workloadIdentityService)
	return service, metrics
}

func TestLegacyExchangeDefaultsAreUnchangedForUnscopedRecords(t *testing.T) {
	repo := newKeyedRepo(scopedTestBinding("", ""))
	service, metrics := scopedTestService(t, repo, scopedTestVerifier("conveste-hostgator"))
	if _, err := service.Exchange(context.Background(), scopedTestRequest()); err != nil {
		t.Fatalf("unscoped legacy exchange: %v", err)
	}
	if got := metricValue(t, metrics.legacyUnscoped); got != 1 {
		t.Fatalf("legacy unscoped metric = %v", got)
	}
	if got := metricValue(t, metrics.legacyCodeQAdmin.WithLabelValues("conveste-hostgator", "workload-conveste")); got != 1 {
		t.Fatalf("legacy codeq:admin metric = %v", got)
	}
	// The scoped key is consulted first, then the bare subject.
	if len(repo.gets) != 2 || repo.gets[0] != domain.WorkloadBindingKey("conveste-hostgator", scopedTestSubject) || repo.gets[1] != scopedTestSubject {
		t.Fatalf("lookup order = %q", repo.gets)
	}
}

func TestLegacyExchangePrefersScopedRecordAndMatchesItsScope(t *testing.T) {
	revokedUnscoped := scopedTestBinding("", "")
	revokedUnscoped.Revoked = true
	tests := []struct {
		name     string
		bindings []domain.WorkloadBinding
		cluster  string
		wantErr  error
	}{
		{name: "scoped record for the verified cluster", bindings: []domain.WorkloadBinding{scopedTestBinding("conveste-hostgator", scopedTestSAUID), revokedUnscoped}, cluster: "conveste-hostgator"},
		{name: "scoped record wins over a valid unscoped record", bindings: []domain.WorkloadBinding{func() domain.WorkloadBinding {
			b := scopedTestBinding("conveste-hostgator", "")
			b.Revoked = true
			return b
		}(), scopedTestBinding("", "")}, cluster: "conveste-hostgator", wantErr: domain.ErrWorkloadBindingDenied},
		{name: "another cluster's scoped record is never used", bindings: []domain.WorkloadBinding{scopedTestBinding("code-cloud", "")}, cluster: "conveste-hostgator", wantErr: domain.ErrWorkloadBindingDenied},
		{name: "scoped ServiceAccount UID mismatch", bindings: []domain.WorkloadBinding{scopedTestBinding("conveste-hostgator", "11111111-2222-4333-8444-555555555555")}, cluster: "conveste-hostgator", wantErr: domain.ErrWorkloadBindingDenied},
		{name: "unscoped key with UID mismatch", bindings: []domain.WorkloadBinding{scopedTestBinding("", "11111111-2222-4333-8444-555555555555")}, cluster: "conveste-hostgator", wantErr: domain.ErrWorkloadBindingDenied},
		{name: "unscoped key with matching UID", bindings: []domain.WorkloadBinding{scopedTestBinding("", scopedTestSAUID)}, cluster: "code-cloud"},
	}
	for _, test := range tests {
		service, _ := scopedTestService(t, newKeyedRepo(test.bindings...), scopedTestVerifier(test.cluster))
		_, err := service.Exchange(context.Background(), scopedTestRequest())
		if !errors.Is(err, test.wantErr) || (test.wantErr == nil && err != nil) {
			t.Fatalf("%s: err = %v, want %v", test.name, err, test.wantErr)
		}
	}
}

func TestScopedWorkloadBindingsFlagRejectsUnscopedRecordsWithMultipleProviders(t *testing.T) {
	repo := newKeyedRepo(scopedTestBinding("", ""))
	service, metrics := scopedTestService(t, repo, scopedTestVerifier("conveste-hostgator"), WithScopedWorkloadBindings(true))
	if _, err := service.Exchange(context.Background(), scopedTestRequest()); !errors.Is(err, domain.ErrWorkloadBindingDenied) {
		t.Fatalf("unscoped record accepted with scopedWorkloadBindings: %v", err)
	}
	if got := metricValue(t, metrics.legacyUnscoped); got != 0 {
		t.Fatalf("unscoped record was read: metric = %v", got)
	}
	upsert := domain.WorkloadBindingUpsertReq{
		Subject: scopedTestSubject, Namespace: "workload-conveste", ServiceAccount: "cflow-codeq-worker-cf",
		Grants: scopedTestBinding("", "").Grants,
	}
	if _, err := service.UpsertBinding(context.Background(), upsert); !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("unscoped upsert accepted with scopedWorkloadBindings: %v", err)
	}
	upsert.ClusterRef = "conveste-hostgator"
	if _, err := service.UpsertBinding(context.Background(), upsert); err != nil {
		t.Fatalf("scoped upsert: %v", err)
	}
	if _, err := service.Exchange(context.Background(), scopedTestRequest()); err != nil {
		t.Fatalf("scoped record denied: %v", err)
	}

	// A single trusted provider is unambiguous: unscoped records stay readable.
	single, _ := scopedTestService(t, newKeyedRepo(scopedTestBinding("", "")), scopedTestVerifier("code-cloud"),
		WithTrustedClusterRefs([]string{"code-cloud"}), WithScopedWorkloadBindings(true))
	if _, err := single.Exchange(context.Background(), scopedTestRequest()); err != nil {
		t.Fatalf("single provider unscoped record denied: %v", err)
	}
}

func TestUpsertBindingValidatesScopeFields(t *testing.T) {
	repo := newKeyedRepo()
	service, _ := scopedTestService(t, repo, scopedTestVerifier("code-cloud"))
	base := domain.WorkloadBindingUpsertReq{
		Subject: scopedTestSubject, Namespace: "workload-conveste", ServiceAccount: "cflow-codeq-worker-cf",
		Grants: scopedTestBinding("", "").Grants,
	}
	for name, mutate := range map[string]func(*domain.WorkloadBindingUpsertReq){
		"untrusted clusterRef": func(r *domain.WorkloadBindingUpsertReq) { r.ClusterRef = "itransform-cluster" },
		"invalid clusterRef":   func(r *domain.WorkloadBindingUpsertReq) { r.ClusterRef = "Code Cloud" },
		"invalid UID":          func(r *domain.WorkloadBindingUpsertReq) { r.ServiceAccountUID = "uid/with/slashes" },
	} {
		req := base
		mutate(&req)
		if _, err := service.UpsertBinding(context.Background(), req); !errors.Is(err, domain.ErrInvalidArgument) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	scoped := base
	scoped.ClusterRef, scoped.ServiceAccountUID = "code-cloud", scopedTestSAUID
	stored, err := service.UpsertBinding(context.Background(), scoped)
	if err != nil || stored.ClusterRef != "code-cloud" || stored.ServiceAccountUID != scopedTestSAUID {
		t.Fatalf("scoped upsert = %#v, %v", stored, err)
	}
	if _, ok := repo.records[domain.WorkloadBindingKey("code-cloud", scopedTestSubject)]; !ok {
		t.Fatalf("scoped record not stored under its cluster key: %v", repo.records)
	}
	// Without the flag an unscoped upsert is still accepted (compatibility).
	if _, err := service.UpsertBinding(context.Background(), base); err != nil {
		t.Fatalf("unscoped upsert without flag: %v", err)
	}
	revoked, err := service.RevokeBinding(context.Background(), domain.WorkloadBindingRevokeReq{Subject: scopedTestSubject, ClusterRef: "code-cloud"})
	if err != nil || !revoked.Revoked || revoked.ClusterRef != "code-cloud" {
		t.Fatalf("scoped revoke = %#v, %v", revoked, err)
	}
	if unscoped := repo.records[scopedTestSubject]; unscoped.Revoked {
		t.Fatal("scoped revoke changed the unscoped record")
	}
	if _, err := service.RevokeBinding(context.Background(), domain.WorkloadBindingRevokeReq{Subject: scopedTestSubject, ClusterRef: "Bad Ref"}); !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("invalid revoke clusterRef: %v", err)
	}
}

func TestLegacyCodeQAdminGrantFlag(t *testing.T) {
	repo := newKeyedRepo(scopedTestBinding("conveste-hostgator", ""))
	service, metrics := scopedTestService(t, repo, scopedTestVerifier("conveste-hostgator"), WithLegacyCodeQAdminGrant(false))
	if _, err := service.Exchange(context.Background(), scopedTestRequest()); !errors.Is(err, domain.ErrWorkloadBindingDenied) {
		t.Fatalf("legacy codeq:admin issued with legacyCodeQAdminGrant=false: %v", err)
	}
	if got := metricValue(t, metrics.legacyCodeQAdmin.WithLabelValues("conveste-hostgator", "workload-conveste")); got != 1 {
		t.Fatalf("legacy codeq:admin attempt metric = %v", got)
	}
	if len(repo.gets) != 0 {
		t.Fatalf("refused exchange still read bindings: %q", repo.gets)
	}
	enabled, _ := scopedTestService(t, repo, scopedTestVerifier("conveste-hostgator"), WithLegacyCodeQAdminGrant(true))
	if _, err := enabled.Exchange(context.Background(), scopedTestRequest()); err != nil {
		t.Fatalf("legacy codeq:admin refused with the default grant: %v", err)
	}
}

func TestLegacyExchangeLookupFailureFailsClosed(t *testing.T) {
	repo := newKeyedRepo(scopedTestBinding("", ""))
	repo.getErr = errors.New("redis down")
	service, _ := scopedTestService(t, repo, scopedTestVerifier("conveste-hostgator"))
	if _, err := service.Exchange(context.Background(), scopedTestRequest()); !errors.Is(err, domain.ErrWorkloadIdentityUnavailable) {
		t.Fatalf("lookup failure: %v", err)
	}
}

func metricValue(t *testing.T, metric prometheus.Metric) float64 {
	t.Helper()
	var out dto.Metric
	if err := metric.Write(&out); err != nil {
		t.Fatalf("read metric: %v", err)
	}
	if out.Counter != nil {
		return out.GetCounter().GetValue()
	}
	if out.Gauge != nil {
		return out.GetGauge().GetValue()
	}
	return float64(out.GetHistogram().GetSampleCount())
}
