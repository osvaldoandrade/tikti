package services

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/osvaldoandrade/tikti/internal/codeqbinding"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	cbTenant     = "conveste"
	cbCluster    = "conveste-hostgator"
	cbNamespace  = "workload-conveste"
	cbSA         = "cflow-codeq-worker-cf"
	cbSAUID      = "6b0f8a52-4c55-4f3c-9d1e-1a2b3c4d5e6f"
	cbPodUID     = "0f9e8d7c-6b5a-4f3e-9d2c-1b0a9f8e7d6c"
	cbTopic      = "cflow-executar"
	cbTopicID    = cbTenant + "." + cbTopic
	cbSubjectJWT = "projected.subject.token-material"
	cbIssuer     = "https://tikti.example"
)

var cbNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

type stubAuthority struct {
	mu         sync.Mutex
	requests   []codeqbinding.AuthorityRequest
	assertions []string
	respond    func(codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error)
	block      chan struct{}
	entered    chan struct{}
}

func (a *stubAuthority) Authorize(ctx context.Context, request codeqbinding.AuthorityRequest, assertion string) (codeqbinding.AuthorityDecision, error) {
	a.mu.Lock()
	a.requests = append(a.requests, request)
	a.assertions = append(a.assertions, assertion)
	a.mu.Unlock()
	if a.entered != nil {
		a.entered <- struct{}{}
	}
	if a.block != nil {
		select {
		case <-a.block:
		case <-ctx.Done():
			return codeqbinding.AuthorityDecision{}, codeqbinding.ErrAuthorityUnavailable
		}
	}
	if a.respond == nil {
		return resolved(request, cbBinding("uid-1", cbTopic, codeqbinding.PolicySubscribe)), nil
	}
	return a.respond(request)
}

func (a *stubAuthority) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.requests)
}

func boolPtr(value bool) *bool { return &value }

func cbBinding(uid, topic, policy string) codeqbinding.Binding {
	return codeqbinding.Binding{BindingUID: uid, Generation: 3, TopicID: cbTenant + "." + topic, TopicName: topic, Policy: policy}
}

func resolved(request codeqbinding.AuthorityRequest, bindings ...codeqbinding.Binding) codeqbinding.AuthorityDecision {
	return codeqbinding.AuthorityDecision{
		SchemaVersion: codeqbinding.SchemaVersion, RequestID: request.RequestID, Allowed: boolPtr(true),
		Reason: codeqbinding.ReasonResolved, Bindings: bindings,
	}
}

type stubTenantReader struct {
	tenant *domain.Tenant
	err    error
}

func (r stubTenantReader) GetRetained(context.Context, string, time.Time) (*domain.Tenant, error) {
	return r.tenant, r.err
}

func activeConveste() *domain.Tenant {
	return &domain.Tenant{Id: cbTenant, Status: domain.TenantStatusActive, CreatedAt: cbNow.Add(-24 * time.Hour)}
}

func cbVerifier() *fakeWorkloadVerifier {
	return &fakeWorkloadVerifier{subject: domain.WorkloadSubject{
		Subject: "system:serviceaccount:" + cbNamespace + ":" + cbSA, Namespace: cbNamespace, ServiceAccount: cbSA,
		Issuer: "https://kubernetes.default.svc.cluster.local", ClusterRef: cbCluster,
		ServiceAccountUID: cbSAUID, PodUID: cbPodUID, ExpiresAt: cbNow.Add(10 * time.Minute),
	}}
}

type cbFixture struct {
	service   *workloadIdentityService
	key       *rsa.PrivateKey
	authority *stubAuthority
	verifier  *fakeWorkloadVerifier
	tenants   *stubTenantReader
	metrics   *WorkloadIdentityMetrics
	audit     *[]string
}

func newCBFixture(t *testing.T, mutate func(*CodeQBindingExchangeConfig)) *cbFixture {
	t.Helper()
	key, pem := workloadTestKey(t)
	cfg := CodeQBindingExchangeConfig{Enabled: true, AccessTokenTTL: 300 * time.Second, MaximumConcurrent: 8, PerIdentityPerMinute: 6}
	if mutate != nil {
		mutate(&cfg)
	}
	authority := &stubAuthority{}
	tenants := &stubTenantReader{tenant: activeConveste()}
	verifier := cbVerifier()
	metrics := NewWorkloadIdentityMetrics(prometheus.NewRegistry())
	service := NewWorkloadIdentityService(nil, verifier, cbIssuer, pem, "tikti-kid", 5*time.Minute,
		WithCodeQBindingExchange(cfg, authority, tenants), WithWorkloadIdentityMetrics(metrics),
	).(*workloadIdentityService)
	service.now = func() time.Time { return cbNow }
	audit := []string{}
	var auditMu sync.Mutex
	service.codeqBindings.auditf = func(format string, args ...any) {
		auditMu.Lock()
		defer auditMu.Unlock()
		audit = append(audit, fmt.Sprintf(format, args...))
	}
	return &cbFixture{service: service, key: key, authority: authority, verifier: verifier, tenants: tenants, metrics: metrics, audit: &audit}
}

func subscribeRequest() domain.WorkloadTokenExchangeReq {
	return domain.WorkloadTokenExchangeReq{
		SubjectToken: cbSubjectJWT, SubjectTokenType: domain.WorkloadSubjectTokenType,
		Audience: domain.WorkloadWorkerAudience,
		Scopes:   []string{"codeq:abandon", "codeq:claim", "codeq:heartbeat", "codeq:nack", "codeq:result"},
		TenantID: cbTenant, CodeQTopicID: cbTopicID,
	}
}

func publishRequest() domain.WorkloadTokenExchangeReq {
	req := subscribeRequest()
	req.Audience, req.Scopes = domain.WorkloadProducerAudience, []string{"codeq:publish"}
	return req
}

func refusalOf(t *testing.T, err error) *domain.WorkloadExchangeError {
	t.Helper()
	var refusal *domain.WorkloadExchangeError
	if !errors.As(err, &refusal) {
		t.Fatalf("error %v is not a coded refusal", err)
	}
	return refusal
}

func expectRefusal(t *testing.T, name string, err error, status int, code string) *domain.WorkloadExchangeError {
	t.Helper()
	refusal := refusalOf(t, err)
	if refusal.Status != status || refusal.Code != code || refusal.CorrelationID == "" {
		t.Fatalf("%s: refusal = %+v, want %d %s", name, refusal, status, code)
	}
	return refusal
}

func TestCodeQBindingExchangeFeatureDisabled(t *testing.T) {
	_, pem := workloadTestKey(t)
	verifier := cbVerifier()
	absent := NewWorkloadIdentityService(nil, verifier, cbIssuer, pem, "kid", time.Minute)
	authority := &stubAuthority{}
	disabled := NewWorkloadIdentityService(nil, verifier, cbIssuer, pem, "kid", time.Minute,
		WithCodeQBindingExchange(CodeQBindingExchangeConfig{Enabled: false, AccessTokenTTL: 300 * time.Second, MaximumConcurrent: 8, PerIdentityPerMinute: 6}, authority, stubTenantReader{tenant: activeConveste()}))
	for name, service := range map[string]WorkloadIdentityService{"absent": absent, "disabled": disabled} {
		_, err := service.Exchange(context.Background(), subscribeRequest())
		expectRefusal(t, name, err, http.StatusForbidden, CodeQBindingCodeFeatureDisabled)
	}
	if authority.calls() != 0 {
		t.Fatalf("disabled grant called the authority %d times", authority.calls())
	}
	// A legacy request (no codeqTopicId) is unchanged and still refuses
	// codeq:publish through the legacy path.
	legacy := publishRequest()
	legacy.CodeQTopicID = ""
	if _, err := disabled.Exchange(context.Background(), legacy); !errors.Is(err, domain.ErrWorkloadBindingDenied) {
		t.Fatalf("legacy codeq:publish = %v", err)
	}
}

func TestCodeQBindingExchangeLegacyPathUnchangedWhenEnabled(t *testing.T) {
	fixture := newCBFixture(t, nil)
	fixture.service.repo = &memoryWorkloadBindingRepo{binding: &domain.WorkloadBinding{
		Subject: "system:serviceaccount:" + cbNamespace + ":" + cbSA, Namespace: cbNamespace, ServiceAccount: cbSA,
		Grants: []domain.WorkloadGrant{{TenantID: cbTenant, Audience: domain.WorkloadProducerAudience, Scopes: []string{domain.WorkloadAdminScope}}},
	}}
	legacy := domain.WorkloadTokenExchangeReq{
		SubjectToken: cbSubjectJWT, SubjectTokenType: domain.WorkloadSubjectTokenType,
		Audience: domain.WorkloadProducerAudience, Scopes: []string{domain.WorkloadAdminScope}, TenantID: cbTenant,
	}
	response, err := fixture.service.Exchange(context.Background(), legacy)
	if err != nil || len(response.EventTypes) != 0 || response.Scopes[0] != domain.WorkloadAdminScope {
		t.Fatalf("legacy exchange = %#v, %v", response, err)
	}
	for _, scopes := range [][]string{{"codeq:publish"}, {"codeq:abandon", "codeq:claim", "codeq:heartbeat", "codeq:nack", "codeq:result"}} {
		req := legacy
		req.Scopes = scopes
		if scopes[0] != "codeq:publish" {
			req.Audience = domain.WorkloadWorkerAudience
		}
		if _, err := fixture.service.Exchange(context.Background(), req); !errors.Is(err, domain.ErrWorkloadBindingDenied) {
			t.Fatalf("legacy path accepted binding scopes %v: %v", scopes, err)
		}
	}
	if fixture.authority.calls() != 0 {
		t.Fatal("legacy exchange consulted the binding authority")
	}
}

func TestCodeQBindingExchangeDispatchRefusesCombinedGrants(t *testing.T) {
	for _, flag := range []bool{true, false} {
		fixture := newCBFixture(t, func(c *CodeQBindingExchangeConfig) { c.Enabled = flag })
		manage := subscribeRequest()
		manage.Audience, manage.Scopes = domain.WorkloadProducerAudience, []string{CodeQTopicManageScope}
		trino := publishRequest()
		trino.Audience = "trino:conveste-installation"
		for name, req := range map[string]domain.WorkloadTokenExchangeReq{"topics:manage": manage, "trino": trino} {
			_, err := fixture.service.Exchange(context.Background(), req)
			expectRefusal(t, fmt.Sprintf("%s flag=%v", name, flag), err, http.StatusBadRequest, CodeQBindingCodeInvalidRequest)
		}
	}
}

func TestCodeQBindingExchangeRejectsInvalidShape(t *testing.T) {
	tests := map[string]func(*domain.WorkloadTokenExchangeReq){
		"unknown audience":          func(r *domain.WorkloadTokenExchangeReq) { r.Audience = "codeq-admin" },
		"publish scopes on worker":  func(r *domain.WorkloadTokenExchangeReq) { r.Scopes = []string{"codeq:publish"} },
		"worker scopes on producer": func(r *domain.WorkloadTokenExchangeReq) { r.Audience = domain.WorkloadProducerAudience },
		"legacy three worker scopes": func(r *domain.WorkloadTokenExchangeReq) {
			r.Scopes = []string{"codeq:claim", "codeq:nack", "codeq:result"}
		},
		"subscribe scope added":        func(r *domain.WorkloadTokenExchangeReq) { r.Scopes = append(r.Scopes, "codeq:subscribe") },
		"admin scope added":            func(r *domain.WorkloadTokenExchangeReq) { r.Scopes = append(r.Scopes, "codeq:admin") },
		"duplicate scope":              func(r *domain.WorkloadTokenExchangeReq) { r.Scopes = append(r.Scopes, "codeq:claim") },
		"whitespace scope":             func(r *domain.WorkloadTokenExchangeReq) { r.Scopes[0] = " codeq:abandon" },
		"no scopes":                    func(r *domain.WorkloadTokenExchangeReq) { r.Scopes = nil },
		"invalid tenant":               func(r *domain.WorkloadTokenExchangeReq) { r.TenantID = "../conveste" },
		"topic of another tenant":      func(r *domain.WorkloadTokenExchangeReq) { r.CodeQTopicID = "wecare." + cbTopic },
		"topic without tenant prefix":  func(r *domain.WorkloadTokenExchangeReq) { r.CodeQTopicID = cbTopic },
		"topic name uppercase":         func(r *domain.WorkloadTokenExchangeReq) { r.CodeQTopicID = cbTenant + ".Cflow" },
		"topic name with dot":          func(r *domain.WorkloadTokenExchangeReq) { r.CodeQTopicID = cbTenant + ".a.b" },
		"topic name too long":          func(r *domain.WorkloadTokenExchangeReq) { r.CodeQTopicID = cbTenant + "." + strings.Repeat("a", 64) },
		"empty topic name":             func(r *domain.WorkloadTokenExchangeReq) { r.CodeQTopicID = cbTenant + "." },
		"wildcard topic":               func(r *domain.WorkloadTokenExchangeReq) { r.CodeQTopicID = cbTenant + ".*" },
		"whitespace-only codeqTopicId": func(r *domain.WorkloadTokenExchangeReq) { r.CodeQTopicID = "   " },
		"subject token type":           func(r *domain.WorkloadTokenExchangeReq) { r.SubjectTokenType = "access_token" },
	}
	for name, mutate := range tests {
		fixture := newCBFixture(t, nil)
		req := subscribeRequest()
		mutate(&req)
		_, err := fixture.service.Exchange(context.Background(), req)
		expectRefusal(t, name, err, http.StatusBadRequest, CodeQBindingCodeInvalidRequest)
		if fixture.authority.calls() != 0 {
			t.Fatalf("%s: authority called for an invalid request", name)
		}
	}
}

func TestCodeQBindingExchangeSubjectTokenRefusals(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*domain.WorkloadTokenExchangeReq, *fakeWorkloadVerifier)
		status int
		code   string
	}{
		{"empty subject token", func(r *domain.WorkloadTokenExchangeReq, _ *fakeWorkloadVerifier) { r.SubjectToken = " " }, 401, CodeQBindingCodeSubjectTokenInvalid},
		{"invalid subject token", func(_ *domain.WorkloadTokenExchangeReq, v *fakeWorkloadVerifier) {
			v.err = domain.ErrWorkloadTokenInvalid
		}, 401, CodeQBindingCodeSubjectTokenInvalid},
		{"verifier unavailable", func(_ *domain.WorkloadTokenExchangeReq, v *fakeWorkloadVerifier) {
			v.err = fmt.Errorf("%w: jwks", domain.ErrWorkloadIdentityUnavailable)
		}, 503, CodeQBindingCodeIdentityUnavailable},
		{"missing ServiceAccount UID", func(_ *domain.WorkloadTokenExchangeReq, v *fakeWorkloadVerifier) { v.subject.ServiceAccountUID = "" }, 401, CodeQBindingCodeUnboundSubjectToken},
		{"missing Pod UID", func(_ *domain.WorkloadTokenExchangeReq, v *fakeWorkloadVerifier) { v.subject.PodUID = "" }, 401, CodeQBindingCodeUnboundSubjectToken},
		{"non-canonical Pod UID", func(_ *domain.WorkloadTokenExchangeReq, v *fakeWorkloadVerifier) { v.subject.PodUID = "pod-1" }, 401, CodeQBindingCodeSubjectTokenInvalid},
		{"uppercase ServiceAccount UID", func(_ *domain.WorkloadTokenExchangeReq, v *fakeWorkloadVerifier) {
			v.subject.ServiceAccountUID = strings.ToUpper(cbSAUID)
		}, 401, CodeQBindingCodeSubjectTokenInvalid},
		{"no verified expiry", func(_ *domain.WorkloadTokenExchangeReq, v *fakeWorkloadVerifier) { v.subject.ExpiresAt = time.Time{} }, 401, CodeQBindingCodeSubjectTokenInvalid},
		{"subject and claims disagree", func(_ *domain.WorkloadTokenExchangeReq, v *fakeWorkloadVerifier) {
			v.subject.Namespace = "workload-wecare"
		}, 401, CodeQBindingCodeSubjectTokenInvalid},
		{"issuer without clusterRef", func(_ *domain.WorkloadTokenExchangeReq, v *fakeWorkloadVerifier) { v.subject.ClusterRef = "" }, 403, CodeQBindingCodeIssuerAmbiguous},
	}
	for _, test := range tests {
		fixture := newCBFixture(t, nil)
		req := subscribeRequest()
		test.mutate(&req, fixture.verifier)
		_, err := fixture.service.Exchange(context.Background(), req)
		expectRefusal(t, test.name, err, test.status, test.code)
		if fixture.authority.calls() != 0 {
			t.Fatalf("%s: authority called", test.name)
		}
	}
}

func TestCodeQBindingExchangeRequiresActiveTenant(t *testing.T) {
	retired := cbNow.Add(-time.Hour)
	tests := map[string]stubTenantReader{
		"missing":       {},
		"suspended":     {tenant: &domain.Tenant{Id: cbTenant, Status: "SUSPENDED", CreatedAt: cbNow.Add(-time.Hour)}},
		"retired":       {tenant: &domain.Tenant{Id: cbTenant, Status: domain.TenantStatusActive, CreatedAt: cbNow.Add(-2 * time.Hour), RetiredAt: &retired}},
		"future":        {tenant: &domain.Tenant{Id: cbTenant, Status: domain.TenantStatusActive, CreatedAt: cbNow.Add(time.Hour)}},
		"zero created":  {tenant: &domain.Tenant{Id: cbTenant, Status: domain.TenantStatusActive}},
		"other tenant":  {tenant: &domain.Tenant{Id: "wecare", Status: domain.TenantStatusActive, CreatedAt: cbNow.Add(-time.Hour)}},
		"store failure": {err: errors.New("redis unavailable")},
	}
	for name, reader := range tests {
		fixture := newCBFixture(t, nil)
		*fixture.tenants = reader
		_, err := fixture.service.Exchange(context.Background(), subscribeRequest())
		if name == "store failure" {
			expectRefusal(t, name, err, 503, CodeQBindingCodeIdentityUnavailable)
		} else {
			expectRefusal(t, name, err, 403, CodeQBindingCodeTenantInactive)
		}
		if fixture.authority.calls() != 0 {
			t.Fatalf("%s: authority called for an inactive tenant", name)
		}
	}
}

func TestCodeQBindingExchangePerIdentityRateLimit(t *testing.T) {
	fixture := newCBFixture(t, nil)
	for attempt := 1; attempt <= 6; attempt++ {
		if _, err := fixture.service.Exchange(context.Background(), subscribeRequest()); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	_, err := fixture.service.Exchange(context.Background(), subscribeRequest())
	refusal := expectRefusal(t, "seventh", err, http.StatusTooManyRequests, CodeQBindingCodeRateLimited)
	if refusal.RetryAfterSeconds < 1 || refusal.RetryAfterSeconds > 60 {
		t.Fatalf("Retry-After = %d", refusal.RetryAfterSeconds)
	}
	if fixture.authority.calls() != 6 {
		t.Fatalf("rate-limited exchange reached the authority: %d calls", fixture.authority.calls())
	}
	// Another Pod of the same ServiceAccount has its own budget.
	fixture.verifier.subject.PodUID = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	if _, err := fixture.service.Exchange(context.Background(), subscribeRequest()); err != nil {
		t.Fatalf("other Pod limited: %v", err)
	}
}

func TestCodeQBindingExchangeBoundsAuthorityConcurrency(t *testing.T) {
	fixture := newCBFixture(t, func(c *CodeQBindingExchangeConfig) { c.MaximumConcurrent = 2 })
	fixture.authority.block = make(chan struct{})
	fixture.authority.entered = make(chan struct{}, 2)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for index := 0; index < 2; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := fixture.service.Exchange(context.Background(), subscribeRequest())
			errs <- err
		}()
	}
	<-fixture.authority.entered
	<-fixture.authority.entered
	_, err := fixture.service.Exchange(context.Background(), subscribeRequest())
	refusal := expectRefusal(t, "third concurrent", err, http.StatusServiceUnavailable, CodeQBindingCodeAuthorityBusy)
	if refusal.RetryAfterSeconds != 1 {
		t.Fatalf("Retry-After = %d", refusal.RetryAfterSeconds)
	}
	close(fixture.authority.block)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("in-flight exchange failed: %v", err)
		}
	}
	// Slots are released: a later exchange proceeds.
	fixture.authority.block, fixture.authority.entered = nil, nil
	if _, err := fixture.service.Exchange(context.Background(), subscribeRequest()); err != nil {
		t.Fatalf("slot not released: %v", err)
	}
}

func TestCodeQBindingExchangeFailsClosedWhenAuthorityUnavailable(t *testing.T) {
	tests := map[string]func(codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error){
		"transport": func(codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error) {
			return codeqbinding.AuthorityDecision{}, codeqbinding.ErrAuthorityUnavailable
		},
		"invalid": func(codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error) {
			return codeqbinding.AuthorityDecision{}, codeqbinding.ErrAuthorityInvalidResponse
		},
		"timeout": func(codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error) {
			return codeqbinding.AuthorityDecision{}, context.DeadlineExceeded
		},
		"requestId": func(r codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error) {
			d := resolved(r)
			d.RequestID = "other"
			return d, nil
		},
		"schema": func(r codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error) {
			d := resolved(r)
			d.SchemaVersion = "v2"
			return d, nil
		},
		"no allowed": func(r codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error) {
			d := resolved(r)
			d.Allowed = nil
			return d, nil
		},
		"bad binding": func(r codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error) {
			b := cbBinding("u", cbTopic, codeqbinding.PolicySubscribe)
			b.TopicID = "wecare." + cbTopic
			return resolved(r, b), nil
		},
	}
	for name, respond := range tests {
		fixture := newCBFixture(t, nil)
		fixture.authority.respond = respond
		_, err := fixture.service.Exchange(context.Background(), subscribeRequest())
		expectRefusal(t, name, err, http.StatusServiceUnavailable, CodeQBindingCodeAuthorityUnavailable)
	}
	// Missing dependencies fail closed even when enabled.
	_, pem := workloadTestKey(t)
	broken := NewWorkloadIdentityService(nil, cbVerifier(), cbIssuer, pem, "kid", time.Minute,
		WithCodeQBindingExchange(CodeQBindingExchangeConfig{Enabled: true, AccessTokenTTL: 300 * time.Second, MaximumConcurrent: 8, PerIdentityPerMinute: 6}, nil, stubTenantReader{tenant: activeConveste()}))
	_, err := broken.Exchange(context.Background(), subscribeRequest())
	expectRefusal(t, "nil authority", err, http.StatusServiceUnavailable, CodeQBindingCodeAuthorityUnavailable)
}

func TestCodeQBindingExchangeMapsAuthorityDenials(t *testing.T) {
	for _, reason := range []string{"NamespaceNotBound", "ServiceNotFound", "ServiceAmbiguous", "ServiceNotReady", "PlacementMismatch", "PlacementAmbiguous", "TooManyBindings"} {
		fixture := newCBFixture(t, nil)
		fixture.authority.respond = func(r codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error) {
			return codeqbinding.AuthorityDecision{SchemaVersion: codeqbinding.SchemaVersion, RequestID: r.RequestID, Allowed: boolPtr(false), Reason: reason}, nil
		}
		_, err := fixture.service.Exchange(context.Background(), subscribeRequest())
		expectRefusal(t, reason, err, http.StatusForbidden, "Authority"+reason)
	}
}

func TestCodeQBindingExchangeSelectsExactlyOneBinding(t *testing.T) {
	excluded := codeqbinding.Excluded{BindingUID: "uid-x", Reason: "TopicNotReady", TopicID: cbTopicID, Policy: codeqbinding.PolicySubscribe}
	tests := []struct {
		name     string
		bindings []codeqbinding.Binding
		excluded []codeqbinding.Excluded
		code     string
	}{
		{name: "allowed with no bindings", code: CodeQBindingCodeBindingNotFound},
		{name: "only excluded for the topic", excluded: []codeqbinding.Excluded{excluded}, code: CodeQBindingCodeBindingNotFound},
		{name: "other topic", bindings: []codeqbinding.Binding{cbBinding("uid-1", "cloudbi-reports", codeqbinding.PolicySubscribe)}, code: CodeQBindingCodeBindingNotFound},
		{name: "same topic other policy", bindings: []codeqbinding.Binding{cbBinding("uid-1", cbTopic, codeqbinding.PolicyPublish)}, code: CodeQBindingCodeBindingNotFound},
		{name: "two bindings same topic and policy", bindings: []codeqbinding.Binding{cbBinding("uid-1", cbTopic, codeqbinding.PolicySubscribe), cbBinding("uid-2", cbTopic, codeqbinding.PolicySubscribe)}, code: CodeQBindingCodeBindingAmbiguous},
	}
	for _, test := range tests {
		fixture := newCBFixture(t, nil)
		fixture.authority.respond = func(r codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error) {
			d := resolved(r, test.bindings...)
			d.Excluded = test.excluded
			return d, nil
		}
		_, err := fixture.service.Exchange(context.Background(), subscribeRequest())
		expectRefusal(t, test.name, err, http.StatusForbidden, test.code)
	}
}

func parseCBToken(t *testing.T, key *rsa.PrivateKey, raw, audience string) (jwt.MapClaims, *jwt.Token) {
	t.Helper()
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(cbIssuer), jwt.WithAudience(audience),
		jwt.WithTimeFunc(func() time.Time { return cbNow }), jwt.WithExpirationRequired())
	if err != nil || !token.Valid {
		t.Fatalf("parse issued token: %v", err)
	}
	return claims, token
}

func claimKeys(claims map[string]any) []string {
	keys := make([]string, 0, len(claims))
	for key := range claims {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func TestCodeQBindingExchangeMintsExactClaimSet(t *testing.T) {
	tests := []struct {
		name     string
		request  domain.WorkloadTokenExchangeReq
		policy   string
		audience string
		scope    string
	}{
		{name: "publish", request: publishRequest(), policy: codeqbinding.PolicyPublish, audience: domain.WorkloadProducerAudience, scope: "codeq:publish"},
		{name: "subscribe", request: subscribeRequest(), policy: codeqbinding.PolicySubscribe, audience: domain.WorkloadWorkerAudience, scope: "codeq:abandon codeq:claim codeq:heartbeat codeq:nack codeq:result"},
	}
	for _, test := range tests {
		fixture := newCBFixture(t, nil)
		fixture.authority.respond = func(r codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error) {
			return resolved(r, cbBinding("binding-uid-7", cbTopic, codeqbinding.PolicyPublish), cbBinding("binding-uid-8", cbTopic, codeqbinding.PolicySubscribe),
				cbBinding("binding-uid-9", "cloudbi-reports", test.policy)), nil
		}
		// Request scopes in a non-sorted order are accepted as the same exact set.
		slices.Reverse(test.request.Scopes)
		response, err := fixture.service.Exchange(context.Background(), test.request)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		claims, token := parseCBToken(t, fixture.key, response.AccessToken, test.audience)
		wantKeys := []string{"aud", "cluster_ref", "codeq_binding", "eventTypes", "exp", "iat", "iss", "jti", "scope", "sub", "tid"}
		if got := claimKeys(claims); !slices.Equal(got, wantKeys) {
			t.Fatalf("%s: claim keys = %v, want %v", test.name, got, wantKeys)
		}
		if token.Header["kid"] != "tikti-kid" || token.Header["alg"] != "RS256" {
			t.Fatalf("%s: header = %v", test.name, token.Header)
		}
		if aud, ok := claims["aud"].(string); !ok || aud != test.audience {
			t.Fatalf("%s: aud must be one string, got %#v", test.name, claims["aud"])
		}
		wantSub := "codefoundry:workload:" + cbCluster + ":" + cbNamespace + ":" + cbSA + ":" + cbPodUID
		if claims["sub"] != wantSub || claims["tid"] != cbTenant || claims["scope"] != test.scope || claims["cluster_ref"] != cbCluster || claims["iss"] != cbIssuer {
			t.Fatalf("%s: claims = %#v", test.name, claims)
		}
		eventTypes, ok := claims["eventTypes"].([]any)
		if !ok || len(eventTypes) != 1 || eventTypes[0] != cbTopic {
			t.Fatalf("%s: eventTypes = %#v", test.name, claims["eventTypes"])
		}
		binding, ok := claims["codeq_binding"].(map[string]any)
		if !ok || !slices.Equal(claimKeys(binding), []string{"generation", "policy", "topicId", "uid"}) {
			t.Fatalf("%s: codeq_binding = %#v", test.name, claims["codeq_binding"])
		}
		wantUID := map[string]string{codeqbinding.PolicyPublish: "binding-uid-7", codeqbinding.PolicySubscribe: "binding-uid-8"}[test.policy]
		if binding["uid"] != wantUID || binding["generation"] != float64(3) || binding["policy"] != test.policy ||
			binding["topicId"] != claims["tid"].(string)+"."+eventTypes[0].(string) {
			t.Fatalf("%s: codeq_binding values = %#v", test.name, binding)
		}
		iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
		if exp-iat != 300 || iat != cbNow.Unix() {
			t.Fatalf("%s: exp-iat = %d", test.name, exp-iat)
		}
		if response.TokenType != "Bearer" || response.ExpiresIn != 300 || response.Audience != test.audience ||
			response.TenantID != cbTenant || !slices.Equal(response.EventTypes, []string{cbTopic}) ||
			strings.Join(response.Scopes, " ") != test.scope {
			t.Fatalf("%s: response metadata = %#v", test.name, response)
		}
	}
}

func TestCodeQBindingExchangeTTLBoundedBySubjectLifetime(t *testing.T) {
	fixture := newCBFixture(t, nil)
	fixture.verifier.subject.ExpiresAt = cbNow.Add(100*time.Second + 400*time.Millisecond)
	response, err := fixture.service.Exchange(context.Background(), subscribeRequest())
	if err != nil || response.ExpiresIn != 100 {
		t.Fatalf("bounded ttl = %#v, %v", response, err)
	}
	claims, _ := parseCBToken(t, fixture.key, response.AccessToken, domain.WorkloadWorkerAudience)
	if int64(claims["exp"].(float64))-int64(claims["iat"].(float64)) != 100 {
		t.Fatalf("token lifetime = %#v", claims)
	}
	fixture.verifier.subject.ExpiresAt = cbNow.Add(29 * time.Second)
	_, err = fixture.service.Exchange(context.Background(), subscribeRequest())
	expectRefusal(t, "expiring", err, http.StatusUnauthorized, CodeQBindingCodeSubjectTokenExpiring)

	shorter := newCBFixture(t, func(c *CodeQBindingExchangeConfig) { c.AccessTokenTTL = 120 * time.Second })
	if response, err := shorter.service.Exchange(context.Background(), subscribeRequest()); err != nil || response.ExpiresIn != 120 {
		t.Fatalf("configured ttl = %#v, %v", response, err)
	}
	// An out-of-bounds configured TTL never issues.
	tooLong := newCBFixture(t, func(c *CodeQBindingExchangeConfig) { c.AccessTokenTTL = 301 * time.Second })
	_, err = tooLong.service.Exchange(context.Background(), subscribeRequest())
	expectRefusal(t, "ttl > 300", err, http.StatusServiceUnavailable, CodeQBindingCodeAuthorityUnavailable)
}

func TestCodeQBindingExchangeAuthorityRequestUsesOnlyVerifiedIdentity(t *testing.T) {
	fixture := newCBFixture(t, nil)
	// The body can only name tenant and topic; even a tenant that does not own
	// the verified namespace is forwarded unchanged for the authority to refuse.
	request := subscribeRequest()
	request.TenantID, request.CodeQTopicID = "wecare", "wecare."+cbTopic
	*fixture.tenants = stubTenantReader{tenant: &domain.Tenant{Id: "wecare", Status: domain.TenantStatusActive, CreatedAt: cbNow.Add(-time.Hour)}}
	fixture.authority.respond = func(r codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error) {
		return codeqbinding.AuthorityDecision{SchemaVersion: codeqbinding.SchemaVersion, RequestID: r.RequestID, Allowed: boolPtr(false), Reason: "NamespaceNotBound"}, nil
	}
	_, err := fixture.service.Exchange(context.Background(), request)
	refusal := expectRefusal(t, "cross tenant", err, http.StatusForbidden, "AuthorityNamespaceNotBound")
	got := fixture.authority.requests[0]
	want := codeqbinding.AuthorityRequest{
		SchemaVersion: codeqbinding.SchemaVersion, RequestID: refusal.CorrelationID, TenantID: "wecare",
		ClusterRef: cbCluster, Namespace: cbNamespace, ServiceAccountName: cbSA, ServiceAccountUID: cbSAUID, PodUID: cbPodUID,
	}
	if got != want || !codeqbinding.ValidRequest(got) {
		t.Fatalf("authority request = %#v, want %#v", got, want)
	}

	// The service assertion: exact audience/subject, <= 60 s, jti, no tenant claims.
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(fixture.authority.assertions[0], claims, func(*jwt.Token) (any, error) { return &fixture.key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(codeqbinding.AuthorityAudience),
		jwt.WithIssuer(cbIssuer), jwt.WithTimeFunc(func() time.Time { return cbNow }))
	if err != nil || !token.Valid {
		t.Fatalf("assertion invalid: %v", err)
	}
	if got := claimKeys(claims); !slices.Equal(got, []string{"aud", "exp", "iat", "iss", "jti", "nbf", "sub"}) {
		t.Fatalf("assertion claim keys = %v", got)
	}
	iat, exp, nbf := int64(claims["iat"].(float64)), int64(claims["exp"].(float64)), int64(claims["nbf"].(float64))
	if claims["sub"] != codeqbinding.ServiceSubject || claims["aud"] != codeqbinding.AuthorityAudience ||
		exp-iat > 60 || exp <= iat || nbf != iat-5 || claims["jti"] == "" || token.Header["kid"] != "tikti-kid" {
		t.Fatalf("assertion claims = %#v header=%v", claims, token.Header)
	}
}

func TestCodeQBindingExchangeNeverCachesDecisions(t *testing.T) {
	fixture := newCBFixture(t, nil)
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := fixture.service.Exchange(context.Background(), subscribeRequest()); err != nil {
			t.Fatal(err)
		}
	}
	// Revocation: the next exchange after the binding disappears is denied.
	fixture.authority.respond = func(r codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error) { return resolved(r), nil }
	_, err := fixture.service.Exchange(context.Background(), subscribeRequest())
	expectRefusal(t, "after revocation", err, http.StatusForbidden, CodeQBindingCodeBindingNotFound)
	if fixture.authority.calls() != 3 {
		t.Fatalf("authority calls = %d, want one per exchange", fixture.authority.calls())
	}
	ids := map[string]bool{}
	for _, request := range fixture.authority.requests {
		ids[request.RequestID] = true
	}
	if len(ids) != 3 {
		t.Fatalf("request IDs reused: %v", ids)
	}
}

func TestCodeQBindingExchangeAuditAndMetricsAreRedacted(t *testing.T) {
	fixture := newCBFixture(t, nil)
	response, err := fixture.service.Exchange(context.Background(), subscribeRequest())
	if err != nil {
		t.Fatal(err)
	}
	fixture.authority.respond = func(r codeqbinding.AuthorityRequest) (codeqbinding.AuthorityDecision, error) {
		return codeqbinding.AuthorityDecision{SchemaVersion: codeqbinding.SchemaVersion, RequestID: r.RequestID, Allowed: boolPtr(false), Reason: "PlacementMismatch"}, nil
	}
	_, denyErr := fixture.service.Exchange(context.Background(), subscribeRequest())
	refusal := refusalOf(t, denyErr)
	if len(*fixture.audit) != 2 {
		t.Fatalf("audit lines = %d", len(*fixture.audit))
	}
	allow, deny := (*fixture.audit)[0], (*fixture.audit)[1]
	for _, want := range []string{"event=codeq_binding_exchange", "decision=allow", `code="Issued"`, `clusterRef="conveste-hostgator"`,
		`namespace="workload-conveste"`, `serviceAccount="cflow-codeq-worker-cf"`, `podUid="` + cbPodUID + `"`, `serviceAccountUid="` + cbSAUID + `"`,
		`topicId="conveste.cflow-executar"`, `policy="Subscribe"`, `bindingUid="uid-1"`, "bindingGeneration=3", "authorityLatencyMs=", " jti=", " exp="} {
		if !strings.Contains(allow, want) {
			t.Fatalf("allow audit missing %q: %s", want, allow)
		}
	}
	if !strings.Contains(deny, "decision=deny") || !strings.Contains(deny, `code="AuthorityPlacementMismatch"`) ||
		!strings.Contains(deny, `correlationId="`+refusal.CorrelationID+`"`) || strings.Contains(deny, " jti=") || strings.Contains(deny, " exp=") {
		t.Fatalf("deny audit = %s", deny)
	}
	secrets := append([]string{cbSubjectJWT, response.AccessToken}, fixture.authority.assertions...)
	for _, line := range *fixture.audit {
		for _, secret := range secrets {
			if strings.Contains(line, secret) || strings.Contains(line, secret[:20]) {
				t.Fatalf("audit leaked token material: %s", line)
			}
		}
		if strings.Contains(strings.ToLower(line), "bearer") || strings.Contains(strings.ToLower(line), "authorization") {
			t.Fatalf("audit mentions authorization material: %s", line)
		}
	}
	if got := metricValue(t, fixture.metrics.bindingExchange.WithLabelValues("issued", "Issued", "Subscribe", cbCluster)); got != 1 {
		t.Fatalf("issued metric = %v", got)
	}
	if got := metricValue(t, fixture.metrics.bindingExchange.WithLabelValues("denied", "AuthorityPlacementMismatch", "Subscribe", cbCluster)); got != 1 {
		t.Fatalf("denied metric = %v", got)
	}
	if got := metricValue(t, fixture.metrics.bindingAuthority.WithLabelValues("allowed").(prometheus.Metric)); got != 1 {
		t.Fatalf("authority histogram samples = %v", got)
	}
}

func TestCodeQBindingSubjectIsUniquePerClusterAndPod(t *testing.T) {
	a := CodeQBindingSubject("code-cloud", cbNamespace, cbSA, cbPodUID)
	b := CodeQBindingSubject(cbCluster, cbNamespace, cbSA, cbPodUID)
	if a == b || a == "codecloud-worker" || strings.HasPrefix(a, "system:serviceaccount:") {
		t.Fatalf("subjects collide: %q %q", a, b)
	}
}

// TestCodeQBindingExchangeQueueBindingConflictThroughRealClient reproduces the
// integration defect: one Service with QueueTopic bindings aa-first (primary,
// eligible) and zz-second (QueueBindingConflict). The primary is issued; the
// conflicting topic is 403 BindingNotFound; neither is 503.
func TestCodeQBindingExchangeQueueBindingConflictThroughRealClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request codeqbinding.AuthorityRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		_, _ = fmt.Fprintf(w, `{"schemaVersion":"codeq-binding-authority/v1","requestId":%q,"allowed":true,"reason":"Resolved",`+
			`"bindings":[{"bindingUid":"uid-aa-first","generation":2,"topicId":"conveste.cflow-executar","topicName":"cflow-executar","policy":"Subscribe"}],`+
			`"excluded":[{"bindingUid":"uid-zz-second","reason":"QueueBindingConflict","topicId":"conveste.cflow-relatorios","policy":"Subscribe"}]}`,
			request.RequestID)
	}))
	t.Cleanup(server.Close)
	client, err := codeqbinding.NewClient(server.URL+codeqbinding.AuthorityPath, server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newCBFixture(t, nil)
	fixture.service.codeqBindings.authority = client

	response, err := fixture.service.Exchange(context.Background(), subscribeRequest())
	if err != nil {
		t.Fatalf("primary binding refused: %v", err)
	}
	if len(response.EventTypes) != 1 || response.EventTypes[0] != cbTopic {
		t.Fatalf("primary eventTypes = %v", response.EventTypes)
	}

	conflicting := subscribeRequest()
	conflicting.CodeQTopicID = cbTenant + ".cflow-relatorios"
	_, err = fixture.service.Exchange(context.Background(), conflicting)
	expectRefusal(t, "conflicting binding", err, http.StatusForbidden, CodeQBindingCodeBindingNotFound)
	if deny := (*fixture.audit)[1]; !strings.Contains(deny, `exclusionReason="QueueBindingConflict"`) || !strings.Contains(deny, `code="BindingNotFound"`) {
		t.Fatalf("deny audit = %s", deny)
	}
	if allow := (*fixture.audit)[0]; !strings.Contains(allow, `exclusionReason=""`) {
		t.Fatalf("allow audit = %s", allow)
	}
	if got := metricValue(t, fixture.metrics.bindingExchange.WithLabelValues("denied", CodeQBindingCodeBindingNotFound, "Subscribe", cbCluster)); got != 1 {
		t.Fatalf("BindingNotFound metric = %v", got)
	}
}
