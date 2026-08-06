package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const testWorkloadSubject = "system:serviceaccount:code-admin:code-admin-controller-queue"

type fakeWorkloadVerifier struct {
	subject domain.WorkloadSubject
	err     error
	wait    bool
}

func (v *fakeWorkloadVerifier) Verify(ctx context.Context, _ string) (domain.WorkloadSubject, error) {
	if v.wait {
		<-ctx.Done()
		return domain.WorkloadSubject{}, ctx.Err()
	}
	return v.subject, v.err
}

type memoryWorkloadBindingRepo struct {
	mu          sync.Mutex
	binding     *domain.WorkloadBinding
	getErr      error
	upsertErr   error
	upsertCalls int
}

func (r *memoryWorkloadBindingRepo) Upsert(_ context.Context, binding *domain.WorkloadBinding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.upsertErr != nil {
		return r.upsertErr
	}
	r.upsertCalls++
	copyBinding := *binding
	r.binding = &copyBinding
	return nil
}

func (r *memoryWorkloadBindingRepo) Get(_ context.Context, subject string) (*domain.WorkloadBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getErr != nil {
		return nil, r.getErr
	}
	if r.binding == nil || r.binding.Subject != subject {
		return nil, nil
	}
	copyBinding := *r.binding
	return &copyBinding, nil
}

func (r *memoryWorkloadBindingRepo) Revoke(_ context.Context, subject string, revokedAt time.Time) (*domain.WorkloadBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getErr != nil {
		return nil, r.getErr
	}
	if r.binding == nil || r.binding.Subject != subject {
		return nil, nil
	}
	r.binding.Revoked = true
	r.binding.UpdatedAt = revokedAt
	copyBinding := *r.binding
	return &copyBinding, nil
}

func TestWorkloadIdentityExchangeIssuesTenantBoundRS256Token(t *testing.T) {
	privateKey, privatePEM := workloadTestKey(t)
	repo := &memoryWorkloadBindingRepo{binding: validWorkloadBinding()}
	service := NewWorkloadIdentityService(repo, validWorkloadVerifier(), "https://tikti.example.com", privatePEM, "tikti-workload-1", 5*time.Minute).(*workloadIdentityService)
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	response, err := service.Exchange(context.Background(), validWorkloadExchangeRequest())
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if response.TokenType != "Bearer" || response.ExpiresIn != 300 || response.TenantID != "payments" || response.Audience != domain.WorkloadTargetAudience || len(response.Scopes) != 1 || response.Scopes[0] != domain.WorkloadAdminScope {
		t.Fatalf("Exchange() metadata = %#v", response)
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(response.AccessToken, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() || token.Header["kid"] != "tikti-workload-1" {
			t.Fatalf("unexpected token header = %#v", token.Header)
		}
		return &privateKey.PublicKey, nil
	}, jwt.WithIssuer("https://tikti.example.com"), jwt.WithAudience(domain.WorkloadTargetAudience), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !token.Valid {
		t.Fatalf("parse access token: %v", err)
	}
	if claims["tid"] != "payments" || claims["scope"] != domain.WorkloadAdminScope || claims["sub"] != testWorkloadSubject {
		t.Fatalf("access token claims = %#v", claims)
	}
	if int64(claims["exp"].(float64))-int64(claims["iat"].(float64)) != 300 {
		t.Fatalf("access token lifetime = %#v", claims)
	}
	if repo.upsertCalls != 0 {
		t.Fatalf("exchange persisted token material through %d binding writes", repo.upsertCalls)
	}
}

func TestWorkloadIdentityExchangeIssuesTopicBoundCodeQWorkerToken(t *testing.T) {
	privateKey, privatePEM := workloadTestKey(t)
	repo := &memoryWorkloadBindingRepo{binding: &domain.WorkloadBinding{
		Subject: testWorkloadSubject, Namespace: "code-admin", ServiceAccount: "code-admin-controller-queue",
		Grants: []domain.WorkloadGrant{{
			TenantID: "payments", Audience: domain.WorkloadWorkerAudience,
			Scopes:     []string{domain.WorkloadResultScope, domain.WorkloadNackScope, domain.WorkloadClaimScope},
			EventTypes: []string{"payments.crud-demo-events"},
		}},
	}}
	service := NewWorkloadIdentityService(repo, validWorkloadVerifier(), "https://tikti.example.com", privatePEM, "tikti-workload-1", 5*time.Minute).(*workloadIdentityService)
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	request := validWorkloadExchangeRequest()
	request.Audience = domain.WorkloadWorkerAudience
	request.Scopes = []string{domain.WorkloadResultScope, domain.WorkloadNackScope, domain.WorkloadClaimScope}
	response, err := service.Exchange(context.Background(), request)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if !slices.Equal(response.Scopes, []string{domain.WorkloadClaimScope, domain.WorkloadNackScope, domain.WorkloadResultScope}) ||
		!slices.Equal(response.EventTypes, []string{"payments.crud-demo-events"}) {
		t.Fatalf("Exchange() worker metadata = %#v", response)
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(response.AccessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	}, jwt.WithIssuer("https://tikti.example.com"), jwt.WithAudience(domain.WorkloadWorkerAudience), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !token.Valid {
		t.Fatalf("parse worker access token: %v", err)
	}
	if claims["scope"] != "codeq:claim codeq:nack codeq:result" || claims["tid"] != "payments" {
		t.Fatalf("worker claims = %#v", claims)
	}
	eventTypes, ok := claims["eventTypes"].([]interface{})
	if !ok || len(eventTypes) != 1 || eventTypes[0] != "payments.crud-demo-events" {
		t.Fatalf("worker event types = %#v", claims["eventTypes"])
	}
}

func TestWorkloadIdentityExchangeFailsClosed(t *testing.T) {
	_, privatePEM := workloadTestKey(t)
	tests := []struct {
		name    string
		mutate  func(*domain.WorkloadTokenExchangeReq, *memoryWorkloadBindingRepo, *fakeWorkloadVerifier)
		wantErr error
	}{
		{name: "empty token", mutate: func(req *domain.WorkloadTokenExchangeReq, _ *memoryWorkloadBindingRepo, _ *fakeWorkloadVerifier) {
			req.SubjectToken = ""
		}, wantErr: domain.ErrWorkloadTokenInvalid},
		{name: "token type", mutate: func(req *domain.WorkloadTokenExchangeReq, _ *memoryWorkloadBindingRepo, _ *fakeWorkloadVerifier) {
			req.SubjectTokenType = "access_token"
		}, wantErr: domain.ErrWorkloadTokenInvalid},
		{name: "audience", mutate: func(req *domain.WorkloadTokenExchangeReq, _ *memoryWorkloadBindingRepo, _ *fakeWorkloadVerifier) {
			req.Audience = "other"
		}, wantErr: domain.ErrInvalidArgument},
		{name: "scope", mutate: func(req *domain.WorkloadTokenExchangeReq, _ *memoryWorkloadBindingRepo, _ *fakeWorkloadVerifier) {
			req.Scopes = []string{"codeq:claim"}
		}, wantErr: domain.ErrWorkloadBindingDenied},
		{name: "tenant", mutate: func(req *domain.WorkloadTokenExchangeReq, _ *memoryWorkloadBindingRepo, _ *fakeWorkloadVerifier) {
			req.TenantID = "../payments"
		}, wantErr: domain.ErrInvalidArgument},
		{name: "invalid projected token", mutate: func(_ *domain.WorkloadTokenExchangeReq, _ *memoryWorkloadBindingRepo, verifier *fakeWorkloadVerifier) {
			verifier.err = domain.ErrWorkloadTokenInvalid
		}, wantErr: domain.ErrWorkloadTokenInvalid},
		{name: "unknown subject", mutate: func(_ *domain.WorkloadTokenExchangeReq, repo *memoryWorkloadBindingRepo, _ *fakeWorkloadVerifier) {
			repo.binding = nil
		}, wantErr: domain.ErrWorkloadBindingDenied},
		{name: "revoked", mutate: func(_ *domain.WorkloadTokenExchangeReq, repo *memoryWorkloadBindingRepo, _ *fakeWorkloadVerifier) {
			repo.binding.Revoked = true
		}, wantErr: domain.ErrWorkloadBindingDenied},
		{name: "cross tenant", mutate: func(req *domain.WorkloadTokenExchangeReq, _ *memoryWorkloadBindingRepo, _ *fakeWorkloadVerifier) {
			req.TenantID = "analytics"
		}, wantErr: domain.ErrWorkloadBindingDenied},
		{name: "namespace mismatch", mutate: func(_ *domain.WorkloadTokenExchangeReq, _ *memoryWorkloadBindingRepo, verifier *fakeWorkloadVerifier) {
			verifier.subject.Namespace = "other"
		}, wantErr: domain.ErrWorkloadBindingDenied},
		{name: "storage unavailable", mutate: func(_ *domain.WorkloadTokenExchangeReq, repo *memoryWorkloadBindingRepo, _ *fakeWorkloadVerifier) {
			repo.getErr = errors.New("redis unavailable")
		}, wantErr: domain.ErrWorkloadIdentityUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := &memoryWorkloadBindingRepo{binding: validWorkloadBinding()}
			verifier := validWorkloadVerifier()
			req := validWorkloadExchangeRequest()
			test.mutate(&req, repo, verifier)
			service := NewWorkloadIdentityService(repo, verifier, "https://tikti.example.com", privatePEM, "kid", time.Minute)
			response, err := service.Exchange(context.Background(), req)
			if response != nil || !errors.Is(err, test.wantErr) {
				t.Fatalf("Exchange() = %#v, %v, want %v", response, err, test.wantErr)
			}
		})
	}
}

func TestWorkloadIdentityExchangeRejectsInvalidSigningConfiguration(t *testing.T) {
	_, privatePEM := workloadTestKey(t)
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak RSA key: %v", err)
	}
	weakPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weakKey)}))
	tests := []struct {
		name   string
		issuer string
		keyPEM string
		keyID  string
	}{
		{name: "missing issuer", keyPEM: privatePEM, keyID: "kid"},
		{name: "missing key id", issuer: "https://tikti.example.com", keyPEM: privatePEM},
		{name: "weak key", issuer: "https://tikti.example.com", keyPEM: weakPEM, keyID: "kid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewWorkloadIdentityService(&memoryWorkloadBindingRepo{binding: validWorkloadBinding()}, validWorkloadVerifier(), test.issuer, test.keyPEM, test.keyID, time.Minute)
			if _, err := service.Exchange(context.Background(), validWorkloadExchangeRequest()); !errors.Is(err, domain.ErrWorkloadIdentityUnavailable) {
				t.Fatalf("Exchange() error = %v", err)
			}
		})
	}
}

func TestWorkloadBindingValidationLimitsGrantsAndAcceptsDottedServiceAccounts(t *testing.T) {
	service := NewWorkloadIdentityService(&memoryWorkloadBindingRepo{}, validWorkloadVerifier(), "issuer", "key", "kid", time.Minute)
	tooMany := make([]domain.WorkloadGrant, domain.MaxWorkloadGrants+1)
	for index := range tooMany {
		tooMany[index] = domain.WorkloadGrant{TenantID: "t" + strings.Repeat("a", index%60+1), Audience: domain.WorkloadTargetAudience, Scopes: []string{domain.WorkloadAdminScope}}
	}
	if _, err := service.UpsertBinding(context.Background(), domain.WorkloadBindingUpsertReq{
		Subject: testWorkloadSubject, Namespace: "code-admin", ServiceAccount: "code-admin-controller-queue", Grants: tooMany,
	}); !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("too many grants error = %v", err)
	}

	dottedSubject := "system:serviceaccount:code-admin:queue.controller"
	binding, err := service.UpsertBinding(context.Background(), domain.WorkloadBindingUpsertReq{
		Subject: dottedSubject, Namespace: "code-admin", ServiceAccount: "queue.controller",
		Grants: []domain.WorkloadGrant{{TenantID: "payments", Audience: domain.WorkloadTargetAudience, Scopes: []string{domain.WorkloadAdminScope}}},
	})
	if err != nil || binding.Subject != dottedSubject {
		t.Fatalf("dotted binding = %#v, %v", binding, err)
	}
}

func TestWorkloadBindingRequiresBoundEventTypesForCodeQWorkers(t *testing.T) {
	service := NewWorkloadIdentityService(&memoryWorkloadBindingRepo{}, validWorkloadVerifier(), "issuer", "key", "kid", time.Minute)
	for _, grant := range []domain.WorkloadGrant{
		{TenantID: "payments", Audience: domain.WorkloadWorkerAudience, Scopes: []string{domain.WorkloadClaimScope, domain.WorkloadNackScope, domain.WorkloadResultScope}},
		{TenantID: "payments", Audience: domain.WorkloadWorkerAudience, Scopes: []string{domain.WorkloadClaimScope, domain.WorkloadNackScope, domain.WorkloadResultScope}, EventTypes: []string{"payments.events\nother"}},
		{TenantID: "payments", Audience: domain.WorkloadProducerAudience, Scopes: []string{domain.WorkloadAdminScope}, EventTypes: []string{"payments.events"}},
	} {
		_, err := service.UpsertBinding(context.Background(), domain.WorkloadBindingUpsertReq{
			Subject: testWorkloadSubject, Namespace: "code-admin", ServiceAccount: "code-admin-controller-queue",
			Grants: []domain.WorkloadGrant{grant},
		})
		if !errors.Is(err, domain.ErrInvalidArgument) {
			t.Fatalf("UpsertBinding(%#v) error = %v", grant, err)
		}
	}
}

func TestWorkloadBindingRevocationBlocksNewExchangesImmediately(t *testing.T) {
	_, privatePEM := workloadTestKey(t)
	repo := &memoryWorkloadBindingRepo{}
	service := NewWorkloadIdentityService(repo, validWorkloadVerifier(), "https://tikti.example.com", privatePEM, "kid", time.Minute)
	bindingReq := domain.WorkloadBindingUpsertReq{
		Subject: testWorkloadSubject, Namespace: "code-admin", ServiceAccount: "code-admin-controller-queue",
		Grants: []domain.WorkloadGrant{{TenantID: "payments", Audience: domain.WorkloadTargetAudience, Scopes: []string{domain.WorkloadAdminScope}}},
	}
	if _, err := service.UpsertBinding(context.Background(), bindingReq); err != nil {
		t.Fatalf("UpsertBinding() error = %v", err)
	}
	if _, err := service.Exchange(context.Background(), validWorkloadExchangeRequest()); err != nil {
		t.Fatalf("Exchange() before revocation error = %v", err)
	}
	if _, err := service.RevokeBinding(context.Background(), domain.WorkloadBindingRevokeReq{Subject: testWorkloadSubject}); err != nil {
		t.Fatalf("RevokeBinding() error = %v", err)
	}
	if _, err := service.Exchange(context.Background(), validWorkloadExchangeRequest()); !errors.Is(err, domain.ErrWorkloadBindingDenied) {
		t.Fatalf("Exchange() after revocation error = %v", err)
	}
}

func TestWorkloadIdentityExchangeHandlesTimeoutAndConcurrency(t *testing.T) {
	_, privatePEM := workloadTestKey(t)
	t.Run("timeout", func(t *testing.T) {
		service := NewWorkloadIdentityService(&memoryWorkloadBindingRepo{binding: validWorkloadBinding()}, &fakeWorkloadVerifier{wait: true}, "https://tikti.example.com", privatePEM, "kid", time.Minute)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		if _, err := service.Exchange(ctx, validWorkloadExchangeRequest()); !errors.Is(err, domain.ErrWorkloadIdentityUnavailable) {
			t.Fatalf("timeout Exchange() error = %v", err)
		}
	})

	t.Run("concurrent", func(t *testing.T) {
		service := NewWorkloadIdentityService(&memoryWorkloadBindingRepo{binding: validWorkloadBinding()}, validWorkloadVerifier(), "https://tikti.example.com", privatePEM, "kid", time.Minute)
		const workers = 32
		var wait sync.WaitGroup
		errorsCh := make(chan error, workers)
		for range workers {
			wait.Add(1)
			go func() {
				defer wait.Done()
				response, err := service.Exchange(context.Background(), validWorkloadExchangeRequest())
				if err != nil || response.AccessToken == "" {
					errorsCh <- err
				}
			}()
		}
		wait.Wait()
		close(errorsCh)
		for err := range errorsCh {
			t.Errorf("concurrent Exchange() error = %v", err)
		}
	})
}

func validWorkloadVerifier() *fakeWorkloadVerifier {
	return &fakeWorkloadVerifier{subject: domain.WorkloadSubject{
		Subject: testWorkloadSubject, Namespace: "code-admin", ServiceAccount: "code-admin-controller-queue",
	}}
}

func validWorkloadBinding() *domain.WorkloadBinding {
	return &domain.WorkloadBinding{
		Subject: testWorkloadSubject, Namespace: "code-admin", ServiceAccount: "code-admin-controller-queue",
		Grants: []domain.WorkloadGrant{{TenantID: "payments", Audience: domain.WorkloadTargetAudience, Scopes: []string{domain.WorkloadAdminScope}}},
	}
}

func validWorkloadExchangeRequest() domain.WorkloadTokenExchangeReq {
	return domain.WorkloadTokenExchangeReq{
		SubjectToken: "projected-service-account-jwt", SubjectTokenType: domain.WorkloadSubjectTokenType,
		Audience: domain.WorkloadTargetAudience, Scopes: []string{domain.WorkloadAdminScope}, TenantID: "payments",
	}
}

func workloadTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}
