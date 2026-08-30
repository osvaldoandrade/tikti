package storagests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type fakeProjectedVerifier struct {
	identity domain.WorkloadSubject
	err      error
	block    <-chan struct{}
	entered  chan<- struct{}
}

func (f fakeProjectedVerifier) Verify(ctx context.Context, _ string) (domain.WorkloadSubject, error) {
	if f.entered != nil {
		select {
		case f.entered <- struct{}{}:
		case <-ctx.Done():
			return domain.WorkloadSubject{}, ctx.Err()
		}
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return domain.WorkloadSubject{}, ctx.Err()
		}
	}
	return f.identity, f.err
}

type fixedAssertionSigner struct{}

func (fixedAssertionSigner) SignServiceAssertion(time.Time) (string, error) {
	return "service-assertion", nil
}

func (fixedAssertionSigner) SignMinIOAssertion(time.Time, Approval) (string, error) {
	return "minio-assertion", nil
}

type fixedAuthorizer struct{ decision AuthorizationDecision }

func (f fixedAuthorizer) Authorize(context.Context, AuthorizationRequest, string) (AuthorizationDecision, error) {
	return f.decision, nil
}

type fixedCredentialIssuer struct{ credentials Credentials }

func (f fixedCredentialIssuer) Exchange(context.Context, string, int) (Credentials, error) {
	return f.credentials, nil
}

type fakeAssertionSigner struct {
	serviceToken, minioToken string
	err                      error
	approval                 Approval
}

func (f *fakeAssertionSigner) SignServiceAssertion(time.Time) (string, error) {
	return f.serviceToken, f.err
}

func (f *fakeAssertionSigner) SignMinIOAssertion(_ time.Time, approval Approval) (string, error) {
	f.approval = approval
	return f.minioToken, f.err
}

type fakeAuthorizer struct {
	decision AuthorizationDecision
	err      error
	request  AuthorizationRequest
	token    string
}

func (f *fakeAuthorizer) Authorize(_ context.Context, request AuthorizationRequest, token string) (AuthorizationDecision, error) {
	f.request, f.token = request, token
	return f.decision, f.err
}

type fakeCredentialIssuer struct {
	credentials Credentials
	err         error
	token       string
	duration    int
}

func (f *fakeCredentialIssuer) Exchange(_ context.Context, token string, duration int) (Credentials, error) {
	f.token, f.duration = token, duration
	return f.credentials, f.err
}

func TestServiceBrokersOnlyAfterVerifiedCurrentAuthorization(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	identity := storageTestIdentity()
	signer := &fakeAssertionSigner{serviceToken: "service-assertion", minioToken: "minio-assertion"}
	authorizer := &fakeAuthorizer{decision: allowDecision(ReadWriteAccess)}
	issuer := &fakeCredentialIssuer{credentials: Credentials{
		AccessKeyID: "MINIOACCESSKEY123456", SecretAccessKey: "minio-secret-access-key",
		SessionToken: "minio-session-token", Expiration: now.Add(15 * time.Minute),
	}}
	service, err := NewService(fakeProjectedVerifier{identity: identity}, signer, authorizer, issuer, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	request, parseErr := ParseRequest(formRequest(t, "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn="+urlEscape(testRoleARN)+"&WebIdentityToken="+urlEscape(testJWT)), testAccountID)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	result, stsErr := service.Exchange(context.Background(), request, "request-storage-1")
	if stsErr != nil || result.Credentials.AccessKeyID == "" || result.Subject != identity.Subject || result.Provider != identity.Issuer {
		t.Fatalf("result=%#v error=%#v", result, stsErr)
	}
	digest := sha256Hex(testJWT)
	if authorizer.token != "service-assertion" || authorizer.request.TokenSHA256 != digest ||
		authorizer.request.Issuer != identity.Issuer || authorizer.request.ClusterRef != identity.ClusterRef ||
		authorizer.request.Namespace != identity.Namespace || authorizer.request.ServiceAccount != identity.ServiceAccount ||
		authorizer.request.RequestID != "request-storage-1" || issuer.token != "minio-assertion" || issuer.duration != 900 ||
		signer.approval.Decision.Binding.UID != "binding-uid" {
		t.Fatalf("authorizer=%#v signer=%#v issuer=%#v", authorizer, signer, issuer)
	}
}

func TestServiceFailsClosedAcrossIdentityAuthorizationAndProviderFailures(t *testing.T) {
	t.Parallel()
	request := Request{
		RoleARN: testRoleARN, Role: Role{AccountID: testAccountID, TenantID: "payments", Namespace: "workload-payments", BindingName: "payments-api-invoices"},
		RoleSessionName: "payments-api", WebIdentityToken: testJWT, DurationSeconds: 900,
	}
	for _, test := range []struct {
		name           string
		identity       domain.WorkloadSubject
		verifyErr      error
		authorizerErr  error
		decision       AuthorizationDecision
		providerErr    error
		want           Code
		providerCalled bool
	}{
		{name: "invalid token", verifyErr: domain.ErrWorkloadTokenInvalid, decision: allowDecision(ReadOnlyAccess), want: CodeInvalidIdentityToken},
		{name: "JWKS unavailable", verifyErr: domain.ErrWorkloadIdentityUnavailable, decision: allowDecision(ReadOnlyAccess), want: CodeIDPCommunicationError},
		{name: "foreign namespace", identity: func() domain.WorkloadSubject {
			value := storageTestIdentity()
			value.Namespace = "workload-other"
			value.Subject = "system:serviceaccount:workload-other:payments-api"
			return value
		}(), decision: allowDecision(ReadOnlyAccess), want: CodeAccessDenied},
		{name: "authorizer unavailable", identity: storageTestIdentity(), authorizerErr: ErrDependencyUnavailable, decision: allowDecision(ReadOnlyAccess), want: CodeIDPCommunicationError},
		{name: "authorizer invalid", identity: storageTestIdentity(), authorizerErr: ErrInvalidDependencyResponse, decision: allowDecision(ReadOnlyAccess), want: CodeInternalFailure},
		{name: "canonical deny", identity: storageTestIdentity(), decision: AuthorizationDecision{SchemaVersion: ObjectStorageVersion, Reason: "BindingNotReady"}, want: CodeAccessDenied},
		{name: "provider unavailable", identity: storageTestIdentity(), decision: allowDecision(ReadOnlyAccess), providerErr: ErrDependencyUnavailable, want: CodeServiceUnavailable, providerCalled: true},
		{name: "provider invalid", identity: storageTestIdentity(), decision: allowDecision(ReadOnlyAccess), providerErr: ErrInvalidDependencyResponse, want: CodeInternalFailure, providerCalled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			signer := &fakeAssertionSigner{serviceToken: "service-assertion", minioToken: "minio-assertion"}
			authorizer := &fakeAuthorizer{decision: test.decision, err: test.authorizerErr}
			provider := &fakeCredentialIssuer{err: test.providerErr}
			service, err := NewService(fakeProjectedVerifier{identity: test.identity, err: test.verifyErr}, signer, authorizer, provider, 8, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, stsErr := service.Exchange(context.Background(), request, "request-storage-1")
			if stsErr == nil || stsErr.Code != test.want || (provider.token != "") != test.providerCalled {
				t.Fatalf("error=%#v provider=%#v", stsErr, provider)
			}
		})
	}
}

func TestServiceBoundsConcurrencyWithoutQueueingSecrets(t *testing.T) {
	t.Parallel()
	blocked := make(chan struct{})
	service, err := NewService(
		fakeProjectedVerifier{identity: storageTestIdentity(), block: blocked},
		&fakeAssertionSigner{serviceToken: "service", minioToken: "minio"},
		&fakeAuthorizer{decision: allowDecision(ReadOnlyAccess)}, &fakeCredentialIssuer{}, 1, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Role: Role{TenantID: "payments", Namespace: "workload-payments"}, WebIdentityToken: testJWT, DurationSeconds: 900}
	request.RoleARN = testRoleARN
	request.Role.AccountID = testAccountID
	request.Role.BindingName = "payments-api-invoices"
	var wait sync.WaitGroup
	wait.Add(1)
	go func() { defer wait.Done(); _, _ = service.Exchange(context.Background(), request, "request-1") }()
	deadline := time.Now().Add(time.Second)
	for len(service.inflight) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, stsErr := service.Exchange(context.Background(), request, "request-2"); stsErr == nil || stsErr.Code != CodeThrottling {
		t.Fatalf("overload error = %#v", stsErr)
	}
	close(blocked)
	wait.Wait()
}

func TestServiceShedsTwoTimesConcurrencyCeilingAndRecovers(t *testing.T) {
	t.Parallel()
	const ceiling = 8
	const requests = 2 * ceiling
	now := time.Unix(1_800_000_000, 0).UTC()
	blocked := make(chan struct{})
	entered := make(chan struct{}, ceiling)
	service, err := NewService(
		fakeProjectedVerifier{
			identity: storageTestIdentity(), block: blocked, entered: entered,
		},
		fixedAssertionSigner{},
		fixedAuthorizer{decision: allowDecision(ReadOnlyAccess)},
		fixedCredentialIssuer{credentials: Credentials{
			AccessKeyID: "MINIOACCESSKEY123456", SecretAccessKey: "minio-secret-access-key",
			SessionToken: "minio-session-token", Expiration: now.Add(15 * time.Minute),
		}},
		ceiling,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	request := Request{
		RoleARN: testRoleARN,
		Role: Role{
			AccountID: testAccountID, TenantID: "payments", Namespace: "workload-payments",
			BindingName: "payments-api-invoices",
		},
		RoleSessionName: "payments-api", WebIdentityToken: testJWT, DurationSeconds: 900,
	}
	start := make(chan struct{})
	results := make(chan *Error, requests)
	var wait sync.WaitGroup
	for index := 0; index < requests; index++ {
		wait.Add(1)
		go func(requestIndex int) {
			defer wait.Done()
			<-start
			_, exchangeErr := service.Exchange(
				t.Context(), request, fmt.Sprintf("request-load-%02d", requestIndex),
			)
			results <- exchangeErr
		}(index)
	}
	close(start)

	for index := 0; index < ceiling; index++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d requests entered the dependency brownout", index)
		}
	}
	for index := 0; index < requests-ceiling; index++ {
		select {
		case exchangeErr := <-results:
			if exchangeErr == nil || exchangeErr.Code != CodeThrottling {
				t.Fatalf("overload result %d = %#v", index, exchangeErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("overload result %d did not fail fast", index)
		}
	}

	close(blocked)
	for index := 0; index < ceiling; index++ {
		select {
		case exchangeErr := <-results:
			if exchangeErr != nil {
				t.Fatalf("admitted result %d = %#v", index, exchangeErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("admitted result %d did not recover", index)
		}
	}
	wait.Wait()

	if _, exchangeErr := service.Exchange(t.Context(), request, "request-recovered"); exchangeErr != nil {
		t.Fatalf("service did not recover after dependency release: %#v", exchangeErr)
	}
}

func storageTestIdentity() domain.WorkloadSubject {
	return domain.WorkloadSubject{
		Subject: "system:serviceaccount:workload-payments:payments-api", Issuer: "https://cluster.example.com",
		ClusterRef: "code-cloud", Namespace: "workload-payments", ServiceAccount: "payments-api",
	}
}

func urlEscape(value string) string { return url.QueryEscape(value) }

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
