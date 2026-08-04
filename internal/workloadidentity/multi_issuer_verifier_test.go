package workloadidentity

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type recordingTokenVerifier struct {
	called  bool
	want    string
	subject domain.WorkloadSubject
	err     error
}

func (v *recordingTokenVerifier) Verify(_ context.Context, token string) (domain.WorkloadSubject, error) {
	v.called = true
	if token != v.want {
		return domain.WorkloadSubject{}, domain.ErrWorkloadTokenInvalid
	}
	return v.subject, v.err
}

func TestMultiIssuerVerifierDispatchesOnlyToConfiguredIssuer(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://cluster-b.example"})
	tokenString, err := token.SignedString(verifierTestKey(t))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	a := &recordingTokenVerifier{}
	b := &recordingTokenVerifier{want: tokenString, subject: domain.WorkloadSubject{Subject: "system:serviceaccount:workload-team:api"}}
	verifier, err := NewMultiIssuerVerifier(map[string]TokenVerifier{
		"https://cluster-a.example": a,
		"https://cluster-b.example": b,
	})
	if err != nil {
		t.Fatalf("NewMultiIssuerVerifier() error = %v", err)
	}
	subject, err := verifier.Verify(context.Background(), tokenString)
	if err != nil || subject.Subject != b.subject.Subject {
		t.Fatalf("Verify() subject=%#v error=%v", subject, err)
	}
	if a.called || !b.called {
		t.Fatalf("issuer dispatch called a=%t b=%t", a.called, b.called)
	}
}

func TestMultiIssuerVerifierRejectsUnknownIssuerAndAlgorithm(t *testing.T) {
	configured := &recordingTokenVerifier{}
	verifier, err := NewMultiIssuerVerifier(map[string]TokenVerifier{"https://cluster.example": configured})
	if err != nil {
		t.Fatal(err)
	}
	for _, claims := range []jwt.MapClaims{
		{"iss": "https://unknown.example"},
		{},
	} {
		token, signErr := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(verifierTestKey(t))
		if signErr != nil {
			t.Fatal(signErr)
		}
		if _, verifyErr := verifier.Verify(context.Background(), token); !errors.Is(verifyErr, domain.ErrWorkloadTokenInvalid) {
			t.Fatalf("Verify() error = %v", verifyErr)
		}
	}
	unsigned, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": "https://cluster.example"}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := verifier.Verify(context.Background(), unsigned); !errors.Is(err, domain.ErrWorkloadTokenInvalid) {
		t.Fatalf("unsigned Verify() error = %v", err)
	}
	if configured.called {
		t.Fatal("configured verifier was called for an untrusted token")
	}
}
