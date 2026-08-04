package workloadidentity

import (
	"context"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// TokenVerifier is the minimal verifier contract composed by MultiIssuerVerifier.
type TokenVerifier interface {
	Verify(context.Context, string) (domain.WorkloadSubject, error)
}

// MultiIssuerVerifier dispatches a projected token only to the verifier whose
// explicitly configured issuer matches its unverified iss claim. The selected
// verifier still performs signature, audience, expiration, and subject checks.
type MultiIssuerVerifier struct {
	byIssuer map[string]TokenVerifier
}

func NewMultiIssuerVerifier(byIssuer map[string]TokenVerifier) (*MultiIssuerVerifier, error) {
	if len(byIssuer) == 0 || len(byIssuer) > 17 {
		return nil, domain.ErrWorkloadIdentityUnavailable
	}
	trusted := make(map[string]TokenVerifier, len(byIssuer))
	for rawIssuer, verifier := range byIssuer {
		issuer := strings.TrimSpace(rawIssuer)
		if issuer == "" || verifier == nil {
			return nil, domain.ErrWorkloadIdentityUnavailable
		}
		if _, duplicate := trusted[issuer]; duplicate {
			return nil, domain.ErrWorkloadIdentityUnavailable
		}
		trusted[issuer] = verifier
	}
	return &MultiIssuerVerifier{byIssuer: trusted}, nil
}

func (v *MultiIssuerVerifier) Verify(ctx context.Context, tokenValue string) (domain.WorkloadSubject, error) {
	if v == nil || len(tokenValue) == 0 || len(tokenValue) > 64<<10 {
		return domain.WorkloadSubject{}, domain.ErrWorkloadTokenInvalid
	}
	claims := jwt.MapClaims{}
	token, _, err := jwt.NewParser().ParseUnverified(tokenValue, claims)
	if err != nil || token == nil || token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
		return domain.WorkloadSubject{}, domain.ErrWorkloadTokenInvalid
	}
	issuer, err := claims.GetIssuer()
	if err != nil {
		return domain.WorkloadSubject{}, domain.ErrWorkloadTokenInvalid
	}
	verifier := v.byIssuer[strings.TrimSpace(issuer)]
	if verifier == nil {
		return domain.WorkloadSubject{}, domain.ErrWorkloadTokenInvalid
	}
	return verifier.Verify(ctx, tokenValue)
}
