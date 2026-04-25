package saml

import (
	"context"
	"fmt"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// IDTokenIssuer is the minimal interface needed from the existing token issuer
// to produce HS256 idTokens with optional AMR claims.
type IDTokenIssuer interface {
	IssueIDTokenWithAMR(u *domain.User, amr []string) (string, int, error)
}

// sessionBridgeAuth implements SessionBridge by looking up (or upserting) the
// user via the repository and delegating token creation to the existing HS256
// idToken issuer.
type sessionBridgeAuth struct {
	repo   repository.UserRepository
	issuer IDTokenIssuer
}

// NewSessionBridge constructs a SessionBridge backed by the given repository
// and idToken issuer.
func NewSessionBridge(repo repository.UserRepository, issuer IDTokenIssuer) SessionBridge {
	return &sessionBridgeAuth{repo: repo, issuer: issuer}
}

// Issue implements SessionBridge. It upserts the SAML-authenticated user and
// issues an HS256 idToken that includes the amr claim from the input.
func (b *sessionBridgeAuth) Issue(ctx context.Context, in IssueInput) (string, error) {
	u, _, err := b.repo.UpsertFromSAML(
		ctx,
		in.TenantID,
		in.ExternalSubject,
		in.Email,
		in.Name,
		in.Roles,
		domain.MergeStrategyEmail,
	)
	if err != nil {
		return "", fmt.Errorf("session bridge: upsert: %w", err)
	}

	// Set the tenant ID on the in-memory copy (returned by value from
	// UpsertFromSAML) so the idToken includes the correct tid claim.
	tid := in.TenantID
	if tid != "" {
		u.CompanyId = &tid
	}

	signed, _, err := b.issuer.IssueIDTokenWithAMR(&u, in.AMR)
	if err != nil {
		return "", fmt.Errorf("session bridge: issue id token: %w", err)
	}
	return signed, nil
}
