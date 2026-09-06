package saml

import (
	"context"
	"fmt"
	"strings"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/config"
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
	repo                   repository.UserRepository
	issuer                 IDTokenIssuer
	platformAdministrators map[string]struct{}
}

// SessionBridgeOption configures a SessionBridge without widening the default
// tenant-scoped SAML trust boundary.
type SessionBridgeOption func(*sessionBridgeAuth)

// WithPlatformAdministrators allows only the exact server-configured
// (tenantId, email) identities to receive platform ADMIN authority.
func WithPlatformAdministrators(administrators []config.SAMLPlatformAdministrator) SessionBridgeOption {
	configured := append([]config.SAMLPlatformAdministrator(nil), administrators...)
	return func(bridge *sessionBridgeAuth) {
		for _, administrator := range configured {
			key := platformAdministratorKey(administrator.TenantID, administrator.Email)
			if key != "" {
				bridge.platformAdministrators[key] = struct{}{}
			}
		}
	}
}

// NewSessionBridge constructs a SessionBridge backed by the given repository
// and idToken issuer.
func NewSessionBridge(repo repository.UserRepository, issuer IDTokenIssuer, options ...SessionBridgeOption) SessionBridge {
	bridge := &sessionBridgeAuth{
		repo: repo, issuer: issuer,
		platformAdministrators: make(map[string]struct{}),
	}
	for _, option := range options {
		if option != nil {
			option(bridge)
		}
	}
	return bridge
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

	// A tenant-controlled IdP can grant tenant administration, never the
	// platform-wide ADMIN tier. The sole exception is an exact principal named
	// by server-side configuration; persist it before issuing the token so token
	// exchange observes the same authority and fail closed if persistence fails.
	if b.isPlatformAdministrator(in.TenantID, in.Email, u) {
		u.Role = domain.RoleAdmin
		if err := b.repo.UpdateUser(ctx, &u); err != nil {
			return "", fmt.Errorf("session bridge: persist platform administrator: %w", err)
		}
	} else if u.Role == domain.RoleAdmin {
		u.Role = domain.RoleCompanyAdmin
	}

	signed, _, err := b.issuer.IssueIDTokenWithAMR(&u, in.AMR)
	if err != nil {
		return "", fmt.Errorf("session bridge: issue id token: %w", err)
	}
	return signed, nil
}

func (b *sessionBridgeAuth) isPlatformAdministrator(tenantID, email string, user domain.User) bool {
	if b == nil || user.AuthSource != domain.AuthSourceSAML || !strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(user.Email)) {
		return false
	}
	_, configured := b.platformAdministrators[platformAdministratorKey(tenantID, email)]
	return configured
}

func platformAdministratorKey(tenantID, email string) string {
	tenantID = strings.TrimSpace(tenantID)
	email = strings.ToLower(strings.TrimSpace(email))
	if tenantID == "" || email == "" {
		return ""
	}
	return tenantID + "\x00" + email
}
