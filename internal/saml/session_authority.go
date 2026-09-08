package saml

import (
	"context"
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

var ErrSessionAuthority = errors.New("saml: invalid session authority")

type SessionIdentity struct {
	Subject  string
	Email    string
	TenantID string
}

type SessionAuthority interface {
	Validate(context.Context, string) (SessionIdentity, error)
	Revoke(context.Context, string, string) error
}

type IDTokenSubjectRevoker interface {
	RevokeIDTokenSubject(context.Context, string) error
}

type IDTokenAuthority interface {
	ValidateIDToken(context.Context, string, string, string) (jwt.MapClaims, error)
	RevokeTokens(context.Context, string, string, string) (*domain.RevokeResp, error)
}

type sessionTokenAuthority struct {
	tokens   IDTokenAuthority
	issuer   string
	audience string
}

func NewSessionAuthority(tokens IDTokenAuthority, issuer, audience string) SessionAuthority {
	return &sessionTokenAuthority{tokens: tokens, issuer: strings.TrimSpace(issuer), audience: strings.TrimSpace(audience)}
}

func (a *sessionTokenAuthority) Validate(ctx context.Context, raw string) (SessionIdentity, error) {
	if a == nil || a.tokens == nil || a.issuer == "" || a.audience == "" {
		return SessionIdentity{}, ErrSessionAuthority
	}
	claims, err := a.tokens.ValidateIDToken(ctx, raw, a.issuer, a.audience)
	if err != nil {
		return SessionIdentity{}, ErrSessionAuthority
	}
	identity := SessionIdentity{
		Subject:  claimString(claims, "sub"),
		Email:    claimString(claims, "email"),
		TenantID: claimString(claims, "tid"),
	}
	if identity.Subject == "" || identity.Email == "" || identity.TenantID == "" || !claimContains(claims, "amr", "saml") {
		return SessionIdentity{}, ErrSessionAuthority
	}
	return identity, nil
}

func (a *sessionTokenAuthority) Revoke(ctx context.Context, subject, email string) error {
	if a == nil || a.tokens == nil || strings.TrimSpace(email) == "" || strings.TrimSpace(subject) == "" {
		return ErrSessionAuthority
	}
	if revoker, ok := a.tokens.(IDTokenSubjectRevoker); ok {
		if err := revoker.RevokeIDTokenSubject(ctx, subject); err != nil {
			return ErrSessionAuthority
		}
		return nil
	}
	if _, err := a.tokens.RevokeTokens(ctx, email, "", "global"); err != nil {
		return ErrSessionAuthority
	}
	return nil
}

func claimString(claims jwt.MapClaims, name string) string {
	value, _ := claims[name].(string)
	return strings.TrimSpace(value)
}

func claimContains(claims jwt.MapClaims, name, expected string) bool {
	switch values := claims[name].(type) {
	case []interface{}:
		for _, value := range values {
			if text, ok := value.(string); ok && text == expected {
				return true
			}
		}
	case []string:
		for _, value := range values {
			if value == expected {
				return true
			}
		}
	}
	return false
}
