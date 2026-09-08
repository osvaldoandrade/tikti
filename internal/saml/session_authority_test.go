package saml

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type sessionAuthorityTokenStub struct {
	claims       jwt.MapClaims
	validateErr  error
	revokeErr    error
	validatedRaw string
	issuer       string
	audience     string
	revokedEmail string
	revokeScope  string
}

func (s *sessionAuthorityTokenStub) ValidateIDToken(
	_ context.Context,
	raw, issuer, audience string,
) (jwt.MapClaims, error) {
	s.validatedRaw, s.issuer, s.audience = raw, issuer, audience
	return s.claims, s.validateErr
}

func (s *sessionAuthorityTokenStub) RevokeTokens(
	_ context.Context,
	email, _, scope string,
) (*domain.RevokeResp, error) {
	s.revokedEmail, s.revokeScope = email, scope
	if s.revokeErr != nil {
		return nil, s.revokeErr
	}
	return &domain.RevokeResp{}, nil
}

func TestSessionAuthorityValidatesCurrentSAMLIdentity(t *testing.T) {
	tokens := &sessionAuthorityTokenStub{claims: jwt.MapClaims{
		"sub": "user-001", "email": "user@example.com", "tid": "t-001",
		"amr": []interface{}{"pwd", "saml"},
	}}
	authority := NewSessionAuthority(tokens, "https://identity.example.com", "tikti")

	identity, err := authority.Validate(context.Background(), "signed-current-token")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if identity != (SessionIdentity{Subject: "user-001", Email: "user@example.com", TenantID: "t-001"}) {
		t.Fatalf("identity = %#v", identity)
	}
	if tokens.validatedRaw != "signed-current-token" ||
		tokens.issuer != "https://identity.example.com" || tokens.audience != "tikti" {
		t.Fatalf("validation boundary = raw %q issuer %q audience %q", tokens.validatedRaw, tokens.issuer, tokens.audience)
	}
}

func TestSessionAuthorityRejectsNonSAMLOrIncompleteIdentity(t *testing.T) {
	tests := map[string]jwt.MapClaims{
		"missing subject": {"email": "user@example.com", "tid": "t-001", "amr": []string{"saml"}},
		"missing email":   {"sub": "user-001", "tid": "t-001", "amr": []string{"saml"}},
		"missing tenant":  {"sub": "user-001", "email": "user@example.com", "amr": []string{"saml"}},
		"password only":   {"sub": "user-001", "email": "user@example.com", "tid": "t-001", "amr": []string{"pwd"}},
	}
	for name, claims := range tests {
		t.Run(name, func(t *testing.T) {
			authority := NewSessionAuthority(&sessionAuthorityTokenStub{claims: claims}, "issuer", "audience")
			if _, err := authority.Validate(context.Background(), "token"); !errors.Is(err, ErrSessionAuthority) {
				t.Fatalf("Validate error = %v, want ErrSessionAuthority", err)
			}
		})
	}
}

func TestSessionAuthorityFailsClosedAndRevokesGlobally(t *testing.T) {
	tokens := &sessionAuthorityTokenStub{validateErr: errors.New("expired")}
	authority := NewSessionAuthority(tokens, "issuer", "audience")
	if _, err := authority.Validate(context.Background(), "expired-token"); !errors.Is(err, ErrSessionAuthority) {
		t.Fatalf("Validate error = %v, want ErrSessionAuthority", err)
	}

	if err := authority.Revoke(context.Background(), "user-1", "user@example.com"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if tokens.revokedEmail != "user@example.com" || tokens.revokeScope != "global" {
		t.Fatalf("revocation = email %q scope %q", tokens.revokedEmail, tokens.revokeScope)
	}

	tokens.revokeErr = errors.New("redis unavailable")
	if err := authority.Revoke(context.Background(), "user-1", "user@example.com"); !errors.Is(err, ErrSessionAuthority) {
		t.Fatalf("Revoke error = %v, want ErrSessionAuthority", err)
	}
}
