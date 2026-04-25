package saml

import (
	"context"
	"time"
)

// Provider abstracts the SAML protocol library. 6 methods, interface
// segregation keeps the dependency replaceable (DIP).
type Provider interface {
	BuildAuthnRequest(ctx context.Context, in BuildAuthnRequestInput) (*AuthnRequest, error)
	ValidateResponse(ctx context.Context, in ValidateResponseInput) (*VerifiedAssertion, error)
	BuildLogoutRequest(ctx context.Context, in BuildLogoutRequestInput) (*LogoutRequest, error)
	ValidateLogoutMessage(ctx context.Context, in ValidateLogoutInput) (*VerifiedLogout, error)
	SPMetadata(ctx context.Context) ([]byte, error)
	ParseIdPMetadata(ctx context.Context, raw []byte) (*IdPRecord, error)
}

// BuildAuthnRequestInput carries the parameters needed to build a SAML AuthnRequest.
type BuildAuthnRequestInput struct {
	TenantID     string
	IdP          IdPRecord
	RelayState   string
	ACSURL       string
	RequestID    string // caller-supplied, 20 random bytes hex
	IssueInstant time.Time
	ForceAuthn   bool
	NameIDFormat string
}

// AuthnRequest is the output of BuildAuthnRequest.
type AuthnRequest struct {
	ID          string
	RedirectURL string // fully signed, ready to 302
}

// ValidateResponseInput carries the parameters needed to validate a SAML Response.
type ValidateResponseInput struct {
	TenantID             string
	IdP                  IdPRecord
	RawBase64            string
	RelayState           string
	Now                  time.Time
	ExpectedInResponseTo string
	ClockSkew            time.Duration
}

// VerifiedAssertion is the validated output of a SAML Response.
type VerifiedAssertion struct {
	AssertionID    string
	NameID         string
	NameIDFormat   string
	SessionIndex   string
	NotOnOrAfter   time.Time
	Attributes     map[string][]string
	IssuerEntityID string
}

// IdPRecord holds the persisted metadata for an external Identity Provider.
type IdPRecord struct {
	TenantID        string
	EntityID        string
	SSOURL          string
	SLOURL          string
	SigningCerts    [][]byte
	EncryptionCerts [][]byte
	NameIDFormat    string
	AttributeMap    map[string][]string
	LastFetched     time.Time
}

// BuildLogoutRequestInput carries the parameters needed to build a SAML LogoutRequest.
type BuildLogoutRequestInput struct {
	TenantID     string
	IdP          IdPRecord
	NameID       string
	SessionIndex string
	RequestID    string
	IssueInstant time.Time
	NameIDFormat string
}

// LogoutRequest is the output of BuildLogoutRequest.
type LogoutRequest struct {
	ID          string
	RedirectURL string
}

// ValidateLogoutInput carries the parameters needed to validate an incoming
// SAML LogoutRequest or LogoutResponse.
type ValidateLogoutInput struct {
	TenantID   string
	IdP        IdPRecord
	RawMessage string
	Binding    string
}

// VerifiedLogout is the validated output of a SAML LogoutRequest or LogoutResponse.
type VerifiedLogout struct {
	NameID       string
	SessionIndex string
	IsResponse   bool
	Status       string
}
