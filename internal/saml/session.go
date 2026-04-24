package saml

import (
	"context"
	"time"
)

// SessionBridge converts a verified SAML assertion into a local idToken,
// decoupling the SAML protocol layer from the session-issuance layer.
type SessionBridge interface {
	Issue(ctx context.Context, in IssueInput) (idToken string, err error)
}

// IssueInput carries the claims extracted from a verified SAML assertion
// that are needed to issue a local idToken.
type IssueInput struct {
	TenantID        string
	Subject         string
	ExternalSubject string
	Email           string
	Name            string
	Roles           []string
	AMR             []string // ["saml"]
	AuthnInstant    time.Time
}
