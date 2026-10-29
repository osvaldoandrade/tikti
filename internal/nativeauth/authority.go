package nativeauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/osvaldoandrade/tikti/internal/nativepolicy"
)

var (
	ErrNoSession    = errors.New("native SAML browser session required")
	ErrAccessDenied = errors.New("native application access denied")
)

type Identity struct {
	Subject          string
	Email            string
	IdentityTenantID string
	TenantName       string
	TokenVersion     int64
	SessionExpiresAt int64
	Scopes           []string
}

func (i Identity) Fingerprint() string {
	digest := sha256.Sum256([]byte("native-identity-v1\x00" + i.Subject + "\x00" + i.IdentityTenantID + "\x00" + strings.ToLower(i.Email)))
	return hex.EncodeToString(digest[:])
}

type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Email       string `json:"email"`
}

// Authority re-evaluates mutable identity, tenant, audience and explicit roles.
// Neither transport input nor persisted grant data defines application policy.
type Authority interface {
	BrowserIdentity(context.Context, string, nativepolicy.Client) (Identity, error)
	IssueNativeToken(context.Context, nativepolicy.Client, Grant) (Token, error)
}
