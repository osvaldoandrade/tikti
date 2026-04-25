package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
)

// samlTestOptions holds the parameters for the "saml test" command.
type samlTestOptions struct {
	TID    string
	Email  string
	ACSURL string
}

// buildTestAuthnURL looks up the IdP for the given tenant and builds a signed
// AuthnRequest redirect URL with RelayState "/debug/ok". The returned URL can
// be opened in a browser for end-to-end IdP validation.
func buildTestAuthnURL(ctx context.Context, store saml.Store, provider saml.Provider, opts samlTestOptions) (*saml.AuthnRequest, error) {
	if opts.TID == "" {
		return nil, fmt.Errorf("--tid is required")
	}
	if opts.Email == "" {
		return nil, fmt.Errorf("--email is required")
	}

	idp, err := store.GetIdP(ctx, opts.TID)
	if err != nil {
		return nil, fmt.Errorf("get IdP for tenant %q: %w", opts.TID, err)
	}

	// Generate a random request ID (20 random bytes, hex-encoded).
	var reqIDBytes [20]byte
	if _, err := rand.Read(reqIDBytes[:]); err != nil {
		return nil, fmt.Errorf("generate request ID: %w", err)
	}
	reqID := hex.EncodeToString(reqIDBytes[:])

	return provider.BuildAuthnRequest(ctx, saml.BuildAuthnRequestInput{
		TenantID:     opts.TID,
		IdP:          idp,
		RelayState:   "/debug/ok",
		ACSURL:       opts.ACSURL,
		RequestID:    reqID,
		IssueInstant: time.Now().UTC(),
	})
}
