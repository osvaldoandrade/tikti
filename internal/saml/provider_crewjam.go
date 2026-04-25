package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"

	crewjamsaml "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// CrewjamProvider implements Provider using the crewjam/saml library.
type CrewjamProvider struct {
	EntityID string
	ACSURL   string
	SLOURL   string
	Key      *rsa.PrivateKey
	Cert     *x509.Certificate
}

// BuildAuthnRequest produces a deflate-compressed, base64-encoded,
// RSA-SHA256-signed redirect URL per HLD §9.1.
func (p *CrewjamProvider) BuildAuthnRequest(_ context.Context, in BuildAuthnRequestInput) (*AuthnRequest, error) {
	acsURL, err := url.Parse(in.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("saml: parse ACS URL: %w", err)
	}

	nameIDFormat := crewjamsaml.EmailAddressNameIDFormat
	if in.NameIDFormat != "" {
		nameIDFormat = crewjamsaml.NameIDFormat(in.NameIDFormat)
	}

	// Build IdP metadata descriptor so crewjam knows where to send the request.
	idpMeta := &crewjamsaml.EntityDescriptor{
		EntityID: in.IdP.EntityID,
		IDPSSODescriptors: []crewjamsaml.IDPSSODescriptor{
			{
				SingleSignOnServices: []crewjamsaml.Endpoint{
					{
						Binding:  crewjamsaml.HTTPRedirectBinding,
						Location: in.IdP.SSOURL,
					},
				},
			},
		},
	}

	// Populate IdP signing certs into the descriptor so crewjam can verify.
	if len(in.IdP.SigningCerts) > 0 {
		kds := make([]crewjamsaml.KeyDescriptor, 0, len(in.IdP.SigningCerts))
		for _, raw := range in.IdP.SigningCerts {
			kds = append(kds, crewjamsaml.KeyDescriptor{
				Use: "signing",
				KeyInfo: crewjamsaml.KeyInfo{
					X509Data: crewjamsaml.X509Data{
						X509Certificates: []crewjamsaml.X509Certificate{
							{Data: base64.StdEncoding.EncodeToString(raw)},
						},
					},
				},
			})
		}
		idpMeta.IDPSSODescriptors[0].KeyDescriptors = kds
	}

	var forceAuthn *bool
	if in.ForceAuthn {
		t := true
		forceAuthn = &t
	}

	sp := crewjamsaml.ServiceProvider{
		EntityID:          p.EntityID,
		AcsURL:            *acsURL,
		Key:               p.Key,
		Certificate:       p.Cert,
		IDPMetadata:       idpMeta,
		AuthnNameIDFormat: nameIDFormat,
		ForceAuthn:        forceAuthn,
		SignatureMethod:   dsig.RSASHA256SignatureMethod,
	}

	req, err := sp.MakeAuthenticationRequest(
		in.IdP.SSOURL,
		crewjamsaml.HTTPRedirectBinding,
		crewjamsaml.HTTPPostBinding,
	)
	if err != nil {
		return nil, fmt.Errorf("saml: make authn request: %w", err)
	}

	// Override the library-generated ID with the caller-supplied one.
	if in.RequestID != "" {
		req.ID = "_" + in.RequestID
	}
	if !in.IssueInstant.IsZero() {
		req.IssueInstant = in.IssueInstant.UTC()
	}

	redirectURL, err := req.Redirect(in.RelayState, &sp)
	if err != nil {
		return nil, fmt.Errorf("saml: redirect URL: %w", err)
	}

	return &AuthnRequest{
		ID:          req.ID,
		RedirectURL: redirectURL.String(),
	}, nil
}

// ValidateResponse is not yet implemented.
func (p *CrewjamProvider) ValidateResponse(_ context.Context, _ ValidateResponseInput) (*VerifiedAssertion, error) {
	return nil, fmt.Errorf("saml: ValidateResponse not implemented")
}

// BuildLogoutRequest is not yet implemented.
func (p *CrewjamProvider) BuildLogoutRequest(_ context.Context, _ BuildLogoutRequestInput) (*LogoutRequest, error) {
	return nil, fmt.Errorf("saml: BuildLogoutRequest not implemented")
}

// ValidateLogoutMessage is not yet implemented.
func (p *CrewjamProvider) ValidateLogoutMessage(_ context.Context, _ ValidateLogoutInput) (*VerifiedLogout, error) {
	return nil, fmt.Errorf("saml: ValidateLogoutMessage not implemented")
}

// SPMetadata is not yet implemented.
func (p *CrewjamProvider) SPMetadata(_ context.Context) ([]byte, error) {
	return nil, fmt.Errorf("saml: SPMetadata not implemented")
}

// ParseIdPMetadata is not yet implemented.
func (p *CrewjamProvider) ParseIdPMetadata(_ context.Context, _ []byte) (*IdPRecord, error) {
	return nil, fmt.Errorf("saml: ParseIdPMetadata not implemented")
}
