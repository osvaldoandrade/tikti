package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
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

// BuildLogoutRequest produces a deflate-compressed, base64-encoded,
// RSA-SHA256-signed LogoutRequest redirect URL per HLD §12.
func (p *CrewjamProvider) BuildLogoutRequest(_ context.Context, in BuildLogoutRequestInput) (*LogoutRequest, error) {
	sloURL, err := url.Parse(p.SLOURL)
	if err != nil {
		return nil, fmt.Errorf("saml: parse SLO URL: %w", err)
	}

	nameIDFormat := crewjamsaml.EmailAddressNameIDFormat
	if in.NameIDFormat != "" {
		nameIDFormat = crewjamsaml.NameIDFormat(in.NameIDFormat)
	}

	// Build IdP metadata descriptor so crewjam knows the SLO endpoint.
	idpMeta := &crewjamsaml.EntityDescriptor{
		EntityID: in.IdP.EntityID,
		IDPSSODescriptors: []crewjamsaml.IDPSSODescriptor{
			{
				SSODescriptor: crewjamsaml.SSODescriptor{
					SingleLogoutServices: []crewjamsaml.Endpoint{
						{
							Binding:  crewjamsaml.HTTPRedirectBinding,
							Location: in.IdP.SLOURL,
						},
					},
				},
			},
		},
	}

	// Populate IdP signing certs into the descriptor.
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

	sp := crewjamsaml.ServiceProvider{
		EntityID:          p.EntityID,
		SloURL:            *sloURL,
		Key:               p.Key,
		Certificate:       p.Cert,
		IDPMetadata:       idpMeta,
		AuthnNameIDFormat: nameIDFormat,
		SignatureMethod:   dsig.RSASHA256SignatureMethod,
	}

	req, err := sp.MakeLogoutRequest(in.IdP.SLOURL, in.NameID)
	if err != nil {
		return nil, fmt.Errorf("saml: make logout request: %w", err)
	}

	// Override the library-generated ID with the caller-supplied one.
	if in.RequestID != "" {
		req.ID = "_" + in.RequestID
	}
	if !in.IssueInstant.IsZero() {
		req.IssueInstant = in.IssueInstant.UTC()
	}
	if in.SessionIndex != "" {
		req.SessionIndex = &crewjamsaml.SessionIndex{Value: in.SessionIndex}
	}

	redirectURL := req.Redirect("")
	return &LogoutRequest{
		ID:          req.ID,
		RedirectURL: redirectURL.String(),
	}, nil
}

// BuildLogoutResponse produces a signed SAML LogoutResponse for the HTTP-POST
// binding, acknowledging an IdP-initiated LogoutRequest per HLD §12.
func (p *CrewjamProvider) BuildLogoutResponse(_ context.Context, in BuildLogoutResponseInput) (*LogoutResponseResult, error) {
	sloURL, err := url.Parse(p.SLOURL)
	if err != nil {
		return nil, fmt.Errorf("saml: parse SLO URL: %w", err)
	}

	idpMeta := &crewjamsaml.EntityDescriptor{
		EntityID: in.IdP.EntityID,
		IDPSSODescriptors: []crewjamsaml.IDPSSODescriptor{
			{
				SSODescriptor: crewjamsaml.SSODescriptor{
					SingleLogoutServices: []crewjamsaml.Endpoint{
						{
							Binding:  crewjamsaml.HTTPPostBinding,
							Location: in.IdP.SLOURL,
						},
					},
				},
			},
		},
	}

	sp := crewjamsaml.ServiceProvider{
		EntityID:        p.EntityID,
		SloURL:          *sloURL,
		Key:             p.Key,
		Certificate:     p.Cert,
		IDPMetadata:     idpMeta,
		SignatureMethod: dsig.RSASHA256SignatureMethod,
	}

	resp, err := sp.MakeLogoutResponse(in.IdP.SLOURL, in.InResponseTo)
	if err != nil {
		return nil, fmt.Errorf("saml: make logout response: %w", err)
	}

	return &LogoutResponseResult{
		PostBody: resp.Post(""),
	}, nil
}

// ValidateLogoutMessage validates an incoming SAML LogoutRequest or LogoutResponse.
// It supports both HTTP-Redirect (deflate+base64) and HTTP-POST (base64) bindings.
func (p *CrewjamProvider) ValidateLogoutMessage(_ context.Context, in ValidateLogoutInput) (*VerifiedLogout, error) {
	var rawXML []byte
	var err error

	switch in.Binding {
	case crewjamsaml.HTTPRedirectBinding:
		compressed, err := base64.StdEncoding.DecodeString(in.RawMessage)
		if err != nil {
			return nil, fmt.Errorf("saml: base64 decode logout message: %w", err)
		}
		reader := flate.NewReader(bytes.NewReader(compressed))
		defer reader.Close()
		rawXML, err = io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("saml: deflate decompress logout message: %w", err)
		}
	case crewjamsaml.HTTPPostBinding, "":
		rawXML, err = base64.StdEncoding.DecodeString(in.RawMessage)
		if err != nil {
			return nil, fmt.Errorf("saml: base64 decode logout message: %w", err)
		}
	default:
		return nil, fmt.Errorf("saml: unsupported binding: %s", in.Binding)
	}

	// Detect root element type using a lightweight probe.
	var probe struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(rawXML, &probe); err != nil {
		return nil, fmt.Errorf("saml: parse logout message XML: %w", err)
	}

	switch probe.XMLName.Local {
	case "LogoutResponse":
		var resp crewjamsaml.LogoutResponse
		if err := xml.Unmarshal(rawXML, &resp); err != nil {
			return nil, fmt.Errorf("saml: unmarshal LogoutResponse: %w", err)
		}
		return &VerifiedLogout{
			IsResponse: true,
			Status:     resp.Status.StatusCode.Value,
		}, nil
	case "LogoutRequest":
		var req crewjamsaml.LogoutRequest
		if err := xml.Unmarshal(rawXML, &req); err != nil {
			return nil, fmt.Errorf("saml: unmarshal LogoutRequest: %w", err)
		}
		vl := &VerifiedLogout{
			IsResponse: false,
		}
		if req.NameID != nil {
			vl.NameID = req.NameID.Value
		}
		if req.SessionIndex != nil {
			vl.SessionIndex = req.SessionIndex.Value
		}
		return vl, nil
	default:
		return nil, fmt.Errorf("saml: unexpected root element: %s", probe.XMLName.Local)
	}
}

// SPMetadata is not yet implemented.
func (p *CrewjamProvider) SPMetadata(_ context.Context) ([]byte, error) {
	return nil, fmt.Errorf("saml: SPMetadata not implemented")
}

// ParseIdPMetadata is not yet implemented.
func (p *CrewjamProvider) ParseIdPMetadata(_ context.Context, _ []byte) (*IdPRecord, error) {
	return nil, fmt.Errorf("saml: ParseIdPMetadata not implemented")
}
