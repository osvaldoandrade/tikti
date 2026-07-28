package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
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

// ValidateResponse verifies a SAML HTTP-POST response against the tenant's
// pinned IdP certificates and the request-specific SP constraints.
func (p *CrewjamProvider) ValidateResponse(ctx context.Context, in ValidateResponseInput) (*VerifiedAssertion, error) {
	raw, err := p.preflightResponse(in)
	if err != nil {
		return nil, err
	}
	sp, err := p.serviceProvider(in.IdP)
	if err != nil {
		return nil, err
	}

	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(raw)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.ACSURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("saml: create response request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		return nil, fmt.Errorf("saml: parse response form: %w", err)
	}

	assertion, err := parseCrewjamResponse(sp, req, in.ExpectedInResponseTo)
	if err != nil {
		return nil, mapCrewjamResponseError(err)
	}
	if err := validateAssertionConstraints(assertion, in, p.EntityID, p.ACSURL); err != nil {
		return nil, err
	}
	return verifiedAssertion(assertion, in.IdP), nil
}

func (p *CrewjamProvider) preflightResponse(in ValidateResponseInput) ([]byte, error) {
	if strings.TrimSpace(in.RawBase64) == "" || strings.TrimSpace(in.ExpectedInResponseTo) == "" {
		return nil, ErrSubjectConfirmation
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(in.RawBase64)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return nil, ErrSignatureInvalid
	}
	if containsDOCTYPE(raw) {
		return nil, ErrXXE
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return nil, ErrSignatureInvalid
	}
	root := doc.Root()
	if root.Tag != "Response" || root.NamespaceURI() != "urn:oasis:names:tc:SAML:2.0:protocol" {
		return nil, ErrSignatureWrapping
	}
	if hasDuplicateXMLID(root, make(map[string]struct{})) {
		return nil, ErrSignatureWrapping
	}

	assertionCount := 0
	for _, child := range root.ChildElements() {
		if child.NamespaceURI() == "urn:oasis:names:tc:SAML:2.0:assertion" &&
			(child.Tag == "Assertion" || child.Tag == "EncryptedAssertion") {
			assertionCount++
		}
	}
	if assertionCount != 1 {
		return nil, ErrSignatureWrapping
	}

	var response crewjamsaml.Response
	if err := xml.Unmarshal(raw, &response); err != nil {
		return nil, ErrSignatureInvalid
	}
	if strings.TrimSpace(response.ID) == "" {
		return nil, ErrSignatureWrapping
	}
	if response.Destination != p.ACSURL {
		return nil, ErrDestinationMismatch
	}
	if response.InResponseTo != in.ExpectedInResponseTo {
		return nil, ErrSubjectConfirmation
	}
	if response.Status.StatusCode.Value != crewjamsaml.StatusSuccess {
		return nil, ErrStatusNotSuccess
	}
	return raw, nil
}

func hasDuplicateXMLID(element *etree.Element, seen map[string]struct{}) bool {
	if id := strings.TrimSpace(element.SelectAttrValue("ID", "")); id != "" {
		if _, exists := seen[id]; exists {
			return true
		}
		seen[id] = struct{}{}
	}
	for _, child := range element.ChildElements() {
		if hasDuplicateXMLID(child, seen) {
			return true
		}
	}
	return false
}

func (p *CrewjamProvider) serviceProvider(idp IdPRecord) (*crewjamsaml.ServiceProvider, error) {
	if p.Key == nil || p.Cert == nil || strings.TrimSpace(p.EntityID) == "" {
		return nil, fmt.Errorf("saml: incomplete SP key material")
	}
	acsURL, err := url.Parse(p.ACSURL)
	if err != nil || acsURL.Scheme != "https" || acsURL.Host == "" {
		return nil, fmt.Errorf("saml: invalid ACS URL")
	}
	sloURL, err := url.Parse(p.SLOURL)
	if err != nil || sloURL.Scheme != "https" || sloURL.Host == "" {
		return nil, fmt.Errorf("saml: invalid SLO URL")
	}
	if strings.TrimSpace(idp.EntityID) == "" || len(idp.SigningCerts) == 0 {
		return nil, fmt.Errorf("saml: incomplete IdP trust material")
	}

	keyDescriptors := make([]crewjamsaml.KeyDescriptor, 0, len(idp.SigningCerts))
	now := time.Now().UTC()
	for _, der := range idp.SigningCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("saml: parse pinned IdP certificate: %w", err)
		}
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			continue
		}
		keyDescriptors = append(keyDescriptors, crewjamsaml.KeyDescriptor{
			Use: "signing",
			KeyInfo: crewjamsaml.KeyInfo{X509Data: crewjamsaml.X509Data{
				X509Certificates: []crewjamsaml.X509Certificate{{
					Data: base64.StdEncoding.EncodeToString(cert.Raw),
				}},
			}},
		})
	}
	if len(keyDescriptors) == 0 {
		return nil, ErrIDPMetadataStale
	}

	idpMetadata := &crewjamsaml.EntityDescriptor{
		EntityID: idp.EntityID,
		IDPSSODescriptors: []crewjamsaml.IDPSSODescriptor{{
			SSODescriptor: crewjamsaml.SSODescriptor{
				RoleDescriptor: crewjamsaml.RoleDescriptor{KeyDescriptors: keyDescriptors},
			},
			SingleSignOnServices: []crewjamsaml.Endpoint{{
				Binding: crewjamsaml.HTTPRedirectBinding, Location: idp.SSOURL,
			}},
		}},
	}
	return &crewjamsaml.ServiceProvider{
		EntityID:        p.EntityID,
		AcsURL:          *acsURL,
		SloURL:          *sloURL,
		Key:             p.Key,
		Certificate:     p.Cert,
		IDPMetadata:     idpMetadata,
		SignatureMethod: dsig.RSASHA256SignatureMethod,
	}, nil
}

func parseCrewjamResponse(sp *crewjamsaml.ServiceProvider, req *http.Request, requestID string) (assertion *crewjamsaml.Assertion, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			assertion = nil
			err = ErrSignatureInvalid
		}
	}()
	return sp.ParseResponse(req, []string{requestID})
}

func mapCrewjamResponseError(err error) error {
	if errors.Is(err, ErrSignatureInvalid) {
		return ErrSignatureInvalid
	}
	var badStatus crewjamsaml.ErrBadStatus
	if errors.As(err, &badStatus) {
		return ErrStatusNotSuccess
	}
	var invalid *crewjamsaml.InvalidResponseError
	if errors.As(err, &invalid) && invalid.PrivateErr != nil {
		err = invalid.PrivateErr
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "destination") || strings.Contains(message, "acsurl"):
		return ErrDestinationMismatch
	case strings.Contains(message, "decrypt"):
		return ErrDecryptFailed
	case strings.Contains(message, "issuer"):
		return ErrIssuerMismatch
	case strings.Contains(message, "audience"):
		return ErrAudienceMismatch
	case strings.Contains(message, "subjectconfirmation") ||
		strings.Contains(message, "recipient") ||
		strings.Contains(message, "inresponseto"):
		return ErrSubjectConfirmation
	case strings.Contains(message, "expired") || strings.Contains(message, "not yet valid"):
		return ErrClockSkew
	case strings.Contains(message, "signature"):
		return ErrSignatureInvalid
	default:
		return ErrSignatureInvalid
	}
}

func validateAssertionConstraints(assertion *crewjamsaml.Assertion, in ValidateResponseInput, entityID, acsURL string) error {
	if assertion == nil || assertion.Subject == nil || assertion.Subject.NameID == nil ||
		assertion.Conditions == nil || strings.TrimSpace(assertion.ID) == "" {
		return ErrSubjectConfirmation
	}
	if assertion.Issuer.Value != in.IdP.EntityID {
		return ErrIssuerMismatch
	}

	audienceMatched := false
	for _, restriction := range assertion.Conditions.AudienceRestrictions {
		if restriction.Audience.Value == entityID {
			audienceMatched = true
		}
	}
	if !audienceMatched {
		return ErrAudienceMismatch
	}

	now := in.Now.UTC()
	skew := in.ClockSkew
	if skew < 0 || skew > 5*time.Minute {
		return ErrClockSkew
	}
	if assertion.Conditions.NotBefore.IsZero() || assertion.Conditions.NotOnOrAfter.IsZero() ||
		assertion.Conditions.NotBefore.Add(-skew).After(now) ||
		!assertion.Conditions.NotOnOrAfter.Add(skew).After(now) {
		return ErrClockSkew
	}

	confirmationMatched := false
	for _, confirmation := range assertion.Subject.SubjectConfirmations {
		data := confirmation.SubjectConfirmationData
		if data == nil || data.Recipient != acsURL || data.InResponseTo != in.ExpectedInResponseTo ||
			data.NotOnOrAfter.IsZero() || !data.NotOnOrAfter.Add(skew).After(now) {
			continue
		}
		confirmationMatched = true
		break
	}
	if !confirmationMatched {
		return ErrSubjectConfirmation
	}
	return nil
}

func verifiedAssertion(assertion *crewjamsaml.Assertion, idp IdPRecord) *VerifiedAssertion {
	attributes := make(map[string][]string)
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			values := make([]string, 0, len(attribute.Values))
			for _, value := range attribute.Values {
				if trimmed := strings.TrimSpace(value.Value); trimmed != "" {
					values = append(values, trimmed)
				}
			}
			if len(values) == 0 {
				continue
			}
			if attribute.Name != "" {
				attributes[attribute.Name] = append(attributes[attribute.Name], values...)
			}
			if attribute.FriendlyName != "" {
				attributes[attribute.FriendlyName] = append(attributes[attribute.FriendlyName], values...)
			}
		}
	}
	for canonical, aliases := range idp.AttributeMap {
		for _, alias := range aliases {
			if values := attributes[alias]; len(values) > 0 {
				attributes[canonical] = append([]string(nil), values...)
				break
			}
		}
	}

	result := &VerifiedAssertion{
		AssertionID:    assertion.ID,
		NameID:         strings.TrimSpace(assertion.Subject.NameID.Value),
		NameIDFormat:   assertion.Subject.NameID.Format,
		Attributes:     attributes,
		IssuerEntityID: assertion.Issuer.Value,
		NotOnOrAfter:   assertion.Conditions.NotOnOrAfter,
	}
	if len(assertion.AuthnStatements) > 0 {
		result.SessionIndex = assertion.AuthnStatements[0].SessionIndex
		if expiry := assertion.AuthnStatements[0].SessionNotOnOrAfter; expiry != nil &&
			(result.NotOnOrAfter.IsZero() || expiry.Before(result.NotOnOrAfter)) {
			result.NotOnOrAfter = *expiry
		}
	}
	return result
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
	req.Signature = nil
	if err := sp.SignLogoutRequest(req); err != nil {
		return nil, fmt.Errorf("saml: sign logout request: %w", err)
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
		compressed, err := base64.StdEncoding.Strict().DecodeString(in.RawMessage)
		if err != nil {
			return nil, fmt.Errorf("saml: base64 decode logout message: %w", err)
		}
		reader := flate.NewReader(bytes.NewReader(compressed))
		defer reader.Close()
		rawXML, err = io.ReadAll(io.LimitReader(reader, (1<<20)+1))
		if err != nil || len(rawXML) == 0 || len(rawXML) > 1<<20 {
			return nil, fmt.Errorf("saml: deflate decompress logout message: %w", err)
		}
	case crewjamsaml.HTTPPostBinding, "":
		rawXML, err = base64.StdEncoding.Strict().DecodeString(in.RawMessage)
		if err != nil || len(rawXML) == 0 || len(rawXML) > 1<<20 {
			return nil, fmt.Errorf("saml: base64 decode logout message: %w", err)
		}
	default:
		return nil, fmt.Errorf("saml: unsupported binding: %s", in.Binding)
	}

	if containsDOCTYPE(rawXML) {
		return nil, ErrXXE
	}
	verifiedRoot, err := verifySignedLogoutXML(rawXML, in.IdP)
	if err != nil {
		return nil, err
	}
	verifiedDoc := etree.NewDocument()
	verifiedDoc.SetRoot(verifiedRoot)
	rawXML, err = verifiedDoc.WriteToBytes()
	if err != nil {
		return nil, ErrSignatureInvalid
	}

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
		if resp.Issuer == nil || resp.Issuer.Value != in.IdP.EntityID {
			return nil, ErrIssuerMismatch
		}
		if resp.Destination != p.SLOURL {
			return nil, ErrDestinationMismatch
		}
		if in.ExpectedInResponseTo == "" || resp.InResponseTo != in.ExpectedInResponseTo {
			return nil, ErrSubjectConfirmation
		}
		if !validLogoutIssueInstant(resp.IssueInstant, time.Now().UTC()) {
			return nil, ErrClockSkew
		}
		return &VerifiedLogout{
			MessageID:  resp.ID,
			IsResponse: true,
			Status:     resp.Status.StatusCode.Value,
		}, nil
	case "LogoutRequest":
		var req crewjamsaml.LogoutRequest
		if err := xml.Unmarshal(rawXML, &req); err != nil {
			return nil, fmt.Errorf("saml: unmarshal LogoutRequest: %w", err)
		}
		if req.Issuer == nil || req.Issuer.Value != in.IdP.EntityID {
			return nil, ErrIssuerMismatch
		}
		if req.Destination != p.SLOURL {
			return nil, ErrDestinationMismatch
		}
		if !validLogoutIssueInstant(req.IssueInstant, time.Now().UTC()) {
			return nil, ErrClockSkew
		}
		vl := &VerifiedLogout{
			MessageID:  req.ID,
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

func validLogoutIssueInstant(issueInstant, now time.Time) bool {
	return !issueInstant.IsZero() &&
		!issueInstant.Add(90*time.Second).Before(now) &&
		!issueInstant.After(now.Add(90*time.Second))
}

func verifySignedLogoutXML(raw []byte, idp IdPRecord) (*etree.Element, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return nil, ErrSignatureInvalid
	}
	root := doc.Root()
	if root.NamespaceURI() != "urn:oasis:names:tc:SAML:2.0:protocol" ||
		(root.Tag != "LogoutRequest" && root.Tag != "LogoutResponse") ||
		hasDuplicateXMLID(root, make(map[string]struct{})) {
		return nil, ErrSignatureWrapping
	}
	if strings.TrimSpace(root.SelectAttrValue("ID", "")) == "" {
		return nil, ErrSignatureWrapping
	}

	signatures := 0
	for _, child := range root.ChildElements() {
		if child.Tag == "Signature" && child.NamespaceURI() == "http://www.w3.org/2000/09/xmldsig#" {
			signatures++
		}
	}
	if signatures != 1 {
		return nil, ErrSignatureInvalid
	}
	allow := map[string]bool{
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": true,
	}
	for _, element := range doc.FindElements("//SignatureMethod") {
		if err := checkAlgorithm(element.SelectAttrValue("Algorithm", ""), allow); err != nil {
			return nil, err
		}
	}
	for _, element := range doc.FindElements("//DigestMethod") {
		algorithm := element.SelectAttrValue("Algorithm", "")
		if algorithm != "http://www.w3.org/2001/04/xmlenc#sha256" {
			return nil, ErrAlgorithmDisallowed
		}
	}

	roots := make([]*x509.Certificate, 0, len(idp.SigningCerts))
	now := time.Now().UTC()
	for _, der := range idp.SigningCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, ErrIDPMetadataStale
		}
		if !now.Before(cert.NotBefore) && now.Before(cert.NotAfter) {
			roots = append(roots, cert)
		}
	}
	if len(roots) == 0 {
		return nil, ErrIDPMetadataStale
	}
	validation := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: roots})
	validation.IdAttribute = "ID"
	validated, err := validation.Validate(root)
	if err != nil {
		return nil, ErrSignatureInvalid
	}
	return validated, nil
}

func (p *CrewjamProvider) SPMetadata(_ context.Context) ([]byte, error) {
	if p.Cert == nil || strings.TrimSpace(p.EntityID) == "" ||
		strings.TrimSpace(p.ACSURL) == "" || strings.TrimSpace(p.SLOURL) == "" {
		return nil, fmt.Errorf("saml: incomplete SP metadata configuration")
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Cert.Raw})
	validUntil := p.Cert.NotAfter
	maximum := time.Now().UTC().Add(7 * 24 * time.Hour)
	if validUntil.After(maximum) {
		validUntil = maximum
	}
	return SPMetadataFromConfig(SPMetadataConfig{
		EntityID:       p.EntityID,
		ACSURL:         p.ACSURL,
		SLOURL:         p.SLOURL,
		SigningCertPEM: certificate,
		EncryptCertPEM: certificate,
		ValidUntil:     validUntil,
	})
}

func (p *CrewjamProvider) ParseIdPMetadata(_ context.Context, raw []byte) (*IdPRecord, error) {
	return ParseIdPMetadata(raw)
}
