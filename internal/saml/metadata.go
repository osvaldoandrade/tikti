package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// SAML 2.0 binding URIs.
const (
	BindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingHTTPPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// supportedBindings lists the SSO bindings we accept.
var supportedBindings = map[string]bool{
	BindingHTTPRedirect: true,
	BindingHTTPPOST:     true,
}

// ---------------------------------------------------------------------------
// Minimal XML model for IdP metadata — we only extract what IdPRecord needs.
// ---------------------------------------------------------------------------

type entityDescriptor struct {
	XMLName    xml.Name     `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID   string       `xml:"entityID,attr"`
	IDPSSODesc []idpSSODesc `xml:"IDPSSODescriptor"`
}

type idpSSODesc struct {
	KeyDescriptors       []keyDescriptor       `xml:"KeyDescriptor"`
	SingleSignOnServices []singleSignOnService `xml:"SingleSignOnService"`
	SingleLogoutServices []singleLogoutService `xml:"SingleLogoutService"`
	NameIDFormats        []string              `xml:"NameIDFormat"`
}

type keyDescriptor struct {
	Use     string  `xml:"use,attr"`
	KeyInfo keyInfo `xml:"KeyInfo"`
}

type keyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data x509Data `xml:"X509Data"`
}

type x509Data struct {
	Certificates []string `xml:"X509Certificate"`
}

type singleSignOnService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

type singleLogoutService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// ParseIdPMetadata parses raw SAML 2.0 IdP metadata XML and returns a
// validated IdPRecord. It rejects metadata with:
//   - malformed XML
//   - empty entityID
//   - no signing certificate
//   - expired signing certificate (all certs expired)
//   - SSO URL not using HTTPS
//   - unsupported SSO binding
func ParseIdPMetadata(raw []byte) (*IdPRecord, error) {
	// Reject XML with DOCTYPE declarations (XXE defence).
	if containsDOCTYPE(raw) {
		return nil, ErrMetadataMalformedXML
	}

	var ed entityDescriptor
	if err := xml.Unmarshal(raw, &ed); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMetadataMalformedXML, err)
	}

	// entityID must not be empty.
	if strings.TrimSpace(ed.EntityID) == "" {
		return nil, ErrMetadataEmptyEntityID
	}

	if len(ed.IDPSSODesc) == 0 {
		return nil, fmt.Errorf("%w: no IDPSSODescriptor element", ErrMetadataMalformedXML)
	}

	idp := ed.IDPSSODesc[0]

	// --- Certificates ---
	sigCerts, encCerts, err := extractCerts(idp.KeyDescriptors)
	if err != nil {
		return nil, err
	}
	if len(sigCerts) == 0 {
		return nil, ErrMetadataNoCert
	}

	// Verify at least one signing cert is not expired.
	if err := checkCertExpiry(sigCerts); err != nil {
		return nil, err
	}

	// --- SSO URL ---
	ssoURL, err := pickSSOURL(idp.SingleSignOnServices)
	if err != nil {
		return nil, err
	}

	// --- SLO URL (optional, best-effort) ---
	sloURL := pickSLOURL(idp.SingleLogoutServices)

	// --- NameIDFormat (pick first if present) ---
	var nameIDFmt string
	if len(idp.NameIDFormats) > 0 {
		nameIDFmt = idp.NameIDFormats[0]
	}

	rec := &IdPRecord{
		EntityID:        ed.EntityID,
		SSOURL:          ssoURL,
		SLOURL:          sloURL,
		SigningCerts:     rawCerts(sigCerts),
		EncryptionCerts: rawCerts(encCerts),
		NameIDFormat:    nameIDFmt,
		LastFetched:     time.Now(),
	}
	return rec, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// containsDOCTYPE checks for DOCTYPE declarations (XXE attack vector).
func containsDOCTYPE(data []byte) bool {
	return strings.Contains(strings.ToUpper(string(data)), "<!DOCTYPE")
}

// extractCerts splits KeyDescriptors into signing and encryption groups.
// KeyDescriptors with use="" are treated as signing (spec default).
func extractCerts(kds []keyDescriptor) ([]*x509.Certificate, []*x509.Certificate, error) {
	var signing, encryption []*x509.Certificate

	for _, kd := range kds {
		for _, b64 := range kd.KeyInfo.X509Data.Certificates {
			raw := strings.Join(strings.Fields(b64), "")
			der, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: bad base64 in certificate: %v", ErrMetadataMalformedXML, err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: bad X.509 certificate: %v", ErrMetadataMalformedXML, err)
			}

			switch strings.ToLower(kd.Use) {
			case "encryption":
				encryption = append(encryption, cert)
			default: // "signing" or ""
				signing = append(signing, cert)
			}
		}
	}
	return signing, encryption, nil
}

// checkCertExpiry returns ErrMetadataExpired when every signing cert is expired.
func checkCertExpiry(certs []*x509.Certificate) error {
	now := time.Now()
	for _, c := range certs {
		if now.Before(c.NotAfter) {
			return nil // at least one is still valid
		}
	}
	return ErrMetadataExpired
}

// pickSSOURL finds the first supported SSO service. It validates the binding
// and enforces HTTPS.
func pickSSOURL(services []singleSignOnService) (string, error) {
	for _, s := range services {
		if !supportedBindings[s.Binding] {
			continue // skip, try next
		}
		u, err := url.Parse(s.Location)
		if err != nil || !strings.EqualFold(u.Scheme, "https") {
			return "", ErrMetadataInsecureURL
		}
		return s.Location, nil
	}
	// No supported binding found. If services exist they all had unsupported
	// bindings; otherwise the element is missing entirely.
	if len(services) > 0 {
		return "", fmt.Errorf("%w: %s", ErrMetadataUnsupportedBind, services[0].Binding)
	}
	return "", fmt.Errorf("%w: no SingleSignOnService element", ErrMetadataMalformedXML)
}

// pickSLOURL returns the first SLO URL with a supported binding, or "" if
// none exists (SLO is optional).
func pickSLOURL(services []singleLogoutService) string {
	for _, s := range services {
		if supportedBindings[s.Binding] {
			return s.Location
		}
	}
	return ""
}

// rawCerts converts parsed certificates back to DER bytes for storage.
func rawCerts(certs []*x509.Certificate) [][]byte {
	out := make([][]byte, len(certs))
	for i, c := range certs {
		out[i] = c.Raw
	}
	return out
}
