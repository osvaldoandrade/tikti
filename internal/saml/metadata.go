package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"
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

const (
	nsMD = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDS = "http://www.w3.org/2000/09/xmldsig#"
	nsP  = "urn:oasis:names:tc:SAML:2.0:protocol"
)

// ---------------------------------------------------------------------------
// SP Metadata emitter
// ---------------------------------------------------------------------------

// SPMetadataConfig carries the parameters needed to build the SP metadata XML.
type SPMetadataConfig struct {
	EntityID       string
	ACSURL         string
	SLOURL         string
	SigningCertPEM []byte
	EncryptCertPEM []byte
	ValidUntil     time.Time

	// ExtraSigningCertPEMs holds additional signing certificates to publish
	// in SP metadata during a 2-step key rotation (--prepare phase).
	ExtraSigningCertPEMs [][]byte
}

// SPMetadataFromConfig builds SAML SP metadata XML bytes per HLD Appendix O.
// The output is deterministic: identical inputs produce byte-equal output.
func SPMetadataFromConfig(cfg SPMetadataConfig) ([]byte, error) {
	sigB64, err := certPEMToBase64(cfg.SigningCertPEM)
	if err != nil {
		return nil, fmt.Errorf("saml: signing cert: %w", err)
	}
	encB64, err := certPEMToBase64(cfg.EncryptCertPEM)
	if err != nil {
		return nil, fmt.Errorf("saml: encryption cert: %w", err)
	}

	doc := etree.NewDocument()
	doc.WriteSettings.CanonicalEndTags = false
	doc.WriteSettings.CanonicalText = true
	doc.WriteSettings.CanonicalAttrVal = true

	ed := doc.CreateElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMD)
	ed.CreateAttr("entityID", cfg.EntityID)
	ed.CreateAttr("validUntil", cfg.ValidUntil.UTC().Format("2006-01-02T15:04:05Z"))

	spd := ed.CreateElement("md:SPSSODescriptor")
	spd.CreateAttr("AuthnRequestsSigned", "true")
	spd.CreateAttr("WantAssertionsSigned", "true")
	spd.CreateAttr("protocolSupportEnumeration", nsP)

	// Signing KeyDescriptor
	addKeyDescriptor(spd, "signing", sigB64, nil)

	// Extra signing KeyDescriptors (used during key rotation).
	for i, extra := range cfg.ExtraSigningCertPEMs {
		extraB64, err := certPEMToBase64(extra)
		if err != nil {
			return nil, fmt.Errorf("saml: extra signing cert %d: %w", i, err)
		}
		addKeyDescriptor(spd, "signing", extraB64, nil)
	}

	// Encryption KeyDescriptor
	addKeyDescriptor(spd, "encryption", encB64, []string{
		"http://www.w3.org/2009/xmlenc11#aes256-gcm",
		"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
	})

	// SingleLogoutService — HTTP-Redirect
	sloRedirect := spd.CreateElement("md:SingleLogoutService")
	sloRedirect.CreateAttr("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
	sloRedirect.CreateAttr("Location", cfg.SLOURL)

	// SingleLogoutService — HTTP-POST
	sloPost := spd.CreateElement("md:SingleLogoutService")
	sloPost.CreateAttr("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
	sloPost.CreateAttr("Location", cfg.SLOURL)

	// NameIDFormat
	nid := spd.CreateElement("md:NameIDFormat")
	nid.SetText("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")

	// AssertionConsumerService
	acs := spd.CreateElement("md:AssertionConsumerService")
	acs.CreateAttr("index", "0")
	acs.CreateAttr("isDefault", "true")
	acs.CreateAttr("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
	acs.CreateAttr("Location", cfg.ACSURL)

	doc.Indent(2)
	out, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("saml: marshal metadata: %w", err)
	}
	return out, nil
}

// addKeyDescriptor appends a md:KeyDescriptor element to parent.
func addKeyDescriptor(parent *etree.Element, use, certB64 string, encMethods []string) {
	kd := parent.CreateElement("md:KeyDescriptor")
	kd.CreateAttr("use", use)

	ki := kd.CreateElement("ds:KeyInfo")
	ki.CreateAttr("xmlns:ds", nsDS)

	x509data := ki.CreateElement("ds:X509Data")
	x509cert := x509data.CreateElement("ds:X509Certificate")
	x509cert.SetText(certB64)

	for _, alg := range encMethods {
		em := kd.CreateElement("md:EncryptionMethod")
		em.CreateAttr("Algorithm", alg)
	}
}

// certPEMToBase64 reads a PEM-encoded certificate and returns the raw
// base64-encoded DER bytes (standard base64, no line-wrapping).
func certPEMToBase64(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("invalid PEM certificate")
	}
	// Validate it's a real X.509 certificate.
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", fmt.Errorf("invalid x509 certificate: %w", err)
	}
	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}

// LoadCertFile reads a PEM certificate file from disk.
func LoadCertFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// ---------------------------------------------------------------------------
// IdP Metadata parser
// ---------------------------------------------------------------------------

// Minimal XML model for IdP metadata — we only extract what IdPRecord needs.

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
// IdP metadata helpers
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
