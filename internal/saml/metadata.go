package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/beevik/etree"
)

const (
	nsMD = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDS = "http://www.w3.org/2000/09/xmldsig#"
	nsP  = "urn:oasis:names:tc:SAML:2.0:protocol"
)

// SPMetadataConfig carries the parameters needed to build the SP metadata XML.
type SPMetadataConfig struct {
	EntityID       string
	ACSURL         string
	SLOURL         string
	SigningCertPEM []byte
	EncryptCertPEM []byte
	ValidUntil     time.Time
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
