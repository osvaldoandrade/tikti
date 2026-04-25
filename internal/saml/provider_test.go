package saml

import (
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"io"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Compile-time interface compliance check.
var _ Provider = (*stubProvider)(nil)

// stubProvider is an unimplemented stub used only for the compile-time assertion above.
type stubProvider struct{}

func (s *stubProvider) BuildAuthnRequest(_ context.Context, _ BuildAuthnRequestInput) (*AuthnRequest, error) {
	return nil, nil
}

func (s *stubProvider) ValidateResponse(_ context.Context, _ ValidateResponseInput) (*VerifiedAssertion, error) {
	return nil, nil
}

func (s *stubProvider) BuildLogoutRequest(_ context.Context, _ BuildLogoutRequestInput) (*LogoutRequest, error) {
	return nil, nil
}

func (s *stubProvider) ValidateLogoutMessage(_ context.Context, _ ValidateLogoutInput) (*VerifiedLogout, error) {
	return nil, nil
}

func (s *stubProvider) SPMetadata(_ context.Context) ([]byte, error) {
	return nil, nil
}

func (s *stubProvider) ParseIdPMetadata(_ context.Context, _ []byte) (*IdPRecord, error) {
	return nil, nil
}

// Compile-time check that CrewjamProvider implements Provider.
var _ Provider = (*CrewjamProvider)(nil)

// testSPKeyPair generates a self-signed RSA 2048 key pair for tests.
func testSPKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-sp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

// newTestProvider builds a CrewjamProvider with test keys and a fixed config.
func newTestProvider(t *testing.T) *CrewjamProvider {
	t.Helper()
	key, cert := testSPKeyPair(t)
	return &CrewjamProvider{
		EntityID: "https://auth.example.com/saml",
		ACSURL:   "https://auth.example.com/saml/acs",
		SLOURL:   "https://auth.example.com/saml/slo",
		Key:      key,
		Cert:     cert,
	}
}

// testBuildInput returns a BuildAuthnRequestInput with common test values.
func testBuildInput() BuildAuthnRequestInput {
	return BuildAuthnRequestInput{
		TenantID: "t-001",
		IdP: IdPRecord{
			TenantID: "t-001",
			EntityID: "https://idp.example.com",
			SSOURL:   "https://idp.example.com/sso",
		},
		RelayState:   "/dashboard",
		ACSURL:       "https://auth.example.com/saml/acs",
		RequestID:    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		IssueInstant: time.Date(2026, 4, 24, 17, 32, 1, 0, time.UTC),
		ForceAuthn:   false,
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	}
}

// decodeSAMLRequestFromURL extracts and decodes the SAMLRequest from a redirect URL.
func decodeSAMLRequestFromURL(t *testing.T, rawURL string) []byte {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}
	encoded := u.Query().Get("SAMLRequest")
	if encoded == "" {
		// The redirect URL uses RawQuery with ordered params; parse manually.
		for _, pair := range strings.Split(u.RawQuery, "&") {
			parts := strings.SplitN(pair, "=", 2)
			if parts[0] == "SAMLRequest" && len(parts) == 2 {
				decoded, err := url.QueryUnescape(parts[1])
				if err != nil {
					t.Fatalf("unescape SAMLRequest: %v", err)
				}
				encoded = decoded
				break
			}
		}
	}
	if encoded == "" {
		t.Fatalf("SAMLRequest not found in URL: %s", rawURL)
	}

	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode SAMLRequest: %v", err)
	}
	reader := flate.NewReader(strings.NewReader(string(compressed)))
	defer reader.Close()
	xmlBytes, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("deflate decompress SAMLRequest: %v", err)
	}
	return xmlBytes
}

// authnRequestXML is a minimal struct for parsing the AuthnRequest XML.
type authnRequestXML struct {
	XMLName      xml.Name         `xml:"AuthnRequest"`
	ID           string           `xml:"ID,attr"`
	Version      string           `xml:"Version,attr"`
	IssueInstant string           `xml:"IssueInstant,attr"`
	Destination  string           `xml:"Destination,attr"`
	ACSURL       string           `xml:"AssertionConsumerServiceURL,attr"`
	Issuer       string           `xml:"Issuer"`
	NameIDPolicy *nameIDPolicyXML `xml:"NameIDPolicy"`
}

type nameIDPolicyXML struct {
	Format      string `xml:"Format,attr"`
	AllowCreate string `xml:"AllowCreate,attr"`
}

func TestAuthnRequest_SignatureValid(t *testing.T) {
	prov := newTestProvider(t)
	in := testBuildInput()

	result, err := prov.BuildAuthnRequest(context.Background(), in)
	if err != nil {
		t.Fatalf("BuildAuthnRequest: %v", err)
	}

	// Parse the redirect URL to extract the signed query.
	u, err := url.Parse(result.RedirectURL)
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}

	// Extract ordered query components for signature verification.
	// Per HTTP-Redirect binding, the signed message is:
	//   SAMLRequest=value&RelayState=value&SigAlg=value
	raw := u.RawQuery
	sigIdx := strings.Index(raw, "&Signature=")
	if sigIdx < 0 {
		t.Fatalf("Signature not found in URL query: %s", raw)
	}
	signedPart := raw[:sigIdx]
	sigValue := raw[sigIdx+len("&Signature="):]

	sigBytes, err := base64.StdEncoding.DecodeString(mustQueryUnescape(t, sigValue))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	// Verify RSA-SHA256 signature using the SP's public key.
	hash := sha256.Sum256([]byte(signedPart))
	err = rsa.VerifyPKCS1v15(&prov.Key.PublicKey, crypto.SHA256, hash[:], sigBytes)
	if err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	// Verify SigAlg is RSA-SHA256.
	if !strings.Contains(signedPart, "SigAlg="+url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")) {
		t.Errorf("SigAlg not RSA-SHA256; signed part: %s", signedPart)
	}

	// Also verify the URL is under 8 KiB.
	if len(result.RedirectURL) > 8192 {
		t.Errorf("redirect URL too long: %d bytes (max 8192)", len(result.RedirectURL))
	}
}

func TestAuthnRequest_IDFormat(t *testing.T) {
	prov := newTestProvider(t)
	in := testBuildInput()

	result, err := prov.BuildAuthnRequest(context.Background(), in)
	if err != nil {
		t.Fatalf("BuildAuthnRequest: %v", err)
	}

	// The ID returned must match the input: "_" + 40 hex chars.
	expectedID := "_" + in.RequestID
	if result.ID != expectedID {
		t.Errorf("ID mismatch: got %q, want %q", result.ID, expectedID)
	}

	// Verify ID format: starts with "_" followed by 40 hex characters.
	idRe := regexp.MustCompile(`^_[0-9a-f]{40}$`)
	if !idRe.MatchString(result.ID) {
		t.Errorf("ID %q does not match expected format _<40 hex>", result.ID)
	}

	// Also verify the ID in the decoded XML matches.
	xmlBytes := decodeSAMLRequestFromURL(t, result.RedirectURL)
	var req authnRequestXML
	if err := xml.Unmarshal(xmlBytes, &req); err != nil {
		t.Fatalf("unmarshal AuthnRequest XML: %v", err)
	}
	if req.ID != expectedID {
		t.Errorf("XML ID mismatch: got %q, want %q", req.ID, expectedID)
	}
}

func TestAuthnRequest_Contains_NameIDPolicy(t *testing.T) {
	prov := newTestProvider(t)
	in := testBuildInput()

	result, err := prov.BuildAuthnRequest(context.Background(), in)
	if err != nil {
		t.Fatalf("BuildAuthnRequest: %v", err)
	}

	xmlBytes := decodeSAMLRequestFromURL(t, result.RedirectURL)
	var req authnRequestXML
	if err := xml.Unmarshal(xmlBytes, &req); err != nil {
		t.Fatalf("unmarshal AuthnRequest XML: %v", err)
	}

	if req.NameIDPolicy == nil {
		t.Fatal("NameIDPolicy element is missing from AuthnRequest")
	}

	wantFormat := "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	if req.NameIDPolicy.Format != wantFormat {
		t.Errorf("NameIDPolicy.Format = %q, want %q", req.NameIDPolicy.Format, wantFormat)
	}

	if req.NameIDPolicy.AllowCreate != "true" {
		t.Errorf("NameIDPolicy.AllowCreate = %q, want %q", req.NameIDPolicy.AllowCreate, "true")
	}
}

func mustQueryUnescape(t *testing.T, s string) string {
	t.Helper()
	v, err := url.QueryUnescape(s)
	if err != nil {
		t.Fatalf("query unescape: %v", err)
	}
	return v
}
