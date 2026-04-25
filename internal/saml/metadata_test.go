package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// SP Metadata tests
// ---------------------------------------------------------------------------

// testMetadataConfig returns a deterministic SPMetadataConfig using the
// test certificates in testdata/.
func testMetadataConfig(t *testing.T) SPMetadataConfig {
	t.Helper()
	sigCert, err := os.ReadFile("testdata/sp_signing.crt")
	if err != nil {
		t.Fatalf("read signing cert: %v", err)
	}
	encCert, err := os.ReadFile("testdata/sp_encryption.crt")
	if err != nil {
		t.Fatalf("read encryption cert: %v", err)
	}
	return SPMetadataConfig{
		EntityID:       "https://auth.example.com/saml",
		ACSURL:         "https://auth.example.com/saml/acs",
		SLOURL:         "https://auth.example.com/saml/slo",
		SigningCertPEM: sigCert,
		EncryptCertPEM: encCert,
		ValidUntil:     time.Date(2027, 4, 24, 0, 0, 0, 0, time.UTC),
	}
}

// TestSPMetadata_GoldenBytes verifies that SPMetadataFromConfig produces
// byte-identical output across 3 successive calls and that the output
// matches the golden file in testdata/sp_metadata.xml.
func TestSPMetadata_GoldenBytes(t *testing.T) {
	cfg := testMetadataConfig(t)

	golden, err := os.ReadFile("testdata/sp_metadata.xml")
	if err != nil {
		t.Fatalf("read golden file: %v", err)
	}

	for i := 0; i < 3; i++ {
		out, err := SPMetadataFromConfig(cfg)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if !bytes.Equal(out, golden) {
			t.Fatalf("call %d: output differs from golden file.\ngot:\n%s\nwant:\n%s", i, out, golden)
		}
	}
}

// TestSPMetadata_SchemaValid verifies that the output is well-formed XML
// and contains the required SAML metadata elements per the OASIS schema.
func TestSPMetadata_SchemaValid(t *testing.T) {
	cfg := testMetadataConfig(t)
	out, err := SPMetadataFromConfig(cfg)
	if err != nil {
		t.Fatalf("SPMetadataFromConfig: %v", err)
	}

	// Verify well-formed XML.
	dec := xml.NewDecoder(bytes.NewReader(out))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("XML is not well-formed: %v", err)
		}
	}

	s := string(out)

	// Verify required OASIS SAML 2.0 metadata elements.
	required := []string{
		`xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"`,
		`entityID="https://auth.example.com/saml"`,
		`validUntil="2027-04-24T00:00:00Z"`,
		"md:SPSSODescriptor",
		`AuthnRequestsSigned="true"`,
		`WantAssertionsSigned="true"`,
		`protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"`,
		"md:KeyDescriptor",
		"ds:KeyInfo",
		"ds:X509Data",
		"ds:X509Certificate",
		"md:SingleLogoutService",
		`urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`,
		`urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST`,
		"md:NameIDFormat",
		"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		"md:AssertionConsumerService",
		`index="0"`,
		`isDefault="true"`,
	}
	for _, r := range required {
		if !strings.Contains(s, r) {
			t.Errorf("output missing required element/attribute: %s", r)
		}
	}
}

// TestSPMetadata_ContainsBothKeyUses verifies that the output contains
// both use="signing" and use="encryption" KeyDescriptor elements.
func TestSPMetadata_ContainsBothKeyUses(t *testing.T) {
	cfg := testMetadataConfig(t)
	out, err := SPMetadataFromConfig(cfg)
	if err != nil {
		t.Fatalf("SPMetadataFromConfig: %v", err)
	}

	s := string(out)
	if !strings.Contains(s, `use="signing"`) {
		t.Error("output missing KeyDescriptor with use=\"signing\"")
	}
	if !strings.Contains(s, `use="encryption"`) {
		t.Error("output missing KeyDescriptor with use=\"encryption\"")
	}

	// Verify EncryptionMethod elements are present under the encryption KeyDescriptor.
	if !strings.Contains(s, `Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"`) {
		t.Error("output missing EncryptionMethod aes256-gcm")
	}
	if !strings.Contains(s, `Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"`) {
		t.Error("output missing EncryptionMethod rsa-oaep-mgf1p")
	}
}

// ---------------------------------------------------------------------------
// IdP Metadata parser tests
// ---------------------------------------------------------------------------

// loadFixture reads a file from testdata/ relative to this test file.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	return data
}

// ---------------------------------------------------------------------------
// Accept tests — 5 vendor fixtures
// ---------------------------------------------------------------------------

func TestParseIdP_5Vendors_Accept(t *testing.T) {
	vendors := []struct {
		file     string
		entityID string
	}{
		{"idp_azure.xml", "https://sts.windows.net/tenant-id-azure/"},
		{"idp_okta.xml", "http://www.okta.com/exk123abc"},
		{"idp_ping.xml", "https://sso.connect.pingidentity.com/abc123"},
		{"idp_adfs.xml", "http://adfs.corp.example.com/adfs/services/trust"},
		{"idp_google.xml", "https://accounts.google.com/o/saml2?idpid=C00000000"},
	}

	start := time.Now()

	for _, v := range vendors {
		t.Run(v.file, func(t *testing.T) {
			raw := loadFixture(t, v.file)
			rec, err := ParseIdPMetadata(raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rec.EntityID != v.entityID {
				t.Errorf("EntityID = %q, want %q", rec.EntityID, v.entityID)
			}
			if rec.SSOURL == "" {
				t.Error("SSOURL is empty")
			}
			if len(rec.SigningCerts) == 0 {
				t.Error("no signing certs")
			}
		})
	}

	elapsed := time.Since(start)
	if elapsed > 20*time.Millisecond {
		t.Errorf("parsing took %v, want < 20ms", elapsed)
	}
}

// ---------------------------------------------------------------------------
// Reject tests — 6 rejection scenarios
// ---------------------------------------------------------------------------

func TestParseIdP_NoCert_Rejected(t *testing.T) {
	raw := loadFixture(t, "idp_reject_no_cert.xml")
	_, err := ParseIdPMetadata(raw)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrMetadataNoCert) {
		t.Errorf("expected ErrMetadataNoCert, got: %v", err)
	}
}

func TestParseIdP_ExpiredCert_Rejected(t *testing.T) {
	raw := loadFixture(t, "idp_reject_expired_cert.xml")
	_, err := ParseIdPMetadata(raw)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrMetadataExpired) {
		t.Errorf("expected ErrMetadataExpired, got: %v", err)
	}
}

func TestParseIdP_InsecureSSO_Rejected(t *testing.T) {
	raw := loadFixture(t, "idp_reject_insecure_url.xml")
	_, err := ParseIdPMetadata(raw)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrMetadataInsecureURL) {
		t.Errorf("expected ErrMetadataInsecureURL, got: %v", err)
	}
}

func TestParseIdP_MalformedXML_Rejected(t *testing.T) {
	raw := loadFixture(t, "idp_reject_malformed.xml")
	_, err := ParseIdPMetadata(raw)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrMetadataMalformedXML) {
		t.Errorf("expected ErrMetadataMalformedXML, got: %v", err)
	}
}

func TestParseIdP_EmptyEntityID_Rejected(t *testing.T) {
	raw := loadFixture(t, "idp_reject_empty_entity_id.xml")
	_, err := ParseIdPMetadata(raw)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrMetadataEmptyEntityID) {
		t.Errorf("expected ErrMetadataEmptyEntityID, got: %v", err)
	}
}

func TestParseIdP_UnsupportedBinding_Rejected(t *testing.T) {
	raw := loadFixture(t, "idp_reject_unsupported_binding.xml")
	_, err := ParseIdPMetadata(raw)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrMetadataUnsupportedBind) {
		t.Errorf("expected ErrMetadataUnsupportedBind, got: %v", err)
	}
}
