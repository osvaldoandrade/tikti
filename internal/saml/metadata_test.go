package saml

import (
	"bytes"
	"encoding/xml"
	"os"
	"strings"
	"testing"
	"time"
)

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
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
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
