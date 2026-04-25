package saml

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
