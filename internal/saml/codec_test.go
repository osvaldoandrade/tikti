package saml

import (
	"reflect"
	"testing"
	"time"
)

func TestCodec_IdPRecord_RoundTrip(t *testing.T) {
	orig := IdPRecord{
		TenantID:        "t-001",
		EntityID:        "https://idp.example.com",
		SSOURL:          "https://idp.example.com/sso",
		SLOURL:          "https://idp.example.com/slo",
		SigningCerts:    [][]byte{[]byte("cert1"), []byte("cert2"), []byte("cert3")},
		EncryptionCerts: [][]byte{[]byte("enc1")},
		NameIDFormat:    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		AttributeMap: map[string][]string{
			"email": {"mail", "email"},
			"name":  {"displayName"},
		},
		LastFetched: time.Date(2025, 1, 15, 10, 0, 0, 123456789, time.UTC),
	}

	data, err := encode(orig)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	got, err := decode[IdPRecord](data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if orig.TenantID != got.TenantID {
		t.Errorf("TenantID: %q vs %q", orig.TenantID, got.TenantID)
	}
	if orig.EntityID != got.EntityID {
		t.Errorf("EntityID: %q vs %q", orig.EntityID, got.EntityID)
	}
	if orig.SSOURL != got.SSOURL {
		t.Errorf("SSOURL: %q vs %q", orig.SSOURL, got.SSOURL)
	}
	if orig.SLOURL != got.SLOURL {
		t.Errorf("SLOURL: %q vs %q", orig.SLOURL, got.SLOURL)
	}
	if orig.NameIDFormat != got.NameIDFormat {
		t.Errorf("NameIDFormat: %q vs %q", orig.NameIDFormat, got.NameIDFormat)
	}
	if !orig.LastFetched.Equal(got.LastFetched) {
		t.Errorf("LastFetched: %v vs %v", orig.LastFetched, got.LastFetched)
	}
	if len(orig.SigningCerts) != len(got.SigningCerts) {
		t.Fatalf("SigningCerts len: %d vs %d", len(orig.SigningCerts), len(got.SigningCerts))
	}
	for i := range orig.SigningCerts {
		if string(orig.SigningCerts[i]) != string(got.SigningCerts[i]) {
			t.Errorf("SigningCerts[%d]: %q vs %q", i, orig.SigningCerts[i], got.SigningCerts[i])
		}
	}
	if !reflect.DeepEqual(orig.AttributeMap, got.AttributeMap) {
		t.Errorf("AttributeMap: %v vs %v", orig.AttributeMap, got.AttributeMap)
	}
}

func TestCodec_EmptyMap_EncodesNil(t *testing.T) {
	orig := IdPRecord{
		TenantID:     "t-nil-map",
		AttributeMap: nil,
	}

	data, err := encode(orig)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	got, err := decode[IdPRecord](data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if got.TenantID != orig.TenantID {
		t.Errorf("TenantID: %q vs %q", orig.TenantID, got.TenantID)
	}
	// nil map should round-trip without error; the decoded value may be nil.
	if len(got.AttributeMap) != 0 {
		t.Errorf("expected nil or empty AttributeMap, got %v", got.AttributeMap)
	}
}

func BenchmarkEncodeIdPRecord(b *testing.B) {
	rec := IdPRecord{
		TenantID:        "t-bench",
		EntityID:        "https://idp.example.com",
		SSOURL:          "https://idp.example.com/sso",
		SLOURL:          "https://idp.example.com/slo",
		SigningCerts:    [][]byte{[]byte("cert1"), []byte("cert2"), []byte("cert3")},
		EncryptionCerts: [][]byte{[]byte("enc1")},
		NameIDFormat:    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		AttributeMap: map[string][]string{
			"email": {"mail", "email"},
			"name":  {"displayName"},
		},
		LastFetched: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := encode(rec)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := decode[IdPRecord](data); err != nil {
			b.Fatal(err)
		}
	}
}
