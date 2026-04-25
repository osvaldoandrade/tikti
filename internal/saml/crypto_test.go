package saml

import (
	"errors"
	"testing"
)

// TestXXE_Doctype_Rejected verifies that a simple DOCTYPE declaration
// is rejected by parseXML.
func TestXXE_Doctype_Rejected(t *testing.T) {
	payload := []byte(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo (#PCDATA)>
]>
<foo>bar</foo>`)

	_, err := parseXML(payload)
	if err == nil {
		t.Fatal("expected error for DOCTYPE payload, got nil")
	}
	if !errors.Is(err, ErrXXE) {
		t.Fatalf("expected ErrXXE, got %v", err)
	}
}

// TestXXE_ExternalEntity_Rejected verifies that an external entity
// declaration (file:/// exfiltration vector) is rejected.
func TestXXE_ExternalEntity_Rejected(t *testing.T) {
	payload := []byte(`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`)

	_, err := parseXML(payload)
	if err == nil {
		t.Fatal("expected error for external entity payload, got nil")
	}
	if !errors.Is(err, ErrXXE) {
		t.Fatalf("expected ErrXXE, got %v", err)
	}
}

// TestXXE_Billion_Laughs_Rejected verifies that a Billion Laughs
// (entity expansion) attack is rejected.
func TestXXE_Billion_Laughs_Rejected(t *testing.T) {
	payload := []byte(`<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>`)

	_, err := parseXML(payload)
	if err == nil {
		t.Fatal("expected error for Billion Laughs payload, got nil")
	}
	if !errors.Is(err, ErrXXE) {
		t.Fatalf("expected ErrXXE, got %v", err)
	}
}

// TestParseXML_ValidDocument verifies that legitimate XML is accepted.
func TestParseXML_ValidDocument(t *testing.T) {
	payload := []byte(`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</Issuer>
</Response>`)

	doc, err := parseXML(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc == nil {
		t.Fatal("expected non-nil document")
	}
	root := doc.Root()
	if root == nil {
		t.Fatal("expected non-nil root element")
	}
	if root.Tag != "Response" {
		t.Errorf("root tag = %q, want %q", root.Tag, "Response")
	}
}
