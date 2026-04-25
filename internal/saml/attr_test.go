package saml

import (
	"errors"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func baseAssertion(attrs map[string][]string) *VerifiedAssertion {
	return &VerifiedAssertion{
		AssertionID:    "a-001",
		NameID:         "user@example.com",
		NameIDFormat:   "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		SessionIndex:   "s-001",
		NotOnOrAfter:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		Attributes:     attrs,
		IssuerEntityID: "https://idp.example.com",
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestMap_AzureFormat(t *testing.T) {
	va := baseAssertion(map[string][]string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {"alice@contoso.com"},
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":         {"Alice Smith"},
	})
	rec := IdPRecord{
		AttributeMap: map[string][]string{
			"email": {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"},
			"name":  {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"},
		},
	}

	email, name, roles, err := MapAttributes(va, rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if email != "alice@contoso.com" {
		t.Errorf("email = %q, want %q", email, "alice@contoso.com")
	}
	if name != "Alice Smith" {
		t.Errorf("name = %q, want %q", name, "Alice Smith")
	}
	if roles != nil {
		t.Errorf("roles = %v, want nil", roles)
	}
}

func TestMap_Okta(t *testing.T) {
	va := baseAssertion(map[string][]string{
		"email": {"bob@okta.dev"},
		"name":  {"Bob Jones"},
	})
	rec := IdPRecord{
		AttributeMap: map[string][]string{
			"email": {"mail", "email"},
			"name":  {"displayName", "name"},
		},
	}

	email, name, _, err := MapAttributes(va, rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if email != "bob@okta.dev" {
		t.Errorf("email = %q, want %q", email, "bob@okta.dev")
	}
	if name != "Bob Jones" {
		t.Errorf("name = %q, want %q", name, "Bob Jones")
	}
}

func TestMap_GoogleGroups(t *testing.T) {
	va := baseAssertion(map[string][]string{
		"email":  {"charlie@google.dev"},
		"groups": {"engineering", "security", "oncall"},
	})
	rec := IdPRecord{
		AttributeMap: map[string][]string{
			"email": {"email"},
			"name":  {"displayName"},
			"roles": {"groups", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"},
		},
	}

	email, _, roles, err := MapAttributes(va, rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if email != "charlie@google.dev" {
		t.Errorf("email = %q, want %q", email, "charlie@google.dev")
	}
	want := []string{"engineering", "security", "oncall"}
	if len(roles) != len(want) {
		t.Fatalf("roles len = %d, want %d", len(roles), len(want))
	}
	for i, r := range roles {
		if r != want[i] {
			t.Errorf("roles[%d] = %q, want %q", i, r, want[i])
		}
	}
}

func TestMap_MissingEmail_Reject(t *testing.T) {
	va := baseAssertion(map[string][]string{
		"name": {"No Email User"},
	})
	rec := IdPRecord{
		AttributeMap: map[string][]string{
			"email": {"mail", "email"},
			"name":  {"displayName", "name"},
		},
	}

	_, _, _, err := MapAttributes(va, rec)
	if err == nil {
		t.Fatal("expected error for missing email")
	}
	var ae *AttrError
	if !errors.As(err, &ae) {
		t.Fatalf("error type = %T, want *AttrError", err)
	}
	if ae.Reason != ReasonMissingAttribute {
		t.Errorf("reason = %q, want %q", ae.Reason, ReasonMissingAttribute)
	}
	if ae.Field != "email" {
		t.Errorf("field = %q, want %q", ae.Field, "email")
	}
}

func TestMap_FirstMatchWins(t *testing.T) {
	va := baseAssertion(map[string][]string{
		"mail":  {"first@example.com"},
		"email": {"second@example.com"},
	})
	rec := IdPRecord{
		AttributeMap: map[string][]string{
			"email": {"mail", "email"},
		},
	}

	email, _, _, err := MapAttributes(va, rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if email != "first@example.com" {
		t.Errorf("email = %q, want %q (first match wins)", email, "first@example.com")
	}
}

func TestMap_NoRoles_NilSlice(t *testing.T) {
	va := baseAssertion(map[string][]string{
		"email": {"noroles@example.com"},
	})
	rec := IdPRecord{
		AttributeMap: map[string][]string{
			"email": {"email"},
			"roles": {"groups"},
		},
	}

	_, _, roles, err := MapAttributes(va, rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if roles != nil {
		t.Errorf("roles = %v, want nil", roles)
	}
}

// ---------------------------------------------------------------------------
// Benchmark — verifies zero allocations in the typical case.
// ---------------------------------------------------------------------------

func BenchmarkMapAttributes(b *testing.B) {
	va := baseAssertion(map[string][]string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {"alice@contoso.com"},
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":         {"Alice Smith"},
		"groups": {"engineering", "security"},
	})
	rec := IdPRecord{
		AttributeMap: map[string][]string{
			"email": {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"},
			"name":  {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"},
			"roles": {"groups"},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		email, name, roles, err := MapAttributes(va, rec)
		if err != nil || email == "" || name == "" || roles == nil {
			b.Fatal("unexpected result")
		}
	}
}
