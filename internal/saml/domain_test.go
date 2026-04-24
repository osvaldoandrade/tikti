package saml

import (
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

func TestIdPRecord_RoundTrip(t *testing.T) {
	samples := []IdPRecord{
		{
			TenantID:        "t-001",
			EntityID:        "https://idp.example.com",
			SSOURL:          "https://idp.example.com/sso",
			SLOURL:          "https://idp.example.com/slo",
			SigningCerts:    [][]byte{[]byte("cert1"), []byte("cert2")},
			EncryptionCerts: [][]byte{[]byte("enc1")},
			NameIDFormat:    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			AttributeMap:    map[string][]string{"email": {"mail", "email"}},
			LastFetched:     time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		},
		{
			TenantID: "t-002",
			EntityID: "https://other.example.com",
		},
		{}, // zero value
	}

	for i, orig := range samples {
		data, err := msgpack.Marshal(orig)
		if err != nil {
			t.Fatalf("sample %d: marshal error: %v", i, err)
		}
		var got IdPRecord
		if err := msgpack.Unmarshal(data, &got); err != nil {
			t.Fatalf("sample %d: unmarshal error: %v", i, err)
		}
		if orig.TenantID != got.TenantID {
			t.Errorf("sample %d: TenantID mismatch: %q vs %q", i, orig.TenantID, got.TenantID)
		}
		if orig.EntityID != got.EntityID {
			t.Errorf("sample %d: EntityID mismatch: %q vs %q", i, orig.EntityID, got.EntityID)
		}
		if orig.SSOURL != got.SSOURL {
			t.Errorf("sample %d: SSOURL mismatch: %q vs %q", i, orig.SSOURL, got.SSOURL)
		}
		if orig.SLOURL != got.SLOURL {
			t.Errorf("sample %d: SLOURL mismatch: %q vs %q", i, orig.SLOURL, got.SLOURL)
		}
		if orig.NameIDFormat != got.NameIDFormat {
			t.Errorf("sample %d: NameIDFormat mismatch: %q vs %q", i, orig.NameIDFormat, got.NameIDFormat)
		}
		if !orig.LastFetched.Equal(got.LastFetched) {
			t.Errorf("sample %d: LastFetched mismatch: %v vs %v", i, orig.LastFetched, got.LastFetched)
		}
	}
}

func TestRequestRecord_RoundTrip(t *testing.T) {
	samples := []RequestRecord{
		{
			ID:           "req-001",
			TenantID:     "t-001",
			RelayState:   "/dashboard",
			ACSURL:       "https://sp.example.com/acs",
			IssueInstant: time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			ID:       "req-002",
			TenantID: "t-002",
		},
		{}, // zero value
	}

	for i, orig := range samples {
		data, err := msgpack.Marshal(orig)
		if err != nil {
			t.Fatalf("sample %d: marshal error: %v", i, err)
		}
		var got RequestRecord
		if err := msgpack.Unmarshal(data, &got); err != nil {
			t.Fatalf("sample %d: unmarshal error: %v", i, err)
		}
		if orig.ID != got.ID {
			t.Errorf("sample %d: ID mismatch: %q vs %q", i, orig.ID, got.ID)
		}
		if orig.TenantID != got.TenantID {
			t.Errorf("sample %d: TenantID mismatch: %q vs %q", i, orig.TenantID, got.TenantID)
		}
		if orig.RelayState != got.RelayState {
			t.Errorf("sample %d: RelayState mismatch: %q vs %q", i, orig.RelayState, got.RelayState)
		}
		if orig.ACSURL != got.ACSURL {
			t.Errorf("sample %d: ACSURL mismatch: %q vs %q", i, orig.ACSURL, got.ACSURL)
		}
		if !orig.IssueInstant.Equal(got.IssueInstant) {
			t.Errorf("sample %d: IssueInstant mismatch: %v vs %v", i, orig.IssueInstant, got.IssueInstant)
		}
	}
}

func TestIndexRecord_RoundTrip(t *testing.T) {
	samples := []IndexRecord{
		{
			TenantID:     "t-001",
			Subject:      "user@example.com",
			SessionIndex: "si-001",
			NotOnOrAfter: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			TenantID: "t-002",
			Subject:  "admin@example.com",
		},
		{}, // zero value
	}

	for i, orig := range samples {
		data, err := msgpack.Marshal(orig)
		if err != nil {
			t.Fatalf("sample %d: marshal error: %v", i, err)
		}
		var got IndexRecord
		if err := msgpack.Unmarshal(data, &got); err != nil {
			t.Fatalf("sample %d: unmarshal error: %v", i, err)
		}
		if orig.TenantID != got.TenantID {
			t.Errorf("sample %d: TenantID mismatch: %q vs %q", i, orig.TenantID, got.TenantID)
		}
		if orig.Subject != got.Subject {
			t.Errorf("sample %d: Subject mismatch: %q vs %q", i, orig.Subject, got.Subject)
		}
		if orig.SessionIndex != got.SessionIndex {
			t.Errorf("sample %d: SessionIndex mismatch: %q vs %q", i, orig.SessionIndex, got.SessionIndex)
		}
		if !orig.NotOnOrAfter.Equal(got.NotOnOrAfter) {
			t.Errorf("sample %d: NotOnOrAfter mismatch: %v vs %v", i, orig.NotOnOrAfter, got.NotOnOrAfter)
		}
	}
}

func TestVerifiedAssertion_NilMap(t *testing.T) {
	orig := VerifiedAssertion{
		AssertionID:  "a-001",
		NameID:       "user@example.com",
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		Attributes:   nil,
	}

	data, err := msgpack.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var got VerifiedAssertion
	if err := msgpack.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if got.Attributes != nil {
		t.Errorf("expected nil Attributes, got %v", got.Attributes)
	}
	if got.AssertionID != orig.AssertionID {
		t.Errorf("AssertionID mismatch: %q vs %q", orig.AssertionID, got.AssertionID)
	}
}

func TestZeroValue_Encodes(t *testing.T) {
	cases := []struct {
		name string
		val  interface{}
	}{
		{"IdPRecord", IdPRecord{}},
		{"RequestRecord", RequestRecord{}},
		{"IndexRecord", IndexRecord{}},
		{"VerifiedAssertion", VerifiedAssertion{}},
	}

	for _, tc := range cases {
		data, err := msgpack.Marshal(tc.val)
		if err != nil {
			t.Errorf("%s: marshal error: %v", tc.name, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("%s: marshal returned empty bytes", tc.name)
		}
	}
}
