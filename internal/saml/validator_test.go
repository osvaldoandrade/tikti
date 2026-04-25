package saml

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/pkg/config"
)

// ---------------------------------------------------------------------------
// Mock provider for validator tests
// ---------------------------------------------------------------------------

type mockValidatorProvider struct {
	stubProvider // embed stub for unimplemented methods
	va           *VerifiedAssertion
	err          error
}

func (m *mockValidatorProvider) ValidateResponse(_ context.Context, _ ValidateResponseInput) (*VerifiedAssertion, error) {
	return m.va, m.err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// goldenResponseBase64 returns a base64-encoded SAML Response with valid
// algorithms (rsa-sha256 signature, sha256 digest, exclusive C14N) for use
// in tests that should pass the algorithm allowlist.
func goldenResponseBase64() string {
	return loadFixtureBase64ForTest("algo_rsa_sha256.xml")
}

// loadFixtureBase64ForTest reads a fixture and returns its base64 encoding.
// It panics on failure because it is used outside *testing.T context (in
// variable initialization). For test-scoped usage prefer loadFixtureBase64.
func loadFixtureBase64ForTest(name string) string {
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		panic(fmt.Sprintf("load fixture %s: %v", name, err))
	}
	return base64.StdEncoding.EncodeToString(data)
}

func goldenAssertion() *VerifiedAssertion {
	return &VerifiedAssertion{
		AssertionID:    "assertion-001",
		NameID:         "user@example.com",
		NameIDFormat:   "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		SessionIndex:   "session-001",
		NotOnOrAfter:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		Attributes:     map[string][]string{"email": {"user@example.com"}},
		IssuerEntityID: "https://idp.example.com",
	}
}

func goldenIdP() IdPRecord {
	return IdPRecord{
		TenantID: "t-001",
		EntityID: "https://idp.example.com",
		SSOURL:   "https://idp.example.com/sso",
	}
}

func goldenRequest() RequestRecord {
	return RequestRecord{
		ID:         "req-001",
		TenantID:   "t-001",
		RelayState: "/dashboard",
		ACSURL:     "https://sp.example.com/saml/acs",
	}
}

func goldenSP() config.SPConfig {
	return config.SPConfig{
		EntityID:       "https://sp.example.com/metadata",
		ACSURL:         "https://sp.example.com/saml/acs",
		ClockSkew:      120 * time.Second,
		AllowedSigAlgs: []string{"rsa-sha256"},
	}
}

// ---------------------------------------------------------------------------
// TestValidate_AcceptGolden — happy path
// ---------------------------------------------------------------------------

func TestValidate_AcceptGolden(t *testing.T) {
	prov := &mockValidatorProvider{va: goldenAssertion()}
	clk := NewFakeClock()

	va, reason, err := validateResponse(
		context.Background(), prov, clk, goldenIdP(),
		goldenResponseBase64(), goldenRequest(), goldenSP(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != ReasonOK {
		t.Fatalf("expected ReasonOK, got %q", reason)
	}
	if va == nil {
		t.Fatal("expected non-nil VerifiedAssertion")
	}
	if va.NameID != "user@example.com" {
		t.Errorf("NameID = %q, want %q", va.NameID, "user@example.com")
	}
}

// ---------------------------------------------------------------------------
// TestValidate_Reject_* — 10 reject branches produce matching Reason
// ---------------------------------------------------------------------------

func TestValidate_Reject(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantReason Reason
	}{
		{"DestinationMismatch", ErrDestinationMismatch, ReasonDestinationMismatch},
		{"StatusNotSuccess", ErrStatusNotSuccess, ReasonStatusNotSuccess},
		{"SignatureInvalid", ErrSignatureInvalid, ReasonSignatureInvalid},
		{"DecryptFailed", ErrDecryptFailed, ReasonDecryptFailed},
		{"AssertionSignatureInvalid", ErrAssertionSignatureInvalid, ReasonAssertionSignatureInvalid},
		{"IssuerMismatch", ErrIssuerMismatch, ReasonIssuerMismatch},
		{"AudienceMismatch", ErrAudienceMismatch, ReasonAudienceMismatch},
		{"ClockSkew", ErrClockSkew, ReasonClockSkew},
		{"SubjectConfirmation", ErrSubjectConfirmation, ReasonSubjectConfirmationMismatch},
		{"SignatureWrapping", ErrSignatureWrapping, ReasonSignatureWrapping},
		{"AlgorithmDisallowed", ErrAlgorithmDisallowed, ReasonAlgorithmDisallowed},
		{"XXE", ErrXXE, ReasonXXE},
		{"MissingNameID", nil, ReasonMissingAttribute}, // provider succeeds but NameID empty
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var prov *mockValidatorProvider
			if tc.err != nil {
				prov = &mockValidatorProvider{err: tc.err}
			} else {
				// MissingNameID case: assertion with empty NameID
				a := goldenAssertion()
				a.NameID = ""
				prov = &mockValidatorProvider{va: a}
			}
			clk := NewFakeClock()

			va, reason, err := validateResponse(
				context.Background(), prov, clk, goldenIdP(),
				goldenResponseBase64(), goldenRequest(), goldenSP(),
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
			if va != nil && tc.err != nil {
				t.Error("expected nil VerifiedAssertion on rejection")
			}
		})
	}
}

// TestValidate_Reject_Internal covers unknown errors mapping to ReasonInternal.
func TestValidate_Reject_Internal(t *testing.T) {
	unknownErr := errors.New("unexpected failure")
	prov := &mockValidatorProvider{err: unknownErr}
	clk := NewFakeClock()

	va, reason, err := validateResponse(
		context.Background(), prov, clk, goldenIdP(),
		goldenResponseBase64(), goldenRequest(), goldenSP(),
	)
	if reason != ReasonInternal {
		t.Errorf("reason = %q, want %q", reason, ReasonInternal)
	}
	if va != nil {
		t.Error("expected nil VerifiedAssertion")
	}
	if !errors.Is(err, unknownErr) {
		t.Errorf("expected original error to be propagated, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestValidate_Reject_WrappedErrors — wrapped sentinel errors still match
// ---------------------------------------------------------------------------

func TestValidate_Reject_WrappedErrors(t *testing.T) {
	cases := []struct {
		sentinel   error
		wantReason Reason
	}{
		{ErrDestinationMismatch, ReasonDestinationMismatch},
		{ErrSignatureInvalid, ReasonSignatureInvalid},
		{ErrClockSkew, ReasonClockSkew},
	}

	for _, tc := range cases {
		t.Run(string(tc.wantReason), func(t *testing.T) {
			wrapped := fmt.Errorf("context: %w", tc.sentinel)
			prov := &mockValidatorProvider{err: wrapped}
			clk := NewFakeClock()

			_, reason, err := validateResponse(
				context.Background(), prov, clk, goldenIdP(),
				goldenResponseBase64(), goldenRequest(), goldenSP(),
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestValidate_FirstFailureWins — provider returns the first error it
// encounters; the validator maps exactly that one.
// ---------------------------------------------------------------------------

func TestValidate_FirstFailureWins(t *testing.T) {
	// Simulate a response that would fail both destination and signature
	// checks.  The provider returns ErrDestinationMismatch (step 2) because
	// it is checked before ErrSignatureInvalid (step 4).
	prov := &mockValidatorProvider{err: ErrDestinationMismatch}
	clk := NewFakeClock()

	_, reason, err := validateResponse(
		context.Background(), prov, clk, goldenIdP(),
		goldenResponseBase64(), goldenRequest(), goldenSP(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != ReasonDestinationMismatch {
		t.Errorf("reason = %q, want %q (first failure should win)",
			reason, ReasonDestinationMismatch)
	}
}

// ---------------------------------------------------------------------------
// TestValidate_AcceptWithAttributes — assertion with NameID in attributes
// ---------------------------------------------------------------------------

func TestValidate_AcceptWithAttributes(t *testing.T) {
	a := goldenAssertion()
	a.Attributes = map[string][]string{
		"email": {"user@example.com"},
		"name":  {"Test User"},
	}
	prov := &mockValidatorProvider{va: a}
	clk := NewFakeClock()

	va, reason, err := validateResponse(
		context.Background(), prov, clk, goldenIdP(),
		goldenResponseBase64(), goldenRequest(), goldenSP(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != ReasonOK {
		t.Fatalf("expected ReasonOK, got %q", reason)
	}
	if va.IssuerEntityID != "https://idp.example.com" {
		t.Errorf("IssuerEntityID = %q, want %q", va.IssuerEntityID, "https://idp.example.com")
	}
}

// ---------------------------------------------------------------------------
// TestAlgo_* — algorithm allowlist enforcement tests (HLD §20 / P2.9)
// ---------------------------------------------------------------------------

// loadFixtureBase64 reads a test XML file and returns it as base64.
func loadFixtureBase64(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func TestAlgo_SHA1_Rejected(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
	}{
		{"RSA-SHA1_Signature", "algo_rsa_sha1.xml"},
		{"SHA1_Digest", "algo_sha1_digest.xml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := loadFixtureBase64(t, tc.fixture)
			prov := &mockValidatorProvider{va: goldenAssertion()}
			clk := NewFakeClock()

			_, reason, err := validateResponse(
				context.Background(), prov, clk, goldenIdP(),
				raw, goldenRequest(), goldenSP(),
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if reason != ReasonAlgorithmDisallowed {
				t.Errorf("reason = %q, want %q", reason, ReasonAlgorithmDisallowed)
			}
		})
	}
}

func TestAlgo_Unsigned_Rejected(t *testing.T) {
	raw := loadFixtureBase64(t, "algo_unsigned.xml")
	prov := &mockValidatorProvider{va: goldenAssertion()}
	clk := NewFakeClock()

	_, reason, err := validateResponse(
		context.Background(), prov, clk, goldenIdP(),
		raw, goldenRequest(), goldenSP(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != ReasonAlgorithmDisallowed {
		t.Errorf("reason = %q, want %q", reason, ReasonAlgorithmDisallowed)
	}
}

func TestAlgo_NonExclusiveC14N_Rejected(t *testing.T) {
	raw := loadFixtureBase64(t, "algo_nonexclusive_c14n.xml")
	prov := &mockValidatorProvider{va: goldenAssertion()}
	clk := NewFakeClock()

	_, reason, err := validateResponse(
		context.Background(), prov, clk, goldenIdP(),
		raw, goldenRequest(), goldenSP(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != ReasonAlgorithmDisallowed {
		t.Errorf("reason = %q, want %q", reason, ReasonAlgorithmDisallowed)
	}
}

func TestAlgo_DES_Rejected(t *testing.T) {
	raw := loadFixtureBase64(t, "algo_des.xml")
	prov := &mockValidatorProvider{va: goldenAssertion()}
	clk := NewFakeClock()

	_, reason, err := validateResponse(
		context.Background(), prov, clk, goldenIdP(),
		raw, goldenRequest(), goldenSP(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != ReasonAlgorithmDisallowed {
		t.Errorf("reason = %q, want %q", reason, ReasonAlgorithmDisallowed)
	}
}

func TestAlgo_MD5_Rejected(t *testing.T) {
	raw := loadFixtureBase64(t, "algo_md5.xml")
	prov := &mockValidatorProvider{va: goldenAssertion()}
	clk := NewFakeClock()

	_, reason, err := validateResponse(
		context.Background(), prov, clk, goldenIdP(),
		raw, goldenRequest(), goldenSP(),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reason != ReasonAlgorithmDisallowed {
		t.Errorf("reason = %q, want %q", reason, ReasonAlgorithmDisallowed)
	}
}

func TestAlgo_ConfigOverride(t *testing.T) {
	raw := loadFixtureBase64(t, "algo_rsa_sha256.xml")

	t.Run("AcceptedByOverride", func(t *testing.T) {
		sp := goldenSP()
		sp.AllowedSigAlgs = []string{"rsa-sha256", "rsa-sha512"}
		prov := &mockValidatorProvider{va: goldenAssertion()}
		clk := NewFakeClock()

		_, reason, err := validateResponse(
			context.Background(), prov, clk, goldenIdP(),
			raw, goldenRequest(), sp,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if reason != ReasonOK {
			t.Errorf("reason = %q, want %q", reason, ReasonOK)
		}
	})

	t.Run("RejectedByOverride", func(t *testing.T) {
		sp := goldenSP()
		// Only allow rsa-sha512 → rsa-sha256 in the fixture should be rejected.
		sp.AllowedSigAlgs = []string{"rsa-sha512"}
		prov := &mockValidatorProvider{va: goldenAssertion()}
		clk := NewFakeClock()

		_, reason, err := validateResponse(
			context.Background(), prov, clk, goldenIdP(),
			raw, goldenRequest(), sp,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if reason != ReasonAlgorithmDisallowed {
			t.Errorf("reason = %q, want %q", reason, ReasonAlgorithmDisallowed)
		}
	})
}

// ---------------------------------------------------------------------------
// TestValidate_InputPassthrough — verifies that validateResponse passes the
// correct input fields to the provider.
// ---------------------------------------------------------------------------

type capturingProvider struct {
	stubProvider
	captured ValidateResponseInput
}

func (p *capturingProvider) ValidateResponse(_ context.Context, in ValidateResponseInput) (*VerifiedAssertion, error) {
	p.captured = in
	return goldenAssertion(), nil
}

func TestValidate_InputPassthrough(t *testing.T) {
	prov := &capturingProvider{}
	clk := NewFakeClock()
	idp := goldenIdP()
	req := goldenRequest()
	sp := goldenSP()
	rawB64 := goldenResponseBase64()

	_, _, err := validateResponse(
		context.Background(), prov, clk, idp,
		rawB64, req, sp,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	c := prov.captured
	if c.TenantID != req.TenantID {
		t.Errorf("TenantID = %q, want %q", c.TenantID, req.TenantID)
	}
	if c.RawBase64 != rawB64 {
		t.Errorf("RawBase64 mismatch")
	}
	if c.RelayState != req.RelayState {
		t.Errorf("RelayState = %q, want %q", c.RelayState, req.RelayState)
	}
	if c.ExpectedInResponseTo != req.ID {
		t.Errorf("ExpectedInResponseTo = %q, want %q", c.ExpectedInResponseTo, req.ID)
	}
	if c.ClockSkew != sp.ClockSkew {
		t.Errorf("ClockSkew = %v, want %v", c.ClockSkew, sp.ClockSkew)
	}
	if c.IdP.EntityID != idp.EntityID {
		t.Errorf("IdP.EntityID = %q, want %q", c.IdP.EntityID, idp.EntityID)
	}
}
