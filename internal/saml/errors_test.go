package saml

import (
	"errors"
	"fmt"
	"testing"
)

// TestReason_BucketsExhaustive verifies every rejection Reason maps to a
// non-empty ErrorBucket.
func TestReason_BucketsExhaustive(t *testing.T) {
	for _, r := range AllRejectReasons {
		b := r.Bucket()
		if b == "" {
			t.Errorf("Reason %q has no bucket", r)
		}
		switch b {
		case BucketBadRequest, BucketForbidden, BucketNotConfigured, BucketInternal:
			// valid
		default:
			t.Errorf("Reason %q maps to unknown bucket %q", r, b)
		}
	}
}

// TestReason_BucketsExhaustive_Count ensures AllRejectReasons contains
// exactly 18 entries (the closed set from HLD §19).
func TestReason_BucketsExhaustive_Count(t *testing.T) {
	if got := len(AllRejectReasons); got != 18 {
		t.Errorf("expected 18 rejection reasons, got %d", got)
	}
}

// TestReason_OKBucket confirms ReasonOK returns an empty bucket.
func TestReason_OKBucket(t *testing.T) {
	if b := ReasonOK.Bucket(); b != "" {
		t.Errorf("ReasonOK.Bucket() = %q, want empty", b)
	}
}

// TestReason_StringStable checks that every Reason constant has the exact
// string spelling defined in HLD §19.
func TestReason_StringStable(t *testing.T) {
	cases := []struct {
		reason Reason
		want   string
	}{
		{ReasonOK, "ok"},
		{ReasonRequestNotFound, "request_not_found"},
		{ReasonRequestReplay, "request_replay"},
		{ReasonDestinationMismatch, "destination_mismatch"},
		{ReasonIssuerMismatch, "issuer_mismatch"},
		{ReasonStatusNotSuccess, "status_not_success"},
		{ReasonAudienceMismatch, "audience_mismatch"},
		{ReasonSignatureInvalid, "signature_invalid"},
		{ReasonDecryptFailed, "decrypt_failed"},
		{ReasonAssertionSignatureInvalid, "assertion_signature_invalid"},
		{ReasonClockSkew, "clock_skew"},
		{ReasonSubjectConfirmationMismatch, "subject_confirmation_mismatch"},
		{ReasonMissingAttribute, "missing_attribute"},
		{ReasonTIDUnknown, "tid_unknown"},
		{ReasonIDPMetadataStale, "idp_metadata_stale"},
		{ReasonAlgorithmDisallowed, "algorithm_disallowed"},
		{ReasonXXE, "xxe_detected"},
		{ReasonSignatureWrapping, "signature_wrapping_detected"},
		{ReasonInternal, "internal_error"},
	}

	for _, tc := range cases {
		if got := tc.reason.String(); got != tc.want {
			t.Errorf("Reason(%q).String() = %q, want %q", tc.reason, got, tc.want)
		}
	}
}

// TestReason_IsAccept verifies that only ReasonOK returns true.
func TestReason_IsAccept(t *testing.T) {
	if !ReasonOK.IsAccept() {
		t.Error("ReasonOK.IsAccept() = false, want true")
	}
	for _, r := range AllRejectReasons {
		if r.IsAccept() {
			t.Errorf("Reason %q: IsAccept() = true, want false", r)
		}
	}
}

// TestErrorSentinels_Typed asserts that each sentinel satisfies errors.Is and
// that wrapping preserves identity.
func TestErrorSentinels_Typed(t *testing.T) {
	sentinels := []struct {
		name string
		err  error
	}{
		{"ErrRequestNotFound", ErrRequestNotFound},
		{"ErrRequestReplay", ErrRequestReplay},
		{"ErrDestinationMismatch", ErrDestinationMismatch},
		{"ErrIssuerMismatch", ErrIssuerMismatch},
		{"ErrStatusNotSuccess", ErrStatusNotSuccess},
		{"ErrAudienceMismatch", ErrAudienceMismatch},
		{"ErrSignatureInvalid", ErrSignatureInvalid},
		{"ErrDecryptFailed", ErrDecryptFailed},
		{"ErrAssertionSignatureInvalid", ErrAssertionSignatureInvalid},
		{"ErrClockSkew", ErrClockSkew},
		{"ErrSubjectConfirmation", ErrSubjectConfirmation},
		{"ErrMissingAttribute", ErrMissingAttribute},
		{"ErrTIDUnknown", ErrTIDUnknown},
		{"ErrIDPMetadataStale", ErrIDPMetadataStale},
		{"ErrAlgorithmDisallowed", ErrAlgorithmDisallowed},
		{"ErrXXE", ErrXXE},
		{"ErrSignatureWrapping", ErrSignatureWrapping},
		{"ErrInternal", ErrInternal},
	}

	for _, s := range sentinels {
		// Direct match.
		if !errors.Is(s.err, s.err) {
			t.Errorf("%s: errors.Is(err, err) = false", s.name)
		}
		// Wrapped match.
		wrapped := fmt.Errorf("context: %w", s.err)
		if !errors.Is(wrapped, s.err) {
			t.Errorf("%s: errors.Is(wrapped, err) = false", s.name)
		}
		// Non-match: every sentinel must differ from ErrInternal (except ErrInternal itself).
		if s.err != ErrInternal && errors.Is(s.err, ErrInternal) {
			t.Errorf("%s: incorrectly matches ErrInternal", s.name)
		}
	}
}
