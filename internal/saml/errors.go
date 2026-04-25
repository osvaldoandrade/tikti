package saml

import "errors"

// Reason is a closed-set string identifying why a SAML login was rejected
// (or accepted). The values match HLD §19 exactly and must not be changed
// without a schema-version bump.
type Reason string

const (
	// ReasonOK is the only accept-path value; every other Reason is a rejection.
	ReasonOK Reason = "ok"

	// 18 rejection reasons — HLD §19.
	ReasonRequestNotFound              Reason = "request_not_found"
	ReasonRequestReplay                Reason = "request_replay"
	ReasonDestinationMismatch          Reason = "destination_mismatch"
	ReasonIssuerMismatch               Reason = "issuer_mismatch"
	ReasonStatusNotSuccess             Reason = "status_not_success"
	ReasonAudienceMismatch             Reason = "audience_mismatch"
	ReasonSignatureInvalid             Reason = "signature_invalid"
	ReasonDecryptFailed                Reason = "decrypt_failed"
	ReasonAssertionSignatureInvalid    Reason = "assertion_signature_invalid"
	ReasonClockSkew                    Reason = "clock_skew"
	ReasonSubjectConfirmationMismatch  Reason = "subject_confirmation_mismatch"
	ReasonMissingAttribute             Reason = "missing_attribute"
	ReasonTIDUnknown                   Reason = "tid_unknown"
	ReasonIDPMetadataStale             Reason = "idp_metadata_stale"
	ReasonAlgorithmDisallowed          Reason = "algorithm_disallowed"
	ReasonXXE                          Reason = "xxe_detected"
	ReasonSignatureWrapping            Reason = "signature_wrapping_detected"
	ReasonInternal                     Reason = "internal_error"
)

// AllRejectReasons enumerates every rejection Reason (excludes ReasonOK).
// Used by tests to ensure exhaustive bucket coverage.
var AllRejectReasons = [...]Reason{
	ReasonRequestNotFound,
	ReasonRequestReplay,
	ReasonDestinationMismatch,
	ReasonIssuerMismatch,
	ReasonStatusNotSuccess,
	ReasonAudienceMismatch,
	ReasonSignatureInvalid,
	ReasonDecryptFailed,
	ReasonAssertionSignatureInvalid,
	ReasonClockSkew,
	ReasonSubjectConfirmationMismatch,
	ReasonMissingAttribute,
	ReasonTIDUnknown,
	ReasonIDPMetadataStale,
	ReasonAlgorithmDisallowed,
	ReasonXXE,
	ReasonSignatureWrapping,
	ReasonInternal,
}

// String returns the stable wire-format spelling of the reason.
func (r Reason) String() string { return string(r) }

// IsAccept returns true only for ReasonOK.
func (r Reason) IsAccept() bool { return r == ReasonOK }

// ---------------------------------------------------------------------------
// Error buckets — HLD Appendix Q
// ---------------------------------------------------------------------------

// ErrorBucket classifies a rejection reason into one of four user-facing
// categories. The bucket determines the HTTP status and neutral message shown.
type ErrorBucket string

const (
	BucketBadRequest    ErrorBucket = "bad_request"
	BucketForbidden     ErrorBucket = "forbidden"
	BucketNotConfigured ErrorBucket = "not_configured"
	BucketInternal      ErrorBucket = "internal"
)

// Bucket maps a Reason to its ErrorBucket per HLD Appendix Q.
// ReasonOK returns an empty bucket because it is not an error.
func (r Reason) Bucket() ErrorBucket {
	switch r {
	// bad_request (400)
	case ReasonDestinationMismatch, ReasonRequestNotFound, ReasonMissingAttribute:
		return BucketBadRequest

	// forbidden (403)
	case ReasonSignatureInvalid, ReasonAssertionSignatureInvalid,
		ReasonSignatureWrapping, ReasonAlgorithmDisallowed,
		ReasonDecryptFailed, ReasonXXE,
		ReasonAudienceMismatch, ReasonIssuerMismatch,
		ReasonSubjectConfirmationMismatch, ReasonRequestReplay,
		ReasonClockSkew, ReasonStatusNotSuccess:
		return BucketForbidden

	// not_configured (404)
	case ReasonTIDUnknown:
		return BucketNotConfigured

	// internal (500)
	case ReasonIDPMetadataStale, ReasonInternal:
		return BucketInternal

	default: // ReasonOK or unknown
		return ""
	}
}

// ---------------------------------------------------------------------------
// Sentinel errors — returned by the provider adapter, mapped to Reason
// by the validator.
// ---------------------------------------------------------------------------

var (
	ErrRequestNotFound           = errors.New("saml: request not found")
	ErrRequestReplay             = errors.New("saml: request replay")
	ErrDestinationMismatch       = errors.New("saml: destination mismatch")
	ErrIssuerMismatch            = errors.New("saml: issuer mismatch")
	ErrStatusNotSuccess          = errors.New("saml: status not success")
	ErrAudienceMismatch          = errors.New("saml: audience mismatch")
	ErrSignatureInvalid          = errors.New("saml: signature invalid")
	ErrDecryptFailed             = errors.New("saml: decrypt failed")
	ErrAssertionSignatureInvalid = errors.New("saml: assertion signature invalid")
	ErrClockSkew                 = errors.New("saml: clock skew")
	ErrSubjectConfirmation       = errors.New("saml: subject confirmation mismatch")
	ErrMissingAttribute          = errors.New("saml: missing attribute")
	ErrTIDUnknown                = errors.New("saml: tenant id unknown")
	ErrIDPMetadataStale          = errors.New("saml: idp metadata stale")
	ErrAlgorithmDisallowed       = errors.New("saml: algorithm disallowed")
	ErrXXE                       = errors.New("saml: xxe detected")
	ErrSignatureWrapping         = errors.New("saml: signature wrapping detected")
	ErrInternal                  = errors.New("saml: internal error")
)
