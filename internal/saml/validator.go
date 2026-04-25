package saml

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/beevik/etree"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

// globalBlockedAlgorithms lists algorithm URIs that are unconditionally
// disallowed regardless of any configuration override.  Per HLD §20.
var globalBlockedAlgorithms = map[string]bool{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":           true,
	"http://www.w3.org/2000/09/xmldsig#sha1":               true,
	"http://www.w3.org/2001/04/xmldsig-more#md5":           true,
	"http://www.w3.org/TR/2001/REC-xml-c14n-20010315":      true,
	"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments": true,
}

// globalBlockedPrefixes lists URI prefixes that are unconditionally disallowed.
var globalBlockedPrefixes = []string{
	"http://www.w3.org/2001/04/xmlenc#des",
	"http://www.w3.org/2001/04/xmlenc#tripledes",
}

// shortNameToSigURI maps the short names used in AllowedSigAlgs to their
// full XML-DSig URIs.
var shortNameToSigURI = map[string]string{
	"rsa-sha256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	"rsa-sha384": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
	"rsa-sha512": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
}

// enforceAllowlist parses the base64-encoded SAML Response XML and rejects
// any disallowed signature, digest, or canonicalization algorithms.
// It also rejects unsigned responses (no ds:Signature element at all).
// The cfg.AllowedSigAlgs field, when non-empty, further restricts which
// signature algorithms are accepted (must be a subset of the global whitelist).
func enforceAllowlist(rawBase64 string, sp config.SPConfig) error {
	xmlBytes, err := base64.StdEncoding.DecodeString(rawBase64)
	if err != nil {
		return ErrAlgorithmDisallowed // cannot parse → reject
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return ErrAlgorithmDisallowed
	}

	// Reject unsigned: at least one ds:Signature must be present.
	sigs := doc.FindElements("//Signature")
	if len(sigs) == 0 {
		sigs = doc.FindElements("//ds:Signature")
	}
	if len(sigs) == 0 {
		return ErrAlgorithmDisallowed
	}

	// Build the config-driven allowlist of full signature algorithm URIs.
	sigAllowSet := make(map[string]bool)
	for _, short := range sp.AllowedSigAlgs {
		if uri, ok := shortNameToSigURI[short]; ok {
			sigAllowSet[uri] = true
		}
	}

	// Check all SignatureMethod, DigestMethod, and CanonicalizationMethod elements.
	for _, path := range []string{
		"//SignatureMethod", "//ds:SignatureMethod",
	} {
		for _, el := range doc.FindElements(path) {
			alg := el.SelectAttrValue("Algorithm", "")
			if err := checkAlgorithm(alg, sigAllowSet); err != nil {
				return err
			}
		}
	}

	for _, path := range []string{
		"//DigestMethod", "//ds:DigestMethod",
	} {
		for _, el := range doc.FindElements(path) {
			alg := el.SelectAttrValue("Algorithm", "")
			if err := checkBlocklisted(alg); err != nil {
				return err
			}
		}
	}

	for _, path := range []string{
		"//CanonicalizationMethod", "//ds:CanonicalizationMethod",
	} {
		for _, el := range doc.FindElements(path) {
			alg := el.SelectAttrValue("Algorithm", "")
			if err := checkBlocklisted(alg); err != nil {
				return err
			}
		}
	}

	for _, path := range []string{
		"//EncryptionMethod", "//xenc:EncryptionMethod",
	} {
		for _, el := range doc.FindElements(path) {
			alg := el.SelectAttrValue("Algorithm", "")
			if err := checkBlocklisted(alg); err != nil {
				return err
			}
		}
	}

	return nil
}

// checkBlocklisted returns ErrAlgorithmDisallowed if the URI is globally blocked.
func checkBlocklisted(uri string) error {
	if globalBlockedAlgorithms[uri] {
		return ErrAlgorithmDisallowed
	}
	for _, prefix := range globalBlockedPrefixes {
		if strings.HasPrefix(uri, prefix) {
			return ErrAlgorithmDisallowed
		}
	}
	return nil
}

// checkAlgorithm checks both the global blocklist and the config-driven
// signature algorithm allowlist.
func checkAlgorithm(uri string, sigAllowSet map[string]bool) error {
	if err := checkBlocklisted(uri); err != nil {
		return err
	}
	// If an allowlist is configured, the algorithm must be in it.
	if len(sigAllowSet) > 0 && !sigAllowSet[uri] {
		return ErrAlgorithmDisallowed
	}
	return nil
}

// validateResponse runs the 10-step SAML Response validation pipeline
// per HLD §9.2 / Appendix A.4.  The Provider performs the actual XML and
// crypto work; this function maps every sentinel error to the matching
// Reason so that the first failure wins and the caller never sees raw
// crypto errors.
func validateResponse(ctx context.Context, prov Provider, clk Clock, idp IdPRecord,
	raw string, req RequestRecord, sp config.SPConfig) (*VerifiedAssertion, Reason, error) {

	// Algorithm allowlist enforcement — invoked before signature verification
	// per HLD §20.
	if err := enforceAllowlist(raw, sp); err != nil {
		return nil, ReasonAlgorithmDisallowed, nil
	}

	va, err := prov.ValidateResponse(ctx, ValidateResponseInput{
		TenantID:             req.TenantID,
		IdP:                  idp,
		RawBase64:            raw,
		RelayState:           req.RelayState,
		Now:                  clk.Now(),
		ExpectedInResponseTo: req.ID,
		ClockSkew:            sp.ClockSkew,
	})

	// First-failure-wins: the provider returns the first sentinel it
	// encounters; we map it to the corresponding Reason.
	switch {
	case errors.Is(err, ErrDestinationMismatch):
		return nil, ReasonDestinationMismatch, nil
	case errors.Is(err, ErrStatusNotSuccess):
		return nil, ReasonStatusNotSuccess, nil
	case errors.Is(err, ErrSignatureInvalid):
		return nil, ReasonSignatureInvalid, nil
	case errors.Is(err, ErrDecryptFailed):
		return nil, ReasonDecryptFailed, nil
	case errors.Is(err, ErrAssertionSignatureInvalid):
		return nil, ReasonAssertionSignatureInvalid, nil
	case errors.Is(err, ErrIssuerMismatch):
		return nil, ReasonIssuerMismatch, nil
	case errors.Is(err, ErrAudienceMismatch):
		return nil, ReasonAudienceMismatch, nil
	case errors.Is(err, ErrClockSkew):
		return nil, ReasonClockSkew, nil
	case errors.Is(err, ErrSubjectConfirmation):
		return nil, ReasonSubjectConfirmationMismatch, nil
	case errors.Is(err, ErrSignatureWrapping):
		return nil, ReasonSignatureWrapping, nil
	case errors.Is(err, ErrAlgorithmDisallowed):
		return nil, ReasonAlgorithmDisallowed, nil
	case errors.Is(err, ErrXXE):
		return nil, ReasonXXE, nil
	case err != nil:
		return nil, ReasonInternal, err
	}

	// Post-crypto attribute gate: NameID must be present.
	if va.NameID == "" {
		return nil, ReasonMissingAttribute, nil
	}

	return va, ReasonOK, nil
}
