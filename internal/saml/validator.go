package saml

import (
	"context"
	"errors"

	"github.com/osvaldoandrade/tikti/pkg/config"
)

// validateResponse runs the 10-step SAML Response validation pipeline
// per HLD §9.2 / Appendix A.4.  The Provider performs the actual XML and
// crypto work; this function maps every sentinel error to the matching
// Reason so that the first failure wins and the caller never sees raw
// crypto errors.
func validateResponse(ctx context.Context, prov Provider, clk Clock, idp IdPRecord,
	raw string, req RequestRecord, sp config.SPConfig) (*VerifiedAssertion, Reason, error) {

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
