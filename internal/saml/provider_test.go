package saml

import "context"

// Compile-time interface compliance check.
var _ Provider = (*stubProvider)(nil)

// stubProvider is an unimplemented stub used only for the compile-time assertion above.
type stubProvider struct{}

func (s *stubProvider) BuildAuthnRequest(_ context.Context, _ BuildAuthnRequestInput) (*AuthnRequest, error) {
	return nil, nil
}

func (s *stubProvider) ValidateResponse(_ context.Context, _ ValidateResponseInput) (*VerifiedAssertion, error) {
	return nil, nil
}

func (s *stubProvider) BuildLogoutRequest(_ context.Context, _ BuildLogoutRequestInput) (*LogoutRequest, error) {
	return nil, nil
}

func (s *stubProvider) ValidateLogoutMessage(_ context.Context, _ ValidateLogoutInput) (*VerifiedLogout, error) {
	return nil, nil
}

func (s *stubProvider) SPMetadata(_ context.Context) ([]byte, error) {
	return nil, nil
}

func (s *stubProvider) ParseIdPMetadata(_ context.Context, _ []byte) (*IdPRecord, error) {
	return nil, nil
}
