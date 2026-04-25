package saml

import "context"

// Compile-time interface compliance check.
var _ SessionBridge = (*stubSessionBridge)(nil)

// stubSessionBridge is an unimplemented stub used only for the compile-time assertion above.
type stubSessionBridge struct{}

func (s *stubSessionBridge) Issue(_ context.Context, _ IssueInput) (string, error) {
	return "", nil
}
