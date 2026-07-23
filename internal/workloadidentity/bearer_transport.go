package workloadidentity

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const maxBearerTokenFileBytes = 64 << 10

// BearerTokenFileTransport authenticates requests with a token read from a
// projected file on every request so Kubernetes token rotation is honored.
type BearerTokenFileTransport struct {
	tokenFile string
	base      http.RoundTripper
}

// NewBearerTokenFileTransport creates a transport for an operator-configured
// absolute token path. Token contents are never retained by the transport.
func NewBearerTokenFileTransport(tokenFile string, base http.RoundTripper) (*BearerTokenFileTransport, error) {
	tokenFile = strings.TrimSpace(tokenFile)
	if tokenFile == "" || !filepath.IsAbs(tokenFile) {
		return nil, fmt.Errorf("JWKS bearer token file must be an absolute path")
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return &BearerTokenFileTransport{tokenFile: tokenFile, base: base}, nil
}

// RoundTrip injects the current projected token without mutating the caller's
// request or placing credentials in a URL.
func (t *BearerTokenFileTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	token, err := readBearerToken(t.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read JWKS bearer token: %w", err)
	}
	cloned := request.Clone(request.Context())
	cloned.Header = request.Header.Clone()
	cloned.Header.Set("Authorization", "Bearer "+token)
	return t.base.RoundTrip(cloned)
}

func readBearerToken(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maxBearerTokenFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(raw) > maxBearerTokenFileBytes {
		return "", fmt.Errorf("token file exceeds %d bytes", maxBearerTokenFileBytes)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("token file is empty")
	}
	return token, nil
}
