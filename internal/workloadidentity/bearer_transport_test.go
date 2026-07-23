package workloadidentity

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestBearerTokenFileTransportReadsRotatingTokenWithoutMutatingRequest(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("first-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var observed []string
	base := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		observed = append(observed, request.Header.Get("Authorization"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("{}")),
			Request:    request,
		}, nil
	})
	transport, err := NewBearerTokenFileTransport(tokenFile, base)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://kubernetes.default.svc/openid/v1/jwks", nil)
	if _, err := transport.RoundTrip(request); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("second-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(request); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("Authorization") != "" {
		t.Fatal("transport mutated the caller request")
	}
	if len(observed) != 2 || observed[0] != "Bearer first-token" || observed[1] != "Bearer second-token" {
		t.Fatalf("authorization headers = %#v", observed)
	}
}

func TestBearerTokenFileTransportRejectsUnsafeOrInvalidFiles(t *testing.T) {
	if _, err := NewBearerTokenFileTransport("relative-token", http.DefaultTransport); err == nil {
		t.Fatal("relative token path was accepted")
	}
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	transport, err := NewBearerTokenFileTransport(tokenFile, http.DefaultTransport)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://kubernetes.default.svc/openid/v1/jwks", nil)
	if _, err := transport.RoundTrip(request); err == nil || strings.Contains(err.Error(), "Bearer") {
		t.Fatalf("unexpected invalid-token error: %v", err)
	}
}
