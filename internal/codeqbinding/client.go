package codeqbinding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

const (
	maxRequestBytes  = 8 << 10
	maxResponseBytes = 64 << 10
	maxAssertion     = 16 << 10
)

var (
	// ErrAuthorityUnavailable covers transport failure, timeout and any
	// non-200 status. No retry is attempted within one exchange.
	ErrAuthorityUnavailable = errors.New("codeq binding authority unavailable")
	// ErrAuthorityInvalidResponse covers any response that does not match the
	// C2 schema exactly.
	ErrAuthorityInvalidResponse = errors.New("codeq binding authority response invalid")
)

// Authority is the decision source used by the exchange. Implementations MUST
// read current state on every call; nothing here caches a decision.
type Authority interface {
	Authorize(ctx context.Context, request AuthorityRequest, serviceAssertion string) (AuthorityDecision, error)
}

// Client calls the C2 authority endpoint. It never follows redirects and never
// retries; every call is bounded by the configured timeout.
type Client struct {
	endpoint string
	http     *http.Client
	timeout  time.Duration
}

// NewClient builds the authority client. The endpoint is validated by
// configuration (config.ValidCodeQBindingAuthorityURL); here it must at least
// carry the exact authority path.
func NewClient(endpoint string, client *http.Client, timeout time.Duration) (*Client, error) {
	endpoint = strings.TrimSpace(endpoint)
	if client == nil || timeout <= 0 || timeout > 10*time.Second || !strings.HasSuffix(endpoint, AuthorityPath) ||
		!(strings.HasPrefix(endpoint, "https://") || strings.HasPrefix(endpoint, "http://")) {
		return nil, errors.New("invalid codeq binding authority client configuration")
	}
	httpClient := *client
	httpClient.Timeout = timeout
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{endpoint: endpoint, http: &httpClient, timeout: timeout}, nil
}

// Authorize sends one decision request and strictly validates the response.
func (c *Client) Authorize(ctx context.Context, request AuthorityRequest, serviceAssertion string) (AuthorityDecision, error) {
	if c == nil || c.http == nil || serviceAssertion == "" || len(serviceAssertion) > maxAssertion || !ValidRequest(request) {
		return AuthorityDecision{}, ErrAuthorityUnavailable
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > maxRequestBytes {
		return AuthorityDecision{}, ErrAuthorityUnavailable
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return AuthorityDecision{}, ErrAuthorityUnavailable
	}
	httpRequest.Header.Set("Authorization", "Bearer "+serviceAssertion)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")
	response, err := c.http.Do(httpRequest)
	if err != nil {
		return AuthorityDecision{}, ErrAuthorityUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return AuthorityDecision{}, ErrAuthorityUnavailable
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" ||
		!hasDirective(response.Header.Values("Cache-Control"), "no-store") ||
		!hasDirective(response.Header.Values("Pragma"), "no-cache") {
		return AuthorityDecision{}, ErrAuthorityInvalidResponse
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return AuthorityDecision{}, ErrAuthorityUnavailable
	}
	if len(raw) == 0 || len(raw) > maxResponseBytes {
		return AuthorityDecision{}, ErrAuthorityInvalidResponse
	}
	decision, err := DecodeDecision(raw)
	if err != nil || !ValidDecision(request, decision) {
		return AuthorityDecision{}, ErrAuthorityInvalidResponse
	}
	return decision, nil
}

// DecodeDecision decodes exactly one JSON object and rejects unknown fields.
func DecodeDecision(raw []byte) (AuthorityDecision, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var decision AuthorityDecision
	if err := decoder.Decode(&decision); err != nil {
		return AuthorityDecision{}, ErrAuthorityInvalidResponse
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return AuthorityDecision{}, ErrAuthorityInvalidResponse
	}
	return decision, nil
}

func hasDirective(values []string, expected string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			name := strings.TrimSpace(strings.SplitN(directive, "=", 2)[0])
			if strings.EqualFold(name, expected) {
				return true
			}
		}
	}
	return false
}
