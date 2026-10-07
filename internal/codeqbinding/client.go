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
	// non-200 status. No retry is attempted within one exchange. The
	// returned error is an *AuthorityError carrying the failure class.
	ErrAuthorityUnavailable = errors.New("codeq binding authority unavailable")
	// ErrAuthorityInvalidResponse covers any response that does not match the
	// C2 schema exactly.
	ErrAuthorityInvalidResponse = errors.New("codeq binding authority response invalid")
)

// Closed failure classes of one authority call. They are metric label values
// and audit fields; none carries a response body.
const (
	// FailureLocal: the request was refused before it was sent.
	FailureLocal = "local"
	// FailureTransport: connection error, timeout or cancellation.
	FailureTransport = "transport"
	// FailureThrottled: the authority answered 429 or 503 (busy, store
	// unavailable or deadline). The caller may retry shortly.
	FailureThrottled = "throttled"
	// FailureRejected: the authority answered 401 or 403 to Tikti's service
	// assertion. This is a misconfiguration (issuer, audience, subject or
	// IDENTITY_AUDIENCES), not an outage.
	FailureRejected = "rejected"
	// FailureStatus: any other non-200 status.
	FailureStatus = "status"
	// FailureInvalid: a 200 response that does not match the C2 schema.
	FailureInvalid = "invalid"
)

// AuthorityError classifies a failed authority call. It wraps
// ErrAuthorityUnavailable or ErrAuthorityInvalidResponse, so errors.Is keeps
// working. Status is the HTTP status, 0 when no response was received.
type AuthorityError struct {
	Class  string
	Status int
	err    error
}

func (e *AuthorityError) Error() string { return e.err.Error() + " (" + e.Class + ")" }

func (e *AuthorityError) Unwrap() error { return e.err }

func failure(class string, status int, err error) error {
	return &AuthorityError{Class: class, Status: status, err: err}
}

// ClassifyFailure returns the closed failure class and HTTP status of err.
// An error that is not an *AuthorityError (another Authority implementation)
// is FailureInvalid when it wraps ErrAuthorityInvalidResponse and
// FailureTransport otherwise.
func ClassifyFailure(err error) (string, int) {
	var classified *AuthorityError
	if errors.As(err, &classified) {
		return classified.Class, classified.Status
	}
	if errors.Is(err, ErrAuthorityInvalidResponse) {
		return FailureInvalid, 0
	}
	return FailureTransport, 0
}

func statusFailure(status int) error {
	switch status {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return failure(FailureThrottled, status, ErrAuthorityUnavailable)
	case http.StatusUnauthorized, http.StatusForbidden:
		return failure(FailureRejected, status, ErrAuthorityUnavailable)
	default:
		return failure(FailureStatus, status, ErrAuthorityUnavailable)
	}
}

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
		return AuthorityDecision{}, failure(FailureLocal, 0, ErrAuthorityUnavailable)
	}
	body, err := json.Marshal(request)
	if err != nil || len(body) > maxRequestBytes {
		return AuthorityDecision{}, failure(FailureLocal, 0, ErrAuthorityUnavailable)
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return AuthorityDecision{}, failure(FailureLocal, 0, ErrAuthorityUnavailable)
	}
	httpRequest.Header.Set("Authorization", "Bearer "+serviceAssertion)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")
	response, err := c.http.Do(httpRequest)
	if err != nil {
		return AuthorityDecision{}, failure(FailureTransport, 0, ErrAuthorityUnavailable)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return AuthorityDecision{}, statusFailure(response.StatusCode)
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" ||
		!hasDirective(response.Header.Values("Cache-Control"), "no-store") ||
		!hasDirective(response.Header.Values("Pragma"), "no-cache") {
		return AuthorityDecision{}, failure(FailureInvalid, response.StatusCode, ErrAuthorityInvalidResponse)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return AuthorityDecision{}, failure(FailureTransport, response.StatusCode, ErrAuthorityUnavailable)
	}
	if len(raw) == 0 || len(raw) > maxResponseBytes {
		return AuthorityDecision{}, failure(FailureInvalid, response.StatusCode, ErrAuthorityInvalidResponse)
	}
	decision, err := DecodeDecision(raw)
	if err != nil || !ValidDecision(request, decision) {
		return AuthorityDecision{}, failure(FailureInvalid, response.StatusCode, ErrAuthorityInvalidResponse)
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
