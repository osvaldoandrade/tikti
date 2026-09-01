package storagests

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const adminAuthorizerPath = "/internal/v1/object-storage/authorize-admin"

type AdminAuthorizerClient struct {
	endpoint string
	http     *http.Client
	timeout  time.Duration
}

func NewAdminAuthorizerClient(rawEndpoint string, client *http.Client, timeout time.Duration) (*AdminAuthorizerClient, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawEndpoint))
	if err != nil || client == nil || timeout <= 0 || timeout > 10*time.Second || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.EscapedPath() != adminAuthorizerPath ||
		!trustedDependencyScheme(parsed) {
		return nil, ErrInvalidDependencyResponse
	}
	httpClient := *client
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &AdminAuthorizerClient{endpoint: parsed.String(), http: &httpClient, timeout: timeout}, nil
}

func (c *AdminAuthorizerClient) AuthorizeAdmin(ctx context.Context, input AdminAuthorizationRequest, serviceAssertion string) (AdminAuthorizationDecision, error) {
	if c == nil || c.http == nil || len(serviceAssertion) < 16 || len(serviceAssertion) > 16<<10 {
		return AdminAuthorizationDecision{}, ErrDependencyUnavailable
	}
	body, err := json.Marshal(input)
	if err != nil || len(body) > maxRequestBodyBytes {
		zeroBytes(body)
		return AdminAuthorizationDecision{}, ErrInvalidDependencyResponse
	}
	defer zeroBytes(body)
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return AdminAuthorizationDecision{}, ErrDependencyUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+serviceAssertion)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return AdminAuthorizationDecision{}, ErrDependencyUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return AdminAuthorizationDecision{}, ErrDependencyUnavailable
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" ||
		!hasHeaderDirective(response.Header.Get("Cache-Control"), "no-store") ||
		!hasHeaderDirective(response.Header.Get("Pragma"), "no-cache") {
		return AdminAuthorizationDecision{}, ErrInvalidDependencyResponse
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxAuthorizerResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxAuthorizerResponseBytes {
		zeroBytes(raw)
		return AdminAuthorizationDecision{}, ErrInvalidDependencyResponse
	}
	defer zeroBytes(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var decision AdminAuthorizationDecision
	if err := decoder.Decode(&decision); err != nil {
		return AdminAuthorizationDecision{}, ErrInvalidDependencyResponse
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF ||
		(!validAdminAuthorizationDecision(decision, "") && !validAdminDenyDecision(decision)) {
		return AdminAuthorizationDecision{}, ErrInvalidDependencyResponse
	}
	return decision, nil
}
