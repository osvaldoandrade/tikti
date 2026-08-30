package storagests

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxAuthorizerResponseBytes = 32 << 10

var (
	opaqueIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	physicalNamePattern = regexp.MustCompile(`^cf-[a-z0-9]([-a-z0-9]*[a-z0-9])?-[a-f0-9]{12}$`)
	regionPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

type AuthorizerClient struct {
	endpoint string
	http     *http.Client
	timeout  time.Duration
}

func NewAuthorizerClient(rawEndpoint string, client *http.Client, timeout time.Duration) (*AuthorizerClient, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawEndpoint))
	if err != nil || client == nil || timeout <= 0 || timeout > 10*time.Second || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.EscapedPath() != "/internal/v1/object-storage:authorize" || !trustedDependencyScheme(parsed) {
		return nil, ErrInvalidDependencyResponse
	}
	httpClient := *client
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &AuthorizerClient{endpoint: parsed.String(), http: &httpClient, timeout: timeout}, nil
}

func (c *AuthorizerClient) Authorize(
	ctx context.Context, input AuthorizationRequest, serviceAssertion string,
) (AuthorizationDecision, error) {
	if c == nil || c.http == nil || serviceAssertion == "" || len(serviceAssertion) > 16<<10 {
		return AuthorizationDecision{}, ErrDependencyUnavailable
	}
	body, err := json.Marshal(input)
	if err != nil || len(body) > maxRequestBodyBytes {
		zeroBytes(body)
		return AuthorizationDecision{}, ErrInvalidDependencyResponse
	}
	defer zeroBytes(body)
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return AuthorizationDecision{}, ErrDependencyUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+serviceAssertion)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return AuthorizationDecision{}, ErrDependencyUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return AuthorizationDecision{}, ErrDependencyUnavailable
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" ||
		!hasHeaderDirective(response.Header.Get("Cache-Control"), "no-store") ||
		!hasHeaderDirective(response.Header.Get("Pragma"), "no-cache") {
		return AuthorizationDecision{}, ErrInvalidDependencyResponse
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxAuthorizerResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxAuthorizerResponseBytes {
		zeroBytes(raw)
		return AuthorizationDecision{}, ErrInvalidDependencyResponse
	}
	defer zeroBytes(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var decision AuthorizationDecision
	if err := decoder.Decode(&decision); err != nil {
		return AuthorizationDecision{}, ErrInvalidDependencyResponse
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || !validAuthorizationDecision(decision) {
		return AuthorizationDecision{}, ErrInvalidDependencyResponse
	}
	return decision, nil
}

func validAuthorizationDecision(decision AuthorizationDecision) bool {
	if decision.SchemaVersion != ObjectStorageVersion || !validAuthorizationReason(decision.Reason) {
		return false
	}
	if !decision.Allowed {
		return decision.Reason != "Allowed" && decision.Binding == nil && decision.Bucket == nil &&
			decision.Installation == nil && decision.MaximumCredentialTTLSeconds == 0
	}
	return validAllowDecision(decision)
}

func validAllowDecision(decision AuthorizationDecision) bool {
	bucketEndpoint, stsEndpoint := "", ""
	if decision.Bucket != nil {
		bucketEndpoint = decision.Bucket.Endpoint
		stsEndpoint = decision.Bucket.STSEndpoint
	}
	bucketOrigin, bucketOriginOK := normalizedHTTPSOrigin(bucketEndpoint)
	stsOrigin, stsOriginOK := normalizedHTTPSOrigin(stsEndpoint)
	if !decision.Allowed || decision.Reason != "Allowed" || decision.Binding == nil || decision.Bucket == nil ||
		decision.Installation == nil || decision.MaximumCredentialTTLSeconds != defaultCredentialTTL ||
		!opaqueIDPattern.MatchString(decision.Binding.UID) || decision.Binding.Generation < 1 ||
		(decision.Binding.Policy != ReadOnlyAccess && decision.Binding.Policy != ReadWriteAccess) ||
		!opaqueIDPattern.MatchString(decision.Bucket.UID) || decision.Bucket.Generation < 1 ||
		decision.Bucket.ObservedGeneration != decision.Bucket.Generation ||
		len(decision.Bucket.ProviderBucketName) > 63 ||
		!physicalNamePattern.MatchString(decision.Bucket.ProviderBucketName) ||
		!bucketOriginOK || !stsOriginOK || bucketOrigin == stsOrigin || !regionPattern.MatchString(decision.Bucket.Region) ||
		!validDNSLabel(decision.Installation.ID) || decision.Installation.Region != decision.Bucket.Region {
		return false
	}
	return true
}

func validAuthorizationReason(reason string) bool {
	switch reason {
	case "Allowed", "InvalidRequest", "RoleMismatch", "BindingNotReady", "SourceMismatch",
		"BucketNotReady", "InstallationNotReady", "CohortDisabled", "DependencyUnavailable":
		return true
	default:
		return false
	}
}

func exactHTTPSOrigin(raw string) bool {
	_, valid := normalizedHTTPSOrigin(raw)
	return valid
}

func normalizedHTTPSOrigin(raw string) (string, bool) {
	if raw != strings.TrimSpace(raw) {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	return "https://" + strings.ToLower(parsed.Host), true
}

func validHTTPSIssuer(raw string) bool { return exactHTTPSOrigin(raw) }

func trustedDependencyScheme(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	address := net.ParseIP(host)
	return host == "localhost" || address != nil && address.IsLoopback() ||
		strings.HasSuffix(host, ".svc") || strings.HasSuffix(host, ".svc.cluster.local")
}

func hasHeaderDirective(raw, expected string) bool {
	for _, directive := range strings.Split(raw, ",") {
		name := strings.TrimSpace(strings.SplitN(directive, "=", 2)[0])
		if strings.EqualFold(name, expected) {
			return true
		}
	}
	return false
}
