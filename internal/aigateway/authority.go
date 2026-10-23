// Package aigateway defines the closed AI identity authority protocol.
package aigateway

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	Audience          = "code-llm-service"
	InvokeScope       = "code-llm:invoke"
	ModelsScope       = "code-llm:models:read"
	UsageScope        = "code-llm:usage:read"
	RuntimeAudience   = "code-admin-api"
	RuntimeScope      = "code-admin:ai:runtime"
	AuthorityAudience = "code-admin-ai-identity"
	AuthorityPath     = "/internal/v1/ai-gateway/identity:authorize"
	IdentityVersion   = "ai-identity/v1"
	RuntimeVersion    = "ai-runtime/v1"
)

var ErrUnavailable = errors.New("AI identity authority unavailable")
var ErrDenied = errors.New("AI identity is not authorized")

type Workload struct {
	Issuer            string `json:"issuer"`
	ServiceUID        string `json:"service_uid"`
	ClusterRef        string `json:"cluster_ref"`
	Namespace         string `json:"namespace"`
	ServiceAccount    string `json:"service_account"`
	ServiceAccountUID string `json:"service_account_uid"`
	PodUID            string `json:"pod_uid"`
}

// WorkloadRequest contains only pins verified by the projected-token verifier.
// ServiceUID is deliberately absent; the current API authority resolves it.
type WorkloadRequest struct {
	Issuer            string `json:"issuer"`
	ClusterRef        string `json:"cluster_ref"`
	Namespace         string `json:"namespace"`
	ServiceAccount    string `json:"service_account"`
	ServiceAccountUID string `json:"service_account_uid"`
	PodUID            string `json:"pod_uid"`
}

type Identity struct {
	SchemaVersion string           `json:"schemaVersion"`
	Kind          string           `json:"kind"`
	Subject       string           `json:"subject"`
	TenantID      string           `json:"tenantId"`
	Scopes        []string         `json:"scopes"`
	Workload      *WorkloadRequest `json:"workload,omitempty"`
}

type Principal struct {
	SchemaVersion string    `json:"schemaVersion"`
	TenantID      string    `json:"tenantId"`
	TenantUID     string    `json:"tenantUID"`
	TenantEpoch   string    `json:"tenantEpoch"`
	Subject       string    `json:"subject"`
	PrincipalKind string    `json:"principalKind"`
	Workload      *Workload `json:"workload,omitempty"`
}

type Actor struct {
	Subject           string `json:"sub"`
	Issuer            string `json:"issuer"`
	ServiceUID        string `json:"service_uid"`
	ClusterRef        string `json:"cluster_ref"`
	Namespace         string `json:"namespace"`
	ServiceAccount    string `json:"service_account"`
	ServiceAccountUID string `json:"service_account_uid"`
	PodUID            string `json:"pod_uid"`
}

type Claims struct {
	Issuer        string    `json:"iss"`
	Audience      string    `json:"aud"`
	Subject       string    `json:"sub"`
	TenantID      string    `json:"tid"`
	Scope         string    `json:"scope"`
	IssuedAt      int64     `json:"iat"`
	ExpiresAt     int64     `json:"exp"`
	ID            string    `json:"jti"`
	PrincipalKind string    `json:"principal_kind"`
	TenantUID     string    `json:"tenant_uid"`
	TenantEpoch   string    `json:"tenant_epoch"`
	Version       *int      `json:"ver,omitempty"`
	Workload      *Workload `json:"workload,omitempty"`
	Actor         *Actor    `json:"act,omitempty"`
}

type Runtime struct {
	SchemaVersion     string `json:"schemaVersion"`
	InstallationUID   string `json:"installationUID"`
	ClusterRef        string `json:"cluster_ref"`
	Namespace         string `json:"namespace"`
	ServiceAccount    string `json:"service_account"`
	ServiceAccountUID string `json:"service_account_uid"`
	PodUID            string `json:"pod_uid"`
}

type Authority interface {
	Authorize(context.Context, string) (Principal, error)
}

func ReservedAudience(a string) bool { return strings.EqualFold(strings.TrimSpace(a), Audience) }

func Scopes(values []string) ([]string, bool) {
	if len(values) < 1 || len(values) > 3 {
		return nil, false
	}
	out := slices.Clone(values)
	slices.Sort(out)
	for i, value := range out {
		if value != InvokeScope && value != ModelsScope && value != UsageScope || i > 0 && out[i-1] == value {
			return nil, false
		}
	}
	return out, true
}

// Client admits one configured destination, with no retries, redirects or cache.
type Client struct {
	url  string
	http *http.Client
}

func NewClient(raw string, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(raw)
	if err != nil || raw != strings.TrimSpace(raw) || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Path != AuthorityPath || u.Hostname() == "" || timeout <= 0 || timeout > 10*time.Second {
		return nil, ErrUnavailable
	}
	local := regexp.MustCompile(`^[a-z0-9-]+\.[a-z0-9-]+\.svc\.cluster\.local$`).MatchString(u.Hostname()) && u.Port() != ""
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, ErrUnavailable
		}
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, ErrUnavailable
	}
	return &Client{url: raw, http: &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) Authorize(ctx context.Context, assertion string) (Principal, error) {
	var p Principal
	if c == nil || c.http == nil || assertion == "" || len(assertion) > 16384 || strings.ContainsAny(assertion, " \t\r\n") {
		return p, ErrUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, nil)
	if err != nil {
		return p, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+assertion)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return p, ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return p, ErrDenied
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || err != nil || media != "application/json" {
		return p, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16385))
	if err != nil || Decode(body, &p) != nil {
		return Principal{}, ErrUnavailable
	}
	return p, nil
}
