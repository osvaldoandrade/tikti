// Package managedlogs implements the real platform Logs grant authority client.
package managedlogs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	Version           = "managed-logs-authority/v1"
	CollectorVersion  = "managed-logs-collector/v1"
	AuthorityAudience = "code-admin-logs-authority"
	AuthoritySubject  = "tikti:logs-exchange"
	GatewaySubject    = "runtime:logs-api"
	AuthorityPath     = "/internal/v1/logs-grants:authorize"
	TopicName         = "cf-logs"
)

var ErrUnavailable = errors.New("logs authority unavailable")
var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Identity struct {
	ClusterRef         string `json:"clusterRef"`
	Namespace          string `json:"namespace"`
	ServiceAccountName string `json:"serviceAccountName"`
	ServiceAccountUID  string `json:"serviceAccountUid"`
	PodUID             string `json:"podUid"`
}
type Request struct {
	SchemaVersion    string   `json:"schemaVersion"`
	RequestID        string   `json:"requestId"`
	Operation        string   `json:"operation"`
	Identity         Identity `json:"identity"`
	TenantID         string   `json:"tenantId,omitempty"`
	ConfigUID        string   `json:"configUID,omitempty"`
	ConfigGeneration int64    `json:"configGeneration,omitempty"`
}
type Decision struct {
	SchemaVersion    string `json:"schemaVersion"`
	RequestID        string `json:"requestId"`
	Allowed          bool   `json:"allowed"`
	Reason           string `json:"reason"`
	InstallationID   string `json:"installationId,omitempty"`
	ClusterUID       string `json:"clusterUID,omitempty"`
	GrantUID         string `json:"grantUID,omitempty"`
	GrantGeneration  int64  `json:"grantGeneration,omitempty"`
	TenantID         string `json:"tenantId,omitempty"`
	TopicID          string `json:"topicId,omitempty"`
	RetentionSeconds int64  `json:"retentionSeconds,omitempty"`
}

type Authority interface {
	Authorize(context.Context, Request, string) (Decision, error)
}

// ValidDecision rejects alternate tenant semantics and malformed successful grants.
func ValidDecision(r Request, d Decision) bool {
	if d.SchemaVersion != Version || d.RequestID != r.RequestID {
		return false
	}
	if !d.Allowed {
		return d.Reason == "NotAuthorized" && d.InstallationID == "" && d.GrantUID == "" && d.GrantGeneration == 0 && d.TenantID == "" && d.TopicID == "" && d.ClusterUID == "" && d.RetentionSeconds == 0
	}
	if d.Reason != "Resolved" || !safeID.MatchString(d.InstallationID) || !safeID.MatchString(d.ClusterUID) || !safeID.MatchString(d.GrantUID) || d.GrantGeneration < 1 {
		return false
	}
	if r.Operation == "Ingest" || r.Operation == "Resolve" {
		return d.TenantID == "" && d.TopicID == "" && d.RetentionSeconds == 0
	}
	return (r.Operation == "Publish" || r.Operation == "Subscribe") && d.GrantUID == r.ConfigUID && d.GrantGeneration == r.ConfigGeneration && d.TenantID == r.TenantID && d.TopicID == r.TenantID+"."+TopicName && d.RetentionSeconds >= 60 && d.RetentionSeconds <= 2147483647
}

// Client never follows redirects, caches grants, retries or emits response bodies.
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
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, ErrUnavailable
	}
	return &Client{url: raw, http: &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) Authorize(ctx context.Context, r Request, assertion string) (Decision, error) {
	var d Decision
	body, err := json.Marshal(r)
	if err != nil {
		return d, ErrUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return d, ErrUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+assertion)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return d, ErrUnavailable
	}
	defer response.Body.Close()
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" {
		return d, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(raw) > 16384 {
		return d, ErrUnavailable
	}
	if Decode(raw, &d) != nil || !ValidDecision(r, d) {
		return Decision{}, ErrUnavailable
	}
	return d, nil
}
