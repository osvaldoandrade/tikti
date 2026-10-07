package domain

import (
	"regexp"
	"strings"
	"time"
)

const (
	WorkloadSubjectTokenType = "urn:ietf:params:oauth:token-type:jwt" // #nosec G101 -- public OAuth token-type identifier, not a credential.
	WorkloadProducerAudience = "codeq-producer"
	WorkloadWorkerAudience   = "codeq-worker"
	WorkloadAdminScope       = "codeq:admin"
	WorkloadClaimScope       = "codeq:claim"
	WorkloadNackScope        = "codeq:nack"
	WorkloadResultScope      = "codeq:result"
	// WorkloadTargetAudience preserves the producer contract for existing clients.
	WorkloadTargetAudience = WorkloadProducerAudience
	MaxWorkloadGrants      = 100
	MaxWorkloadEventTypes  = 100
)

const workloadSubjectPrefix = "system:serviceaccount:"

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// WorkloadSubject is the verified Kubernetes ServiceAccount identity carried
// by a projected token. It contains no token material.
type WorkloadSubject struct {
	// Signed object lifetimes; empty only for legacy unbound identity tokens.
	ServiceAccountUID string
	PodUID            string
	Subject           string
	Issuer            string
	ClusterRef        string
	Namespace         string
	ServiceAccount    string
	// ExpiresAt is the verified exp of the projected token; zero when the
	// verifier did not report it (callers that bound a lifetime fail closed).
	ExpiresAt time.Time
}

// ParseWorkloadSubject validates the canonical Kubernetes ServiceAccount
// subject. Namespaces are DNS labels while ServiceAccount names are DNS
// subdomains, matching the Kubernetes object-name constraints.
func ParseWorkloadSubject(raw string) (WorkloadSubject, bool) {
	subject := strings.TrimSpace(raw)
	if !strings.HasPrefix(subject, workloadSubjectPrefix) {
		return WorkloadSubject{}, false
	}
	parts := strings.Split(strings.TrimPrefix(subject, workloadSubjectPrefix), ":")
	if len(parts) != 2 || !validDNSLabel(parts[0]) || !validDNSSubdomain(parts[1]) {
		return WorkloadSubject{}, false
	}
	return WorkloadSubject{Subject: subject, Namespace: parts[0], ServiceAccount: parts[1]}, true
}

func validDNSLabel(value string) bool {
	return len(value) >= 1 && len(value) <= 63 && dnsLabelPattern.MatchString(value)
}

func validDNSSubdomain(value string) bool {
	if len(value) < 1 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

// WorkloadGrant authorizes one workload subject to mint a narrowly scoped
// access token for one tenant.
type WorkloadGrant struct {
	TenantID   string   `json:"tenantId"`
	Audience   string   `json:"audience"`
	Scopes     []string `json:"scopes"`
	EventTypes []string `json:"eventTypes,omitempty"`
}

// WorkloadBinding is the durable subject-to-tenant authorization record.
// ClusterRef and ServiceAccountUID are optional scoping fields: when set, the
// legacy exchange matches them against the verified subject. A record with a
// ClusterRef is stored under WorkloadBindingKey(clusterRef, subject) so that
// the same namespace/ServiceAccount name on two trusted clusters never shares
// one record (ADR-0022 E9).
type WorkloadBinding struct {
	Subject           string          `json:"subject"`
	Namespace         string          `json:"namespace"`
	ServiceAccount    string          `json:"serviceAccount"`
	ClusterRef        string          `json:"clusterRef,omitempty"`
	ServiceAccountUID string          `json:"serviceAccountUid,omitempty"`
	Grants            []WorkloadGrant `json:"grants"`
	Revoked           bool            `json:"revoked"`
	UpdatedAt         time.Time       `json:"updatedAt"`
}

type WorkloadBindingUpsertReq struct {
	Subject           string          `json:"subject"`
	Namespace         string          `json:"namespace"`
	ServiceAccount    string          `json:"serviceAccount"`
	ClusterRef        string          `json:"clusterRef,omitempty"`
	ServiceAccountUID string          `json:"serviceAccountUid,omitempty"`
	Grants            []WorkloadGrant `json:"grants"`
}

type WorkloadBindingRevokeReq struct {
	Subject    string `json:"subject"`
	ClusterRef string `json:"clusterRef,omitempty"`
}

// WorkloadBindingKey is the storage key of a WorkloadBinding. Unscoped legacy
// records keep the bare subject; scoped records are clusterRef + NUL + subject.
func WorkloadBindingKey(clusterRef, subject string) string {
	if clusterRef == "" {
		return subject
	}
	return clusterRef + "\x00" + subject
}

// ValidWorkloadClusterRef reports whether value is an operator clusterRef
// (a Kubernetes DNS label).
func ValidWorkloadClusterRef(value string) bool {
	return validDNSLabel(value)
}

// ValidWorkloadObjectUID accepts the signed Kubernetes object UID shape that
// the projected-token verifier preserves (1..128 of [A-Za-z0-9-]).
func ValidWorkloadObjectUID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

type WorkloadTokenExchangeReq struct {
	SubjectToken     string   `json:"subjectToken"`
	SubjectTokenType string   `json:"subjectTokenType"`
	Audience         string   `json:"audience"`
	Scopes           []string `json:"scopes"`
	TenantID         string   `json:"tenantId"`
	// CodeQTopicID selects the ADR-0022 binding-scoped CodeQ grant. It is
	// "<tenantId>.<topicName>". The request never carries cluster, namespace,
	// ServiceAccount or UIDs: those come only from the verified subject token.
	CodeQTopicID string `json:"codeqTopicId,omitempty"`
}

// WorkloadExchangeError is a client-safe refusal with a stable code and the
// exchange correlation ID. It never carries token material or dependency
// detail. Status is the HTTP status; RetryAfterSeconds, when positive, is sent
// as Retry-After.
type WorkloadExchangeError struct {
	Status            int
	Code              string
	CorrelationID     string
	RetryAfterSeconds int
}

func (e *WorkloadExchangeError) Error() string {
	if e == nil {
		return "workload exchange refused"
	}
	return "workload exchange refused: " + e.Code
}

type WorkloadTokenExchangeResp struct {
	AccessToken string   `json:"accessToken"`
	TokenType   string   `json:"tokenType"`
	ExpiresIn   int      `json:"expiresIn"`
	Audience    string   `json:"audience"`
	Scopes      []string `json:"scopes"`
	TenantID    string   `json:"tenantId"`
	EventTypes  []string `json:"eventTypes,omitempty"`
}
