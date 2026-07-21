package domain

import (
	"regexp"
	"strings"
	"time"
)

const (
	WorkloadSubjectTokenType = "urn:ietf:params:oauth:token-type:jwt"
	WorkloadTargetAudience   = "codeq-producer"
	WorkloadAdminScope       = "codeq:admin"
	MaxWorkloadGrants        = 100
)

const workloadSubjectPrefix = "system:serviceaccount:"

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// WorkloadSubject is the verified Kubernetes ServiceAccount identity carried
// by a projected token. It contains no token material.
type WorkloadSubject struct {
	Subject        string
	Namespace      string
	ServiceAccount string
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
	TenantID string   `json:"tenantId"`
	Audience string   `json:"audience"`
	Scopes   []string `json:"scopes"`
}

// WorkloadBinding is the durable subject-to-tenant authorization record.
type WorkloadBinding struct {
	Subject        string          `json:"subject"`
	Namespace      string          `json:"namespace"`
	ServiceAccount string          `json:"serviceAccount"`
	Grants         []WorkloadGrant `json:"grants"`
	Revoked        bool            `json:"revoked"`
	UpdatedAt      time.Time       `json:"updatedAt"`
}

type WorkloadBindingUpsertReq struct {
	Subject        string          `json:"subject"`
	Namespace      string          `json:"namespace"`
	ServiceAccount string          `json:"serviceAccount"`
	Grants         []WorkloadGrant `json:"grants"`
}

type WorkloadBindingRevokeReq struct {
	Subject string `json:"subject"`
}

type WorkloadTokenExchangeReq struct {
	SubjectToken     string   `json:"subjectToken"`
	SubjectTokenType string   `json:"subjectTokenType"`
	Audience         string   `json:"audience"`
	Scopes           []string `json:"scopes"`
	TenantID         string   `json:"tenantId"`
}

type WorkloadTokenExchangeResp struct {
	AccessToken string   `json:"accessToken"`
	TokenType   string   `json:"tokenType"`
	ExpiresIn   int      `json:"expiresIn"`
	Audience    string   `json:"audience"`
	Scopes      []string `json:"scopes"`
	TenantID    string   `json:"tenantId"`
}
