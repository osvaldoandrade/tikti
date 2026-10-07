// Package codeqbinding implements Tikti's side of the ADR-0022 C2 contract:
// the request/response schema of the code-admin-api QueueTopic binding
// authority, a strict no-cache HTTP client for it, and the per-Pod-identity
// exchange rate limit. It stores no decision, grant or token.
package codeqbinding

import (
	"regexp"
	"strings"
)

const (
	SchemaVersion = "codeq-binding-authority/v1"
	// AuthorityAudience is the exact aud of the Tikti service assertion.
	AuthorityAudience = "code-admin-codeq-binding-authority"
	// ServiceSubject is the exact sub of the Tikti service assertion.
	ServiceSubject = "tikti:codeq-binding-exchange"
	// AuthorityPath is the exact C2 route.
	AuthorityPath = "/internal/v1/codeq-bindings:authorize"

	PolicyPublish   = "Publish"
	PolicySubscribe = "Subscribe"

	// ReasonResolved is the only reason of an allowed decision.
	ReasonResolved = "Resolved"
	// MaxBindings mirrors the API's TooManyBindings bound.
	MaxBindings = 32
)

// deniedReasons is the closed set of C2 allowed:false reasons. An unknown
// reason is an invalid authority response (fail closed).
var deniedReasons = map[string]struct{}{
	"NamespaceNotBound": {}, "ServiceNotFound": {}, "ServiceAmbiguous": {}, "ServiceNotReady": {},
	"PlacementMismatch": {}, "PlacementAmbiguous": {}, "TooManyBindings": {},
}

// excludedReasons is the closed set of C2 per-candidate exclusion reasons.
var excludedReasons = map[string]struct{}{
	"TargetKindUnsupported": {}, "PolicyInvalid": {}, "OwnerMismatch": {}, "BindingNotReady": {},
	"TopicNotFound": {}, "TopicTenantMismatch": {}, "TopicNotReady": {}, "TopicIdentityMismatch": {},
}

var (
	dnsLabelPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	opaqueIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	tenantIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
)

// AuthorityRequest is the exact C2 request. Every identity field comes from
// the verified projected token and the trusted issuer -> clusterRef map.
type AuthorityRequest struct {
	SchemaVersion      string `json:"schemaVersion"`
	RequestID          string `json:"requestId"`
	TenantID           string `json:"tenantId"`
	ClusterRef         string `json:"clusterRef"`
	Namespace          string `json:"namespace"`
	ServiceAccountName string `json:"serviceAccountName"`
	ServiceAccountUID  string `json:"serviceAccountUid"`
	PodUID             string `json:"podUid"`
}

// AuthorityDecision is the exact C2 response body.
type AuthorityDecision struct {
	SchemaVersion string     `json:"schemaVersion"`
	RequestID     string     `json:"requestId"`
	Allowed       *bool      `json:"allowed"`
	Reason        string     `json:"reason"`
	Bindings      []Binding  `json:"bindings"`
	Excluded      []Excluded `json:"excluded"`
}

// IsAllowed reports the decoded allowed flag (false when absent).
func (d AuthorityDecision) IsAllowed() bool { return d.Allowed != nil && *d.Allowed }

// Binding is one eligible QueueTopic ResourceBinding.
type Binding struct {
	BindingUID string `json:"bindingUid"`
	Generation int64  `json:"generation"`
	TopicID    string `json:"topicId"`
	TopicName  string `json:"topicName"`
	Policy     string `json:"policy"`
}

// Excluded is one candidate binding the authority did not make eligible.
type Excluded struct {
	BindingUID string `json:"bindingUid"`
	Reason     string `json:"reason"`
	TopicID    string `json:"topicId"`
	Policy     string `json:"policy"`
}

// ValidTopicName reports whether name is a QueueTopic name (DNS label, <= 63).
func ValidTopicName(name string) bool {
	return len(name) >= 1 && len(name) <= 63 && dnsLabelPattern.MatchString(name)
}

// ValidCanonicalUUID reports whether value is a lowercase hyphenated UUID, the
// shape C2 requires for serviceAccountUid and podUid.
func ValidCanonicalUUID(value string) bool { return uuidPattern.MatchString(value) }

// ValidRequest checks the outbound request against the C2 field shapes so a
// malformed identity is refused locally instead of reaching the API.
func ValidRequest(request AuthorityRequest) bool {
	return request.SchemaVersion == SchemaVersion && ValidCanonicalUUID(request.RequestID) &&
		tenantIDPattern.MatchString(request.TenantID) &&
		len(request.ClusterRef) <= 63 && dnsLabelPattern.MatchString(request.ClusterRef) &&
		len(request.Namespace) <= 63 && dnsLabelPattern.MatchString(request.Namespace) &&
		validDNSSubdomain(request.ServiceAccountName) &&
		ValidCanonicalUUID(request.ServiceAccountUID) && ValidCanonicalUUID(request.PodUID)
}

func validDNSSubdomain(value string) bool {
	if len(value) < 1 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 || !dnsLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

// ValidDecision validates a decoded decision strictly against its request.
func ValidDecision(request AuthorityRequest, decision AuthorityDecision) bool {
	if decision.SchemaVersion != SchemaVersion || decision.RequestID != request.RequestID || decision.Allowed == nil {
		return false
	}
	if !*decision.Allowed {
		_, known := deniedReasons[decision.Reason]
		return known && len(decision.Bindings) == 0 && len(decision.Excluded) == 0
	}
	if decision.Reason != ReasonResolved || len(decision.Bindings) > MaxBindings {
		return false
	}
	prefix := request.TenantID + "."
	seen := make(map[string]struct{}, len(decision.Bindings))
	for _, binding := range decision.Bindings {
		if !opaqueIDPattern.MatchString(binding.BindingUID) || binding.Generation < 1 ||
			!ValidTopicName(binding.TopicName) || binding.TopicID != prefix+binding.TopicName ||
			(binding.Policy != PolicyPublish && binding.Policy != PolicySubscribe) {
			return false
		}
		if _, duplicate := seen[binding.BindingUID]; duplicate {
			return false
		}
		seen[binding.BindingUID] = struct{}{}
	}
	for _, excluded := range decision.Excluded {
		if _, known := excludedReasons[excluded.Reason]; !known ||
			(excluded.BindingUID != "" && !opaqueIDPattern.MatchString(excluded.BindingUID)) ||
			!strings.HasPrefix(excluded.TopicID, prefix) || len(excluded.TopicID) > 320 || !printable(excluded.TopicID) ||
			len(excluded.Policy) > 64 || !printable(excluded.Policy) {
			return false
		}
	}
	return true
}

func printable(value string) bool {
	for _, c := range value {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}
