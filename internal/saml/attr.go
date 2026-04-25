package saml

import (
	"fmt"
	"log"
)

// tidDenylist contains attribute names that must never be taken from a SAML
// assertion because tid is always sourced from the URL path.
var tidDenylist = map[string]bool{
	"tid":       true,
	"tenant_id": true,
	"tenantId":  true,
}

// SanitizeAttributes strips tid-like attributes from a SAML assertion's
// attribute map. When a tid-like attribute is found it is deleted, a metric
// is incremented, and an INFO-level log line is emitted.
//
// urlTID is the tenant ID extracted from the URL path and is used only for
// metric labels — it is never overwritten.
func SanitizeAttributes(attrs map[string][]string, urlTID string, m *Metrics) {
	for k := range attrs {
		if tidDenylist[k] {
			log.Printf("saml: ignoring assertion-supplied %q attribute for tid %s", k, urlTID)
			if m != nil {
				m.TIDOverrideIgnored.WithLabelValues(urlTID).Inc()
			}
			delete(attrs, k)
		}
	}
}

// MapAttributes extracts email, name, and roles from a VerifiedAssertion
// using the per-tenant attribute map stored in rec.AttributeMap.
//
// Before extraction, any assertion-supplied tid-like attributes (tid,
// tenant_id, tenantId) are stripped to prevent cross-tenant escalation.
// When such attributes are found a metric is incremented and an INFO log
// is emitted.
//
// First-match semantics: for each Tikti field the mapped IdP attribute names
// are tried in order; the first non-empty value wins.
//
// Email is required. If it cannot be resolved, a ReasonMissingAttribute
// error is returned. Name and roles are optional.
func MapAttributes(va *VerifiedAssertion, rec IdPRecord, urlTID string, m *Metrics) (email, name string, roles []string, err error) {
	SanitizeAttributes(va.Attributes, urlTID, m)

	email = firstValue(va, rec.AttributeMap["email"])
	if email == "" {
		return "", "", nil, &AttrError{Reason: ReasonMissingAttribute, Field: "email"}
	}

	name = firstValue(va, rec.AttributeMap["name"])

	roles = allValues(va, rec.AttributeMap["roles"])
	return email, name, roles, nil
}

// firstValue tries each mapped attribute name in order and returns the first
// non-empty value from the assertion. Returns "" if none found.
func firstValue(va *VerifiedAssertion, keys []string) string {
	for _, k := range keys {
		if vals := va.Attributes[k]; len(vals) > 0 && vals[0] != "" {
			return vals[0]
		}
	}
	return ""
}

// allValues collects every value for the first matched attribute key.
// Returns nil (not an empty slice) when no values are found, so callers
// can distinguish "no roles mapped" from "roles mapped but empty".
func allValues(va *VerifiedAssertion, keys []string) []string {
	for _, k := range keys {
		if vals := va.Attributes[k]; len(vals) > 0 {
			return vals
		}
	}
	return nil
}

// AttrError is returned by MapAttributes when a required attribute is missing.
type AttrError struct {
	Reason Reason
	Field  string
}

func (e *AttrError) Error() string {
	return fmt.Sprintf("saml: %s: %s", e.Reason, e.Field)
}
