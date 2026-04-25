package saml

import "fmt"

// MapAttributes extracts email, name, and roles from a VerifiedAssertion
// using the per-tenant attribute map stored in rec.AttributeMap.
//
// First-match semantics: for each Tikti field the mapped IdP attribute names
// are tried in order; the first non-empty value wins.
//
// Email is required. If it cannot be resolved, a ReasonMissingAttribute
// error is returned. Name and roles are optional.
func MapAttributes(va *VerifiedAssertion, rec IdPRecord) (email, name string, roles []string, err error) {
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
