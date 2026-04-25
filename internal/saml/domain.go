package saml

import "time"

// IdPRecord is the trust material for 1 tenant.
type IdPRecord struct {
	TenantID        string              `msgpack:"tid"`
	EntityID        string              `msgpack:"entity_id"`
	SSOURL          string              `msgpack:"sso_url"`
	SLOURL          string              `msgpack:"slo_url"`
	SigningCerts    [][]byte            `msgpack:"signing_certs"`
	EncryptionCerts [][]byte            `msgpack:"encryption_certs"`
	NameIDFormat    string              `msgpack:"name_id_format"`
	AttributeMap    map[string][]string `msgpack:"attribute_map"`
	LastFetched     time.Time           `msgpack:"last_fetched"`
}

// RequestRecord tracks an in-flight SAML AuthnRequest.
type RequestRecord struct {
	ID           string    `msgpack:"id"`
	TenantID     string    `msgpack:"tid"`
	RelayState   string    `msgpack:"relay_state"`
	ACSURL       string    `msgpack:"acs_url"`
	IssueInstant time.Time `msgpack:"issue_instant"`
}

// IndexRecord maps a session index to a subject for SLO.
type IndexRecord struct {
	TenantID     string    `msgpack:"tid"`
	Subject      string    `msgpack:"sub"`
	SessionIndex string    `msgpack:"session_index"`
	NotOnOrAfter time.Time `msgpack:"not_on_or_after"`
}

// VerifiedAssertion holds the validated claims from a SAML Response.
type VerifiedAssertion struct {
	AssertionID    string              `msgpack:"assertion_id"`
	NameID         string              `msgpack:"name_id"`
	NameIDFormat   string              `msgpack:"name_id_format"`
	SessionIndex   string              `msgpack:"session_index"`
	NotOnOrAfter   time.Time           `msgpack:"not_on_or_after"`
	Attributes     map[string][]string `msgpack:"attributes"`
	IssuerEntityID string              `msgpack:"issuer_entity_id"`
}
