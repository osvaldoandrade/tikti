// Package redis provides shared Redis key-prefix constants used across the
// application.  Centralising prefixes avoids typo-induced cross-feature
// collisions and makes key-layout changes a one-line diff.
package redis

// SAML key prefixes — see HLD §15 / Appendix C.
const (
	SAMLRequestPrefix    = "saml:req:"
	SAMLIdPPrefix        = "saml:idp:"
	SAMLIndexPrefix      = "saml:idx:"
	SAMLSeenPrefix       = "saml:seen:"
	SAMLDomainPrefix     = "saml:discover:domain:"
	SAMLSPRotationKey    = "saml:sp:rotation"
)
