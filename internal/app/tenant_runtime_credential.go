package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// tenantRuntimeStateCredentialLabel binds the derived credential to the one
// read-only tenant runtime-state route. Changing it is a breaking contract
// change for every installation that holds the derived value.
const tenantRuntimeStateCredentialLabel = "code-foundry/tikti/tenant-runtime-state/v1" // #nosec G101 -- public HMAC domain-separation label, not a credential.

// deriveTenantRuntimeStateCredential returns lowercase hex(HMAC-SHA256(key =
// master, message = ASCII label)), 64 characters. The master is used exactly
// as Tikti compares it (cfg.ApiKey after configuration loading); no further
// normalization happens here. An empty master never yields a credential.
//
// The derived value is purpose-bound by construction: only the tenant
// runtime-state handler holds it. The shared RequiredApiKeyHeader middleware
// compares against the master key alone, so the derived value is an ordinary
// wrong key on every other route.
func deriveTenantRuntimeStateCredential(master string) (string, bool) {
	if master == "" {
		return "", false
	}
	mac := hmac.New(sha256.New, []byte(master))
	_, _ = mac.Write([]byte(tenantRuntimeStateCredentialLabel))
	return hex.EncodeToString(mac.Sum(nil)), true
}
