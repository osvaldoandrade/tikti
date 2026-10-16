package redis

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

const sessionIndexVersion = "v2"

// SAMLSessionIndexRecord is the existing persisted SLO session projection.
type SAMLSessionIndexRecord struct {
	TenantID     string    `msgpack:"tid"`
	Subject      string    `msgpack:"sub"`
	NameID       string    `msgpack:"name_id"`
	Email        string    `msgpack:"email"`
	SessionIndex string    `msgpack:"session_index"`
	NotOnOrAfter time.Time `msgpack:"not_on_or_after"`
}

// SAMLSessionIndexKey keeps identifiers out of Redis lookup keys.
func SAMLSessionIndexKey(tenantID, kind, value string) string {
	if tenantID == "" || strings.TrimSpace(tenantID) != tenantID || len(tenantID) > 128 ||
		value == "" || strings.TrimSpace(value) != value || len(value) > 1024 {
		return ""
	}
	digest := sha256.Sum256([]byte(sessionIndexVersion + "\x00" + tenantID + "\x00" + kind + "\x00" + value))
	return sessionIndexVersion + ":" + kind + ":" + hex.EncodeToString(digest[:])
}
