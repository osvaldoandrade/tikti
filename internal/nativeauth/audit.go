package nativeauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
)

// RedisAuditor persists only server-selected authority metadata. OAuth request
// parameters, redirect URLs, browser cookies and credentials have no fields.
type RedisAuditor struct{ Client *redis.Client }

func (a RedisAuditor) Emit(ctx context.Context, record AuditRecord) error {
	if a.Client == nil || (record.Event != "native.consent" && record.Event != "native.token") ||
		(record.Phase != "intent" && record.Phase != "outcome") || (record.Decision != "approve" && record.Decision != "deny") ||
		!principalID.MatchString(record.ClientID) || !principalID.MatchString(record.TenantID) || !principalID.MatchString(record.IdentityTenantID) || !fingerprint(record.SubjectHash) {
		return ErrUnavailable
	}
	if _, err := time.Parse(time.RFC3339Nano, record.Timestamp); err != nil {
		return ErrUnavailable
	}
	data, err := json.Marshal(record)
	if err != nil {
		return ErrUnavailable
	}
	digest := sha256.Sum256(data)
	if a.Client.SetNX(ctx, "identity:v2:native:audit:"+hex.EncodeToString(digest[:]), data, 90*24*time.Hour).Err() != nil {
		return ErrUnavailable
	}
	return nil
}
