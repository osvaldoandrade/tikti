package saml

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const sessionIndexVersion = "v2"

// SessionSubjectIndexKey and SessionNameIDIndexKey deliberately hash external
// and local identifiers so Redis keys do not become a secondary PII index.
func SessionSubjectIndexKey(tenantID, subject string) string {
	return sessionIndexLookupKey(tenantID, "subject", subject)
}

func SessionNameIDIndexKey(tenantID, nameID string) string {
	return sessionIndexLookupKey(tenantID, "nameid", nameID)
}

func sessionIndexLookupKey(tenantID, kind, value string) string {
	if tenantID == "" || strings.TrimSpace(tenantID) != tenantID || len(tenantID) > 128 ||
		value == "" || strings.TrimSpace(value) != value || len(value) > 1024 {
		return ""
	}
	digest := sha256.Sum256([]byte(sessionIndexVersion + "\x00" + tenantID + "\x00" + kind + "\x00" + value))
	return sessionIndexVersion + ":" + kind + ":" + hex.EncodeToString(digest[:])
}

func putSessionIndex(ctx context.Context, store Store, record IndexRecord) error {
	subjectKey := SessionSubjectIndexKey(record.TenantID, record.Subject)
	nameIDKey := SessionNameIDIndexKey(record.TenantID, record.NameID)
	if store == nil || subjectKey == "" || nameIDKey == "" || record.Email == "" || record.SessionIndex == "" {
		return ErrSessionAuthority
	}
	return store.PutSessionIndexes(ctx, subjectKey, nameIDKey, record)
}

func deleteSessionIndex(ctx context.Context, store Store, record IndexRecord) error {
	subjectKey := SessionSubjectIndexKey(record.TenantID, record.Subject)
	nameIDKey := SessionNameIDIndexKey(record.TenantID, record.NameID)
	if store == nil || subjectKey == "" || nameIDKey == "" {
		return ErrSessionAuthority
	}
	return store.DeleteSessionIndexes(ctx, subjectKey, nameIDKey)
}

func validSessionIndex(record IndexRecord, tenantID, subject, nameID string) bool {
	return record.TenantID == tenantID && record.Subject != "" && record.NameID != "" &&
		record.Email != "" && record.SessionIndex != "" &&
		(subject == "" || record.Subject == subject) && (nameID == "" || record.NameID == nameID)
}
