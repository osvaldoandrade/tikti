package saml

import (
	"context"
	rkeys "github.com/osvaldoandrade/tikti/internal/redis"
)

// SessionSubjectIndexKey and SessionNameIDIndexKey deliberately hash external
// and local identifiers so Redis keys do not become a secondary PII index.
func SessionSubjectIndexKey(tenantID, subject string) string {
	return rkeys.SAMLSessionIndexKey(tenantID, "subject", subject)
}

func SessionNameIDIndexKey(tenantID, nameID string) string {
	return rkeys.SAMLSessionIndexKey(tenantID, "nameid", nameID)
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
