package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const TrinoQueryScope = "code-admin:trino:query"

// TrinoPrincipal is authority-derived identity, never a token request DTO.
// TenantEpoch preserves tenant-runtime/v1's lowercase SHA-256 lifetime hash.
type TrinoPrincipal struct {
	InstallationUID string
	TenantID        string
	TenantEpoch     string
	SubjectKind     string
	SubjectUID      string
}

func trinoIdentityPart(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// TrinoInstallationAudience accepts only the dedicated installation namespace.
func TrinoInstallationAudience(audience string) (string, bool) {
	if !strings.HasPrefix(audience, "trino:") {
		return "", false
	}
	uid := strings.TrimPrefix(audience, "trino:")
	return uid, trinoIdentityPart(uid)
}

// OpaquePrincipal implements RFC-0013 section 4's ordered UTF-8 netstrings.
func (p TrinoPrincipal) OpaquePrincipal() (string, error) {
	epoch, err := hex.DecodeString(p.TenantEpoch)
	if !trinoIdentityPart(p.InstallationUID) || !trinoIdentityPart(p.TenantID) || !trinoIdentityPart(p.SubjectUID) || err != nil || len(epoch) != 32 || hex.EncodeToString(epoch) != p.TenantEpoch || (p.SubjectKind != "User" && p.SubjectKind != "Service") {
		return "", errors.New("invalid Trino principal identity")
	}
	var tuple strings.Builder
	for _, field := range []string{p.InstallationUID, p.TenantID, p.TenantEpoch, p.SubjectKind, p.SubjectUID} {
		tuple.WriteString(strconv.Itoa(len(field)))
		tuple.WriteByte(':')
		tuple.WriteString(field)
		tuple.WriteByte(',')
	}
	sum := sha256.Sum256([]byte(tuple.String()))
	return "cfp_" + hex.EncodeToString(sum[:]), nil
}
