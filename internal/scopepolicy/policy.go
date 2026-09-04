// Package scopepolicy enforces the offline Code Admin reserved-scope contract.
package scopepolicy

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"
)

const (
	PolicyVersion  = "2026-09-04.1"
	ManifestSHA256 = "9767e336800bb3ef00fd55d38971665962b5b65d1c64e396de2dba5927b56d7d"
	reservedPrefix = "code-admin:"
)

type scopeEntry struct {
	Scope            string `json:"scope"`
	Boundary         string `json:"boundary"`
	TenantAssignable bool   `json:"tenantAssignable"`
	Reason           string `json:"reason,omitempty"`
}

type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	PolicyVersion string       `json:"policyVersion"`
	Scopes        []scopeEntry `json:"scopes"`
}

//go:embed manifest.v1.json
var manifestJSON []byte

var (
	policyOnce   sync.Once
	policyErr    error
	policyScopes map[string]scopeEntry
)

// ValidateCompiled verifies the versioned manifest without a runtime service call.
func ValidateCompiled() error {
	policyOnce.Do(loadPolicy)
	return policyErr
}

// CanonicalPermissions preserves non-Code-Admin permissions for compatibility,
// while reserved Code Admin permissions require an assignable manifest entry.
func CanonicalPermissions(values []string) ([]string, bool) {
	if len(values) < 1 || len(values) > 500 {
		return nil, false
	}
	result := append([]string(nil), values...)
	seen := make(map[string]struct{}, len(result))
	for _, value := range result {
		if !validPermission(value) {
			return nil, false
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, false
		}
		seen[value] = struct{}{}
		if strings.HasPrefix(value, reservedPrefix) {
			if ValidateCompiled() != nil {
				return nil, false
			}
			entry, known := policyScopes[value]
			if !known || !entry.TenantAssignable || entry.Boundary != "tenant" {
				return nil, false
			}
		}
	}
	sort.Strings(result)
	return result, true
}

// ValidCanonicalPermissions requires exact sorted, unique permission storage.
func ValidCanonicalPermissions(values []string) bool {
	canonical, ok := CanonicalPermissions(values)
	return ok && slices.Equal(canonical, values)
}

// CanonicalAudienceScopes accepts the existing scope language while requiring
// every reserved Code Admin scope to exist in the compiled manifest.
func CanonicalAudienceScopes(values []string) ([]string, bool) {
	if len(values) < 1 || len(values) > 500 || ValidateCompiled() != nil {
		return nil, false
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if !validPermission(value) {
			return nil, false
		}
		if strings.HasPrefix(value, reservedPrefix) {
			if _, known := policyScopes[value]; !known {
				return nil, false
			}
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, len(result) > 0
}

// ValidCanonicalAudienceScopes requires exact sorted and unique storage.
func ValidCanonicalAudienceScopes(values []string) bool {
	canonical, ok := CanonicalAudienceScopes(values)
	return ok && slices.Equal(canonical, values)
}

// TenantRoleAssignable reports whether a reserved scope can be granted by an
// exact tenant role. External scopes such as console navigation gates are
// deliberately home-authority-only in tenant-target token exchange.
func TenantRoleAssignable(value string) bool {
	if ValidateCompiled() != nil || !strings.HasPrefix(value, reservedPrefix) {
		return false
	}
	entry, known := policyScopes[value]
	return known && entry.TenantAssignable && entry.Boundary == "tenant"
}

// RequiresHomeAuthority reports whether a canonical audience scope cannot be
// granted by a tenant role and therefore must come from signed home authority.
func RequiresHomeAuthority(value string) bool {
	if !validPermission(value) {
		return false
	}
	if !strings.HasPrefix(value, reservedPrefix) {
		return true
	}
	if ValidateCompiled() != nil {
		return false
	}
	entry, known := policyScopes[value]
	return known && (!entry.TenantAssignable || entry.Boundary != "tenant")
}

func loadPolicy() {
	policyScopes, policyErr = parseManifest(manifestJSON, ManifestSHA256, PolicyVersion)
}

func parseManifest(data []byte, expectedDigest, expectedVersion string) (map[string]scopeEntry, error) {
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		return nil, errors.New("compiled scope policy digest mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var parsed manifest
	if decoder.Decode(&parsed) != nil || parsed.SchemaVersion != 1 || parsed.PolicyVersion != expectedVersion {
		return nil, errors.New("compiled scope policy version mismatch")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("compiled scope policy contains trailing data")
	}
	scopes := make(map[string]scopeEntry, len(parsed.Scopes))
	for _, entry := range parsed.Scopes {
		if entry.Scope == "" || entry.TenantAssignable && entry.Boundary != "tenant" ||
			entry.Boundary != "tenant" && entry.Boundary != "global" && entry.Boundary != "mixed" {
			return nil, errors.New("compiled scope policy contains an invalid entry")
		}
		if _, duplicate := scopes[entry.Scope]; duplicate {
			return nil, errors.New("compiled scope policy contains a duplicate scope")
		}
		scopes[entry.Scope] = entry
	}
	return scopes, nil
}

func validPermission(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/*-", rune(character)) {
			return false
		}
	}
	return true
}
