package scopepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestCompiledPolicyVersionDigestAndNamespaceBoundary(t *testing.T) {
	if err := ValidateCompiled(); err != nil {
		t.Fatalf("compiled policy: %v", err)
	}
	digest := sha256.Sum256(manifestJSON)
	if PolicyVersion != "2026-09-04.1" || hex.EncodeToString(digest[:]) != ManifestSHA256 {
		t.Fatalf("unexpected policy identity: %s %x", PolicyVersion, digest)
	}
	tests := []struct {
		scope string
		want  bool
	}{
		{scope: "code-admin:services:read", want: true},
		{scope: "code-admin:identity:write", want: true},
		{scope: "codeq:claim", want: true},
		{scope: "bereia:read", want: true},
		{scope: "code-admin:tenants:admin"},
		{scope: "code-admin:platform:read"},
		{scope: "code-admin:clusters:read"},
		{scope: "code-admin:repositories:read"},
		{scope: "code-admin:identity:read"},
		{scope: "code-admin:secrets:read"},
		{scope: "code-admin:secrets:write"},
		{scope: "code-admin:owners:delegate"},
		{scope: "code-admin:unknown:read"},
	}
	for _, test := range tests {
		t.Run(test.scope, func(t *testing.T) {
			got, ok := CanonicalPermissions([]string{test.scope})
			if ok != test.want || ok && !reflect.DeepEqual(got, []string{test.scope}) {
				t.Fatalf("CanonicalPermissions(%q) = %q, %v", test.scope, got, ok)
			}
		})
	}
}

func TestCanonicalPermissionsAreSortedUniqueAndDefensive(t *testing.T) {
	input := []string{"scope:z", "scope:a"}
	got, ok := CanonicalPermissions(input)
	if !ok || !reflect.DeepEqual(got, []string{"scope:a", "scope:z"}) ||
		ValidCanonicalPermissions(input) || !ValidCanonicalPermissions(got) {
		t.Fatalf("canonical permissions = %q, %v", got, ok)
	}
	got[0] = "mutated"
	if input[0] != "scope:z" {
		t.Fatal("canonicalization mutated its input")
	}
	for _, invalid := range [][]string{
		{}, {"scope:read", "scope:read"}, {" scope:read"}, {strings.Repeat("x", 129)},
	} {
		if _, ok := CanonicalPermissions(invalid); ok {
			t.Fatalf("invalid permissions accepted: %q", invalid)
		}
	}
}

func TestAudienceScopesUseOnlyExistingReservedNames(t *testing.T) {
	got, ok := CanonicalAudienceScopes([]string{
		" console:clusters:read ", "code-admin:workloads:read", "code-admin:clusters:read", "console:clusters:read",
	})
	want := []string{"code-admin:clusters:read", "code-admin:workloads:read", "console:clusters:read"}
	if !ok || !reflect.DeepEqual(got, want) || !ValidCanonicalAudienceScopes(got) {
		t.Fatalf("unexpected audience scopes: %v ok=%v", got, ok)
	}
	if _, ok := CanonicalAudienceScopes([]string{"code-admin:invented:read"}); ok {
		t.Fatal("accepted an unknown reserved scope")
	}
	for _, dormant := range []string{"code-admin:secrets:read", "code-admin:secrets:write"} {
		if _, ok := CanonicalAudienceScopes([]string{dormant}); ok {
			t.Fatalf("accepted dormant tenant scope %q for an audience", dormant)
		}
		if RequiresHomeAuthority(dormant) {
			t.Fatalf("classified dormant tenant scope %q as home authority", dormant)
		}
	}
	if !RequiresHomeAuthority("code-admin:clusters:read") || RequiresHomeAuthority("code-admin:workloads:read") ||
		!RequiresHomeAuthority("console:clusters:read") || !TenantRoleAssignable("code-admin:workloads:read") ||
		TenantRoleAssignable("code-admin:clusters:read") || TenantRoleAssignable("console:clusters:read") {
		t.Fatal("scope boundary classification mismatch")
	}
}

func TestParseManifestFailsClosed(t *testing.T) {
	valid := []byte(`{"schemaVersion":1,"policyVersion":"v","scopes":[{"scope":"code-admin:test:read","boundary":"tenant","tenantAssignable":true}]}`)
	digest := func(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }
	if scopes, err := parseManifest(valid, digest(valid), "v"); err != nil || !scopes["code-admin:test:read"].TenantAssignable {
		t.Fatalf("valid manifest = %#v, %v", scopes, err)
	}
	for _, test := range []struct {
		name                    string
		data                    []byte
		expectedDigest, version string
	}{
		{name: "digest", data: valid, expectedDigest: "wrong", version: "v"},
		{name: "JSON", data: []byte(`{`), version: "v"},
		{name: "schema", data: []byte(`{"schemaVersion":2,"policyVersion":"v","scopes":[]}`), version: "v"},
		{name: "version", data: valid, version: "other"},
		{name: "trailing", data: []byte(string(valid) + ` {}`), version: "v"},
		{name: "empty scope", data: []byte(`{"schemaVersion":1,"policyVersion":"v","scopes":[{"scope":"","boundary":"tenant"}]}`), version: "v"},
		{name: "global assignable", data: []byte(`{"schemaVersion":1,"policyVersion":"v","scopes":[{"scope":"code-admin:test:read","boundary":"global","tenantAssignable":true}]}`), version: "v"},
		{name: "boundary", data: []byte(`{"schemaVersion":1,"policyVersion":"v","scopes":[{"scope":"code-admin:test:read","boundary":"unknown"}]}`), version: "v"},
		{name: "duplicate", data: []byte(`{"schemaVersion":1,"policyVersion":"v","scopes":[{"scope":"code-admin:test:read","boundary":"tenant"},{"scope":"code-admin:test:read","boundary":"tenant"}]}`), version: "v"},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectedDigest := test.expectedDigest
			if expectedDigest == "" {
				expectedDigest = digest(test.data)
			}
			if scopes, err := parseManifest(test.data, expectedDigest, test.version); err == nil || scopes != nil {
				t.Fatalf("invalid manifest accepted: %#v, %v", scopes, err)
			}
		})
	}
}
