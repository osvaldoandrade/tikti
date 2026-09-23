package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestPlatformDataAccessPrincipalContract(t *testing.T) {
	p := TrinoPrincipal{InstallationUID: "installation-1", TenantID: "tenant-1", TenantEpoch: strings.Repeat("a", 64), SubjectKind: "User", SubjectUID: "user-1"}
	got, err := p.OpaquePrincipal()
	if err != nil {
		t.Fatal(err)
	}
	// Independent fixed netstring input: lengths are UTF-8 byte lengths, no domain prefix.
	bytes := "14:installation-1,8:tenant-1,64:" + strings.Repeat("a", 64) + ",4:User,6:user-1,"
	sum := sha256.Sum256([]byte(bytes))
	if got != "cfp_"+hex.EncodeToString(sum[:]) {
		t.Fatal("principal bytes differ")
	}
	for _, mutate := range []func(*TrinoPrincipal){func(p *TrinoPrincipal) { p.InstallationUID = "" }, func(p *TrinoPrincipal) { p.TenantEpoch = "1" }, func(p *TrinoPrincipal) { p.TenantEpoch = strings.Repeat("A", 64) }, func(p *TrinoPrincipal) { p.SubjectKind = "Role" }, func(p *TrinoPrincipal) { p.SubjectUID = "" }, func(p *TrinoPrincipal) { p.TenantID = "foreign\n" }} {
		bad := p
		mutate(&bad)
		if _, err := bad.OpaquePrincipal(); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
	for _, field := range []func(*TrinoPrincipal){func(p *TrinoPrincipal) { p.InstallationUID += "2" }, func(p *TrinoPrincipal) { p.TenantID += "2" }, func(p *TrinoPrincipal) { p.TenantEpoch = strings.Repeat("b", 64) }, func(p *TrinoPrincipal) { p.SubjectKind = "Service" }, func(p *TrinoPrincipal) { p.SubjectUID += "2" }} {
		other := p
		field(&other)
		value, err := other.OpaquePrincipal()
		if err != nil || value == got {
			t.Fatal("identity dimension unbound")
		}
	}
}

func TestPlatformDataAccessAudience(t *testing.T) {
	for _, aud := range []string{"codeq-worker", "trino:", "trino:a/b", "trino:" + strings.Repeat("x", 129)} {
		if _, ok := TrinoInstallationAudience(aud); ok {
			t.Fatal("invalid audience accepted")
		}
	}
	if uid, ok := TrinoInstallationAudience("trino:installation-1"); !ok || uid != "installation-1" {
		t.Fatal("valid audience rejected")
	}
}
