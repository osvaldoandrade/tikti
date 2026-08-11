package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigExactMembershipRoutes(t *testing.T) {
	t.Run("off ignores dedicated secret file", func(t *testing.T) {
		t.Setenv("EXACT_MEMBERSHIP_READ_ROUTES_V1", "false")
		t.Setenv("EXACT_MEMBERSHIP_READ_ROUTES_V1_TENANTS", "")
		t.Setenv("EXACT_MEMBERSHIP_PAGE_TOKEN_SECRET_FILE", filepath.Join(t.TempDir(), "missing"))
		cfg, err := LoadConfig(writeTempConfig(t, `exactMembershipPageTokenSecret: plaintext`))
		if err != nil || cfg.ExactMembershipReadRoutesV1 || len(cfg.ExactMembershipReadRoutesV1Tenants) != 0 || cfg.ExactMembershipPageTokenSecret != "" {
			t.Fatalf("off config = %#v, %v", cfg, err)
		}
	})
	t.Run("environment enables canonical allowlist and file secret", func(t *testing.T) {
		secretPath := filepath.Join(t.TempDir(), "page-token")
		if err := os.WriteFile(secretPath, []byte(strings.Repeat("k", 32)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("EXACT_MEMBERSHIP_READ_ROUTES_V1", "true")
		t.Setenv("EXACT_MEMBERSHIP_READ_ROUTES_V1_TENANTS", "storifly,bereia")
		t.Setenv("EXACT_MEMBERSHIP_PAGE_TOKEN_SECRET_FILE", secretPath)
		cfg, err := LoadConfig(writeTempConfig(t, `{}`))
		if err != nil || !cfg.ExactMembershipReadRoutesV1 || strings.Join(cfg.ExactMembershipReadRoutesV1Tenants, ",") != "bereia,storifly" || len(cfg.ExactMembershipPageTokenSecret) != 32 {
			t.Fatalf("enabled config = %#v, %v", cfg, err)
		}
	})
}

func TestLoadConfigRejectsUnsafeExactMembershipRoutes(t *testing.T) {
	for _, test := range []struct{ name, flag, tenants, secretFile string }{
		{name: "invalid boolean", flag: "1", tenants: "bereia"},
		{name: "missing allowlist", flag: "true"},
		{name: "invalid tenant", flag: "true", tenants: "Bereia"},
		{name: "duplicate tenant", flag: "true", tenants: "bereia,bereia"},
		{name: "missing secret file", flag: "true", tenants: "bereia", secretFile: "/missing/exact-membership-secret"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("EXACT_MEMBERSHIP_READ_ROUTES_V1", test.flag)
			t.Setenv("EXACT_MEMBERSHIP_READ_ROUTES_V1_TENANTS", test.tenants)
			if test.secretFile != "" {
				t.Setenv("EXACT_MEMBERSHIP_PAGE_TOKEN_SECRET_FILE", test.secretFile)
			}
			if _, err := LoadConfig(writeTempConfig(t, `{}`)); err == nil {
				t.Fatal("unsafe exact membership route configuration was accepted")
			}
		})
	}
}
