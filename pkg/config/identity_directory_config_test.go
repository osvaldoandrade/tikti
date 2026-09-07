package config

import "testing"

func TestLoadConfigIdentityGroupsRemainDarkByDefault(t *testing.T) {
	cfg, err := LoadConfig(writeTempConfig(t, `{}`))
	if err != nil || cfg.IdentityGroupsV1 {
		t.Fatalf("default groups config = %#v, %v", cfg, err)
	}

	t.Setenv("IDENTITY_GROUPS_V1", "true")
	cfg, err = LoadConfig(writeTempConfig(t, `identityGroupsV1: false`))
	if err != nil || !cfg.IdentityGroupsV1 {
		t.Fatalf("enabled groups config = %#v, %v", cfg, err)
	}

	t.Setenv("IDENTITY_GROUPS_V1", "invalid")
	if _, err = LoadConfig(writeTempConfig(t, `{}`)); err == nil {
		t.Fatal("invalid IDENTITY_GROUPS_V1 value was accepted")
	}
}
