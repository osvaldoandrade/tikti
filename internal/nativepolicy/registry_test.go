package nativepolicy

import "testing"

func TestForeignSAMLAccessRequiresDeclaredNativeTrustAndRoles(t *testing.T) {
	registry, err := NewRegistry([]Client{testClient()})
	if err != nil {
		t.Fatal(err)
	}
	roles := []string{"code-forge-member", "code-forge-viewer"}
	if !registry.AllowsForeignAssignment("local-tenant", "code-forge", roles) {
		t.Fatal("declared native application roles should be assignable for the trusted identity realm")
	}
	for _, test := range []struct {
		source, target string
		roles          []string
	}{
		{"another-tenant", "code-forge", roles},
		{"local-tenant", "another-tenant", roles},
		{"local-tenant", "code-forge", []string{"ADMIN"}},
		{"local-tenant", "code-forge", []string{"code-forge-member", "code-forge-admin"}},
		{"local-tenant", "code-forge", nil},
	} {
		if registry.AllowsForeignAssignment(test.source, test.target, test.roles) {
			t.Error("undeclared federation or administrative authority was accepted")
		}
	}
	var disabled *Registry
	if disabled.AllowsForeignAssignment("local-tenant", "code-forge", roles) {
		t.Fatal("disabled native policy must preserve the SAML tenant boundary")
	}
	copy, ok := registry.Get("code-forge-desktop-native")
	if !ok {
		t.Fatal("registered client missing")
	}
	copy.BaseRole.Scopes[0] = "changed:scope"
	scopes, ok := registry.ExpectedRoleScopes("code-forge", "code-forge-member")
	if !ok || len(scopes) != 1 || scopes[0] != "code-forge-desktop:session" {
		t.Fatal("caller mutation changed trusted role authority")
	}
}

func TestRegistryRejectsDuplicateClientsAndConflictingRoleDefinitions(t *testing.T) {
	client := testClient()
	if _, err := NewRegistry([]Client{client, client}); err == nil {
		t.Error("duplicate client identity accepted")
	}
	other := testClient()
	other.ID = "another-native-client"
	other.BaseRole.Scopes = []string{"different:session"}
	other.RequiredScopes[0] = "different:session"
	if _, err := NewRegistry([]Client{client, other}); err == nil {
		t.Error("conflicting immutable target-role definitions accepted")
	}
}
