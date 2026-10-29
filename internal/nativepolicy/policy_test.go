package nativepolicy

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func testClient() Client {
	return Client{
		ID: "code-forge-desktop-native", Name: "Code Forge", TenantID: "code-forge",
		IdentityTenantID: "local-tenant", Audience: "code-forge-desktop", RedirectPath: "/oauth/callback", TTLSeconds: 3600,
		BaseRole: Role{Name: "code-forge-member", Scopes: []string{"code-forge-desktop:session"}},
		AdditionalRoles: []Role{
			{Name: "code-forge-viewer", Scopes: []string{"code-forge:workspace:read", "code-forge:planner:read", "code-forge:access"}},
			{Name: "code-forge-developer", Scopes: []string{"code-forge:workspace:write", "code-forge:access"}},
			{Name: "code-forge-ai-operator", Scopes: []string{"code-forge:ai:use", "code-forge:access"}},
		},
		RequiredScopes: []string{"code-forge-desktop:session", "code-forge:access", "code-forge:workspace:read", "code-forge:planner:read"},
	}
}

func TestRedirectKeepsExactRegisteredLoopbackBoundary(t *testing.T) {
	client := testClient()
	for _, redirect := range []string{"http://127.0.0.1:49152/oauth/callback", "http://[::1]:49152/oauth/callback"} {
		if err := client.ValidateRedirect(redirect); err != nil {
			t.Errorf("valid native loopback redirect refused: %v", err)
		}
	}
	for _, redirect := range []string{
		"https://attacker.invalid/oauth/callback", "http://localhost:49152/oauth/callback",
		"http://0.0.0.0:49152/oauth/callback", "http://127.0.0.2:49152/oauth/callback",
		"http://127.0.0.1.attacker.invalid:49152/oauth/callback", "http://2130706433:49152/oauth/callback",
		"http://user@127.0.0.1:49152/oauth/callback", "http://127.0.0.1:49152/oauth/callback?redirect=elsewhere",
		"http://127.0.0.1:49152/oauth/callback#fragment", "http://127.0.0.1:49152/oauth/callback?",
		"http://127.0.0.1:49152/oauth/%63allback", "http://127.0.0.1:49152/oauth/callback/",
		"http://127.0.0.1:49152/other", "http://127.0.0.1:0/oauth/callback",
		"http://127.0.0.1:65536/oauth/callback", "http://127.0.0.1/oauth/callback",
		"http://127.0.0.1:049152/oauth/callback", "http://[::1%25zone]:49152/oauth/callback",
	} {
		if err := client.ValidateRedirect(redirect); err == nil {
			t.Errorf("unsafe or unregistered redirect accepted: %s", redirect)
		}
	}
}

func TestPKCES256MatchesRFC7636AppendixB(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	computed, err := S256Challenge(verifier)
	if err != nil || computed != challenge || !VerifyS256(verifier, challenge) {
		t.Fatal("S256 must reproduce the published RFC proof-key vector")
	}
	for _, invalid := range []string{"", strings.Repeat("x", 42), strings.Repeat("x", 129), verifier + "=", verifier + "\n"} {
		if VerifyS256(invalid, challenge) {
			t.Error("invalid verifier was accepted")
		}
	}
	if VerifyS256(strings.Repeat("x", 43), challenge) || VerifyS256(verifier, verifier) || VerifyS256(verifier, challenge+"=") {
		t.Error("a wrong verifier or malformed challenge must fail")
	}
}

func TestNativeScopesRequireExplicitApplicationMembershipAndViewer(t *testing.T) {
	client := testClient()
	for _, roles := range [][]string{{"ADMIN"}, {"code-forge-member"}, {"code-forge-member", "code-forge-developer"}, {"code-forge-viewer"}} {
		if _, err := client.ScopesForRoles(roles); !errors.Is(err, ErrAccessDenied) {
			t.Errorf("membership without required viewer authority was accepted: %v", roles)
		}
	}
	scopes, err := client.ScopesForRoles([]string{"ADMIN", "code-forge-member", "code-forge-viewer", "code-forge-ai-operator"})
	want := []string{"code-forge-desktop:session", "code-forge:access", "code-forge:ai:use", "code-forge:planner:read", "code-forge:workspace:read"}
	if err != nil || !reflect.DeepEqual(scopes, want) {
		t.Fatalf("unexpected explicit application scope union: %v, %v", scopes, err)
	}
}

func TestNativePolicyFingerprintIsStableAndDetached(t *testing.T) {
	client := testClient()
	originalHash, err := client.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := client.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if nextHash, err := normalized.Fingerprint(); err != nil || nextHash != originalHash {
		t.Fatal("equivalent configuration order changed the authorization binding")
	}
	client.BaseRole.Scopes[0] = "changed:scope"
	client.AdditionalRoles[0].Scopes[0] = "changed:scope"
	client.RequiredScopes[0] = "changed:scope"
	if nextHash, err := normalized.Fingerprint(); err != nil || nextHash != originalHash {
		t.Fatal("caller mutation changed the accepted policy")
	}
	normalized.IdentityTenantID = "another-tenant"
	if nextHash, _ := normalized.Fingerprint(); nextHash == originalHash {
		t.Fatal("changing the authentication realm must change the grant binding")
	}
}

func TestMalformedClientPoliciesFailClosed(t *testing.T) {
	mutations := []func(*Client){
		func(c *Client) { c.ID = "../client" },
		func(c *Client) { c.IdentityTenantID = "" },
		func(c *Client) { c.Name = "Code Forge\nInjected" },
		func(c *Client) { c.RedirectPath = "//elsewhere" },
		func(c *Client) { c.RedirectPath = "/oauth/../callback" },
		func(c *Client) { c.TTLSeconds = 3601 },
		func(c *Client) { c.TTLSeconds = 0 },
		func(c *Client) { c.RequiredScopes = []string{"undeclared:scope"} },
		func(c *Client) { c.AdditionalRoles = append(c.AdditionalRoles, c.BaseRole) },
		func(c *Client) { c.BaseRole.Scopes = []string{"code-forge:*"} },
	}
	for _, mutate := range mutations {
		client := testClient()
		mutate(&client)
		if _, err := client.Normalize(); !errors.Is(err, ErrInvalidClient) {
			t.Error("invalid native client policy was accepted")
		}
	}
}
