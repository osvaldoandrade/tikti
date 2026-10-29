package config

import (
	"strings"
	"testing"

	"github.com/osvaldoandrade/tikti/internal/nativepolicy"
)

func TestNativeSAMLConfigDefaultsOffAndRequiresExplicitSecureAuthority(t *testing.T) {
	if err := (&Config{}).ValidateNativeSAML(); err != nil {
		t.Fatal("default-off native SAML broke existing configuration")
	}
	valid := func() *Config {
		return &Config{IssuerBaseURL: "https://issuer.example", JwtSecret: strings.Repeat("k", 32), SAML: SAMLConfig{Enabled: true, ACS: ACSConfig{CookieName: "tikti_idt", CookieSecure: true, CookieHTTPOnly: true}}, NativeSAML: NativeSAMLConfig{Enabled: true, Clients: []nativepolicy.Client{{ID: "desktop", Name: "Desktop", TenantID: "app", IdentityTenantID: "home", Audience: "desktop", RedirectPath: "/oauth/callback", TTLSeconds: 600, BaseRole: nativepolicy.Role{Name: "member", Scopes: []string{"app:read"}}, RequiredScopes: []string{"app:read"}}}}}
	}
	if err := valid().ValidateNativeSAML(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Config){func(c *Config) { c.SAML.Enabled = false }, func(c *Config) { c.NativeSAML.Clients = nil }, func(c *Config) { c.JwtSecret = "short" }, func(c *Config) { c.IssuerBaseURL = "http://issuer.example" }, func(c *Config) { c.SAML.ACS.CookieSecure = false }, func(c *Config) { c.SAML.ACS.CookieHTTPOnly = false }, func(c *Config) { c.SAML.ACS.CookieDomain = ".example" }, func(c *Config) { c.NativeSAML.Clients[0].RedirectPath = "//attacker.invalid" }} {
		c := valid()
		change(c)
		if err := c.ValidateNativeSAML(); err == nil {
			t.Fatal("unsafe native authority enabled")
		}
	}
}
