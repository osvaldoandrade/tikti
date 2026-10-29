package config

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/osvaldoandrade/tikti/internal/nativepolicy"
)

// NativeSAMLConfig activates only registered public native applications. It
// introduces no client secret or additional authentication workload.
type NativeSAMLConfig struct {
	Enabled bool                  `yaml:"enabled"`
	Clients []nativepolicy.Client `yaml:"clients"`
}

func (c *Config) ValidateNativeSAML() error {
	if c == nil {
		return fmt.Errorf("native SAML configuration is unavailable")
	}
	if !c.NativeSAML.Enabled {
		return nil
	}
	if !c.SAML.Enabled || len(c.NativeSAML.Clients) == 0 || len(c.JwtSecret) < 32 {
		return fmt.Errorf("native SAML requires SAML, registered clients and a strong server session key")
	}
	issuer, err := url.Parse(c.IssuerBaseURL)
	if err != nil || issuer == nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil ||
		issuer.RawQuery != "" || issuer.Fragment != "" || issuer.ForceQuery || issuer.Opaque != "" ||
		(issuer.Path != "" && issuer.Path != "/") {
		return fmt.Errorf("native SAML requires an HTTPS issuer origin")
	}
	cookie := &http.Cookie{Name: c.SAML.ACS.CookieName, Path: "/", Secure: true, HttpOnly: true}
	if !c.SAML.ACS.CookieSecure || !c.SAML.ACS.CookieHTTPOnly || c.SAML.ACS.CookieDomain != "" || cookie.Valid() != nil {
		return fmt.Errorf("native SAML requires a valid host-only secure HttpOnly SAML session cookie")
	}
	if _, err := nativepolicy.NewRegistry(c.NativeSAML.Clients); err != nil {
		return fmt.Errorf("native SAML client policy is invalid")
	}
	return nil
}
