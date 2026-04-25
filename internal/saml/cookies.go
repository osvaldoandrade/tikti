package saml

import (
	"net/http"
	"strings"
	"time"
)

// setStateCookie writes the SAML state cookie used to correlate the
// AuthnRequest with the IdP's POST-back. The cookie uses SameSite=None
// so that it is included when the IdP sends the cross-origin POST.
func (h *Handler) setStateCookie(w http.ResponseWriter, id string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     "tikti_saml_state",
		Value:    id,
		Path:     "/saml",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

// setIDTokenCookie writes the idToken as an HTTP cookie per HLD App. A.9.
// The cookie uses config-driven attributes (SameSite=Lax by default).
func (h *Handler) setIDTokenCookie(w http.ResponseWriter, idt string) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.ACS.CookieName,
		Value:    idt,
		Path:     "/",
		Domain:   h.cfg.ACS.CookieDomain,
		Secure:   h.cfg.ACS.CookieSecure,
		HttpOnly: h.cfg.ACS.CookieHTTPOnly,
		SameSite: parseSameSite(h.cfg.ACS.CookieSameSite),
		MaxAge:   h.cfg.ACS.SessionTTL,
	})
}

// clearStateCookie removes the SAML state cookie by setting MaxAge=-1
// and an empty value.
func (h *Handler) clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "tikti_saml_state",
		Value:    "",
		Path:     "/saml",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})
}

// parseSameSite converts a string cookie SameSite value to http.SameSite.
// Unrecognized or empty values return http.SameSiteDefaultMode.
func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}
