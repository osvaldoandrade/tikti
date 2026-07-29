package saml

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/beevik/etree"
)

const (
	stateCookieName = "__Host-tikti_saml_state"
	stateCookiePath = "/"
)

// setStateCookie writes the SAML state cookie used to correlate the
// AuthnRequest with the IdP's POST-back. The __Host- prefix prevents a
// sibling domain from creating a colliding Domain cookie. SameSite=None
// allows the cookie on the IdP's cross-origin POST when the browser permits it.
func (h *Handler) setStateCookie(w http.ResponseWriter, id string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    id,
		Path:     stateCookiePath,
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
		Name:     stateCookieName,
		Value:    "",
		Path:     stateCookiePath,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})
}

// stateCookieForResponse returns the browser state cookie that belongs to the
// AuthnRequest referenced by the SAML Response. Browsers can retain multiple
// same-name cookies after migrations or interrupted flows; selecting the first
// one can therefore consume stale state while the current request remains
// pending. A malformed response preserves the historical first-cookie behavior
// so the normal validation pipeline remains responsible for its rejection.
func stateCookieForResponse(r *http.Request, rawResponse string) (*http.Cookie, error) {
	requestID, ok := responseInResponseTo(rawResponse)
	if !ok {
		return r.Cookie(stateCookieName)
	}

	for _, cookie := range r.Cookies() {
		if cookie.Name != stateCookieName {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(requestID)) == 1 {
			return cookie, nil
		}
	}
	return nil, http.ErrNoCookie
}

func responseInResponseTo(rawResponse string) (string, bool) {
	if strings.TrimSpace(rawResponse) == "" {
		return "", false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(rawResponse)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 || containsDOCTYPE(raw) {
		return "", false
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return "", false
	}
	root := doc.Root()
	if root.Tag != "Response" || root.NamespaceURI() != nsP {
		return "", false
	}
	requestID := strings.TrimSpace(root.SelectAttrValue("InResponseTo", ""))
	return requestID, requestID != ""
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
