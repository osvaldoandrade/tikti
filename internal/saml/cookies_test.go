package saml

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/pkg/config"
)

func cookieHandler() *Handler {
	return NewHandler(Deps{
		Cfg: config.SAMLConfig{
			SP: config.SPConfig{
				RequestTTL: 300 * time.Second,
			},
			ACS: config.ACSConfig{
				CookieName:     "tikti_idt",
				CookieDomain:   "example.com",
				CookieSameSite: "Lax",
				CookieSecure:   true,
				CookieHTTPOnly: true,
				SessionTTL:     3600,
			},
		},
	})
}

func TestStateCookie_Attributes(t *testing.T) {
	h := cookieHandler()
	w := httptest.NewRecorder()

	h.setStateCookie(w, "req-123", 300*time.Second)

	cookies := w.Result().Cookies()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == stateCookieName {
			found = c
			break
		}
	}

	if found == nil {
		t.Fatalf("%s cookie not set", stateCookieName)
	}
	if found.Name != "__Host-tikti_saml_state" {
		t.Errorf("Name = %q, want __Host- protected name", found.Name)
	}
	if found.Value != "req-123" {
		t.Errorf("Value = %q, want %q", found.Value, "req-123")
	}
	if found.Path != stateCookiePath {
		t.Errorf("Path = %q, want %q", found.Path, stateCookiePath)
	}
	if found.Domain != "" {
		t.Errorf("Domain = %q, want host-only cookie", found.Domain)
	}
	if !found.Secure {
		t.Error("Secure = false, want true")
	}
	if !found.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if found.SameSite != http.SameSiteNoneMode {
		t.Errorf("SameSite = %v, want SameSiteNoneMode", found.SameSite)
	}
	if found.MaxAge != 300 {
		t.Errorf("MaxAge = %d, want 300", found.MaxAge)
	}
}

func TestIDTokenCookie_Attributes(t *testing.T) {
	h := cookieHandler()
	w := httptest.NewRecorder()

	h.setIDTokenCookie(w, "jwt.token.value")

	cookies := w.Result().Cookies()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == "tikti_idt" {
			found = c
			break
		}
	}

	if found == nil {
		t.Fatal("tikti_idt cookie not set")
	}
	if found.Value != "jwt.token.value" {
		t.Errorf("Value = %q, want %q", found.Value, "jwt.token.value")
	}
	if found.Path != "/" {
		t.Errorf("Path = %q, want %q", found.Path, "/")
	}
	if found.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", found.Domain, "example.com")
	}
	if !found.Secure {
		t.Error("Secure = false, want true")
	}
	if !found.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if found.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want SameSiteLaxMode", found.SameSite)
	}
	if found.MaxAge != 3600 {
		t.Errorf("MaxAge = %d, want 3600", found.MaxAge)
	}
}

func TestClearState_RemovesCookie(t *testing.T) {
	h := cookieHandler()
	w := httptest.NewRecorder()

	h.clearStateCookie(w)

	cookies := w.Result().Cookies()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == stateCookieName {
			found = c
			break
		}
	}

	if found == nil {
		t.Fatalf("%s cookie not set", stateCookieName)
	}
	if found.MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", found.MaxAge)
	}
	if found.Value != "" {
		t.Errorf("Value = %q, want empty", found.Value)
	}
	if found.Path != stateCookiePath {
		t.Errorf("Path = %q, want %q", found.Path, stateCookiePath)
	}
	if found.Domain != "" {
		t.Errorf("Domain = %q, want host-only cookie", found.Domain)
	}
	if !found.Secure {
		t.Error("Secure = false, want true")
	}
	if !found.HttpOnly {
		t.Error("HttpOnly = false, want true")
	}
	if found.SameSite != http.SameSiteNoneMode {
		t.Errorf("SameSite = %v, want SameSiteNoneMode", found.SameSite)
	}
}
