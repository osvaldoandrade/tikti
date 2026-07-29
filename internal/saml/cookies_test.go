package saml

import (
	"encoding/base64"
	"errors"
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

func TestStateCookieForResponse_SelectsMatchingCookie(t *testing.T) {
	response := base64.StdEncoding.EncodeToString([]byte(
		`<samlp:Response xmlns:samlp="` + nsP + `" InResponseTo="_current"/>`,
	))
	r := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	r.AddCookie(&http.Cookie{Name: "unrelated", Value: "_current"})
	r.AddCookie(&http.Cookie{Name: stateCookieName, Value: "_stale"})
	r.AddCookie(&http.Cookie{Name: stateCookieName, Value: "_current"})

	state, err := stateCookieForResponse(r, response)
	if err != nil {
		t.Fatalf("stateCookieForResponse: %v", err)
	}
	if state.Value != "_current" {
		t.Fatalf("state cookie = %q, want matching request", state.Value)
	}
}

func TestStateCookieForResponse_RejectsOnlyStaleCookie(t *testing.T) {
	response := base64.StdEncoding.EncodeToString([]byte(
		`<samlp:Response xmlns:samlp="` + nsP + `" InResponseTo="_current"/>`,
	))
	r := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	r.AddCookie(&http.Cookie{Name: stateCookieName, Value: "_stale"})

	if _, err := stateCookieForResponse(r, response); !errors.Is(err, http.ErrNoCookie) {
		t.Fatalf("error = %v, want http.ErrNoCookie", err)
	}
}

func TestStateCookieForResponse_MalformedResponsePreservesFallback(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	r.AddCookie(&http.Cookie{Name: stateCookieName, Value: "_fallback"})

	state, err := stateCookieForResponse(r, "not-base64")
	if err != nil {
		t.Fatalf("stateCookieForResponse: %v", err)
	}
	if state.Value != "_fallback" {
		t.Fatalf("state cookie = %q, want fallback cookie", state.Value)
	}
}

func TestDiagnoseStateCorrelation(t *testing.T) {
	response := base64.StdEncoding.EncodeToString([]byte(
		`<samlp:Response xmlns:samlp="` + nsP + `" InResponseTo="_current"/>`,
	))
	r := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	r.AddCookie(&http.Cookie{Name: "unrelated", Value: "_current"})
	r.AddCookie(&http.Cookie{Name: stateCookieName, Value: "_stale"})
	r.AddCookie(&http.Cookie{Name: stateCookieName, Value: "_current"})

	diagnostics := diagnoseStateCorrelation(r, response, "_current")
	if !diagnostics.ResponseIDPresent {
		t.Error("ResponseIDPresent = false, want true")
	}
	if diagnostics.StateCookieCount != 2 {
		t.Errorf("StateCookieCount = %d, want 2", diagnostics.StateCookieCount)
	}
	if !diagnostics.MatchingCookiePresent {
		t.Error("MatchingCookiePresent = false, want true")
	}
	if !diagnostics.SelectedMatchesResponse {
		t.Error("SelectedMatchesResponse = false, want true")
	}
}

func TestDiagnoseStateCorrelation_MalformedResponse(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	r.AddCookie(&http.Cookie{Name: stateCookieName, Value: "_fallback"})

	diagnostics := diagnoseStateCorrelation(r, "not-base64", "_fallback")
	if diagnostics.ResponseIDPresent {
		t.Error("ResponseIDPresent = true, want false")
	}
	if diagnostics.StateCookieCount != 1 {
		t.Errorf("StateCookieCount = %d, want 1", diagnostics.StateCookieCount)
	}
	if diagnostics.MatchingCookiePresent || diagnostics.SelectedMatchesResponse {
		t.Fatal("malformed response must not report a correlated cookie")
	}
}

func TestResponseInResponseTo_RejectsInvalidEnvelopes(t *testing.T) {
	tests := map[string]string{
		"invalid XML":     `<samlp:Response`,
		"wrong element":   `<samlp:Request xmlns:samlp="` + nsP + `" InResponseTo="_current"/>`,
		"wrong namespace": `<samlp:Response xmlns:samlp="urn:example:wrong" InResponseTo="_current"/>`,
	}

	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString([]byte(response))
			if requestID, ok := responseInResponseTo(encoded); ok {
				t.Fatalf("request ID = %q, want invalid envelope rejection", requestID)
			}
		})
	}
}

func TestResponseInResponseTo_UsesSubjectConfirmationData(t *testing.T) {
	response := `<samlp:Response xmlns:samlp="` + nsP + `">` +
		`<saml:Assertion xmlns:saml="` + samlAssertionNamespace + `">` +
		`<saml:Subject><saml:SubjectConfirmation>` +
		`<saml:SubjectConfirmationData InResponseTo="_subject-request"/>` +
		`</saml:SubjectConfirmation></saml:Subject></saml:Assertion>` +
		`</samlp:Response>`
	encoded := base64.StdEncoding.EncodeToString([]byte(response))

	requestID, ok := responseInResponseTo(encoded)
	if !ok {
		t.Fatal("subject confirmation request ID was not found")
	}
	if requestID != "_subject-request" {
		t.Fatalf("request ID = %q, want subject confirmation value", requestID)
	}
}

func TestResponseInResponseTo_RejectsConflictingRequestIDs(t *testing.T) {
	response := `<samlp:Response xmlns:samlp="` + nsP + `" InResponseTo="_root-request">` +
		`<saml:Assertion xmlns:saml="` + samlAssertionNamespace + `">` +
		`<saml:Subject><saml:SubjectConfirmation>` +
		`<saml:SubjectConfirmationData InResponseTo="_different-request"/>` +
		`</saml:SubjectConfirmation></saml:Subject></saml:Assertion>` +
		`</samlp:Response>`
	encoded := base64.StdEncoding.EncodeToString([]byte(response))

	if requestID, ok := responseInResponseTo(encoded); ok {
		t.Fatalf("request ID = %q, want conflicting-value rejection", requestID)
	}
}
