package nativeauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/osvaldoandrade/tikti/internal/nativepolicy"
)

const httpVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

type httpAuthority struct {
	issued atomic.Int32
	denied bool
}

func (a *httpAuthority) BrowserIdentity(_ context.Context, session string, _ nativepolicy.Client) (Identity, error) {
	if session != "browser-session" {
		return Identity{}, ErrNoSession
	}
	if a.denied {
		return Identity{}, ErrAccessDenied
	}
	return Identity{Subject: "user-1", Email: "owner@example.test", IdentityTenantID: "local-tenant", TenantName: "Code Forge", TokenVersion: 2,
		SessionExpiresAt: time.Now().Add(10 * time.Minute).Unix(), Scopes: []string{"desktop:session", "app:read"}}, nil
}
func (a *httpAuthority) IssueNativeToken(_ context.Context, _ nativepolicy.Client, _ Grant) (Token, error) {
	a.issued.Add(1)
	if a.denied {
		return Token{}, ErrAccessDenied
	}
	return Token{AccessToken: "signed-fixture-token", TokenType: "Bearer", Email: "owner@example.test", Scope: "app:read desktop:session", ExpiresIn: 600}, nil
}

type httpLimiter struct {
	allowed bool
	err     error
}

func (l httpLimiter) AllowAuthenticationAttempt(context.Context, string, string, int, time.Duration) (bool, error) {
	return l.allowed, l.err
}

type httpAudit struct {
	fail  bool
	calls atomic.Int32
}

func (a *httpAudit) Emit(context.Context, AuditRecord) error {
	a.calls.Add(1)
	if a.fail {
		return ErrUnavailable
	}
	return nil
}

func newHTTPFixture(t *testing.T) (*Handler, *httpAuthority, *httpAudit, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })
	registry, err := nativepolicy.NewRegistry([]nativepolicy.Client{{ID: "desktop", Name: "Code Forge", TenantID: "code-forge", IdentityTenantID: "local-tenant", Audience: "desktop", RedirectPath: "/oauth/callback", TTLSeconds: 600,
		BaseRole: nativepolicy.Role{Name: "member", Scopes: []string{"desktop:session"}}, AdditionalRoles: []nativepolicy.Role{{Name: "viewer", Scopes: []string{"app:read"}}}, RequiredScopes: []string{"desktop:session", "app:read"}}})
	if err != nil {
		t.Fatal(err)
	}
	authority := &httpAuthority{}
	audit := &httpAudit{}
	handler, err := NewHandler(HTTPOptions{Issuer: "https://issuer.example", CookieName: "tikti_idt", CSRFKey: []byte(strings.Repeat("k", 32)), Clients: registry, Store: NewStore(redisClient, nil), Authority: authority, Audit: audit,
		Limiter: httpLimiter{allowed: true}, ResolveIP: func(*http.Request) string { return "127.0.0.1" }, RateRequests: 20, RateWindow: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return handler, authority, audit, server
}

func authorizeValues() url.Values {
	challenge, _ := nativepolicy.S256Challenge(httpVerifier)
	return url.Values{"response_type": {"code"}, "client_id": {"desktop"}, "redirect_uri": {"http://127.0.0.1:49152/oauth/callback"}, "state": {strings.Repeat("s", 43)}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
}

func callHTTP(handler http.Handler, method, path string, form url.Values, cookie, origin string) *httptest.ResponseRecorder {
	body := ""
	if form != nil {
		body = form.Encode()
	}
	r := httptest.NewRequest(method, "https://issuer.example"+PublicPrefix+path, strings.NewReader(body))
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: "tikti_idt", Value: cookie})
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func consentForm(t *testing.T, handler http.Handler) url.Values {
	t.Helper()
	w := callHTTP(handler, "GET", "authorize?"+authorizeValues().Encode(), nil, "browser-session", "")
	if w.Code != 200 {
		t.Fatalf("authorize status=%d body=%s", w.Code, w.Body.String())
	}
	values := url.Values{"decision": {"approve"}}
	for _, field := range []string{"request", "csrf"} {
		match := regexp.MustCompile(`name="` + field + `" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
		if len(match) != 2 {
			t.Fatal("consent missing bound form field")
		}
		values.Set(field, match[1])
	}
	return values
}

func issueHTTPCode(t *testing.T, handler http.Handler) string {
	t.Helper()
	w := callHTTP(handler, "POST", "consent", consentForm(t, handler), "browser-session", "https://issuer.example")
	if w.Code != 303 {
		t.Fatalf("consent status=%d body=%s", w.Code, w.Body.String())
	}
	callback, err := url.Parse(w.Header().Get("Location"))
	if err != nil || callback.Host != "127.0.0.1:49152" || callback.Path != "/oauth/callback" || callback.Query().Get("state") != strings.Repeat("s", 43) || callback.Query().Get("iss") != "https://issuer.example" {
		t.Fatal("unbound native callback")
	}
	code := callback.Query().Get("code")
	if !nativepolicy.ValidS256Challenge(code) {
		t.Fatal("invalid code")
	}
	return code
}

func tokenForm(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {"desktop"}, "code": {code}, "redirect_uri": {"http://127.0.0.1:49152/oauth/callback"}, "code_verifier": {httpVerifier}}
}

func TestNativeHTTPRequiresBrowserSAMLAndKeepsRelayServerOwned(t *testing.T) {
	h, _, _, _ := newHTTPFixture(t)
	w := callHTTP(h, "GET", "authorize?"+authorizeValues().Encode(), nil, "", "")
	redirect, err := url.Parse(w.Header().Get("Location"))
	if w.Code != 303 || err != nil || redirect.Path != "/saml/login/local-tenant" {
		t.Fatal("authorization must use registered SAML realm")
	}
	relay, err := url.Parse(redirect.Query().Get("RelayState"))
	if err != nil || relay.IsAbs() || relay.Path != PublicPrefix+"resume" || !nativepolicy.ValidS256Challenge(relay.Query().Get("request")) || strings.Contains(redirect.String(), "127.0.0.1") {
		t.Fatal("relay must contain only server continuation")
	}
	w = callHTTP(h, "GET", "resume?"+relay.RawQuery, nil, "browser-session", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "owner@example.test") || !strings.Contains(w.Body.String(), "Code Forge") {
		t.Fatal("verified browser session did not reach consent")
	}
}

func TestNativeHTTPRejectsInputAmbiguityAndRemoteRedirects(t *testing.T) {
	h, _, _, _ := newHTTPFixture(t)
	for _, tc := range []struct{ field, value string }{
		{"redirect_uri", "https://attacker.invalid/callback"}, {"code_challenge_method", "plain"}, {"response_type", "token"}, {"state", "short"}, {"code_challenge", "invalid"}, {"client_id", "unknown"}, {"scope", "admin"},
	} {
		v := authorizeValues()
		v.Set(tc.field, tc.value)
		w := callHTTP(h, "GET", "authorize?"+v.Encode(), nil, "browser-session", "")
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Errorf("unsafe %s accepted", tc.field)
		}
	}
	v := authorizeValues()
	v.Add("client_id", "desktop")
	if w := callHTTP(h, "GET", "authorize?"+v.Encode(), nil, "browser-session", ""); w.Code != 400 {
		t.Fatal("duplicate input accepted")
	}
}

func TestNativeHTTPConsentCSRFOriginCancellationAndReplay(t *testing.T) {
	h, a, _, _ := newHTTPFixture(t)
	form := consentForm(t, h)
	for _, origin := range []string{"", "null", "https://attacker.invalid"} {
		if w := callHTTP(h, "POST", "consent", form, "browser-session", origin); w.Code != 403 {
			t.Fatal("cross-origin consent accepted")
		}
	}
	bad := form.Get("csrf")
	form.Set("csrf", "forged")
	if w := callHTTP(h, "POST", "consent", form, "browser-session", "https://issuer.example"); w.Code != 403 {
		t.Fatal("forged CSRF accepted")
	}
	form.Set("csrf", bad)
	form.Set("decision", "deny")
	w := callHTTP(h, "POST", "consent", form, "browser-session", "https://issuer.example")
	location, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 303 || location.Query().Get("error") != "access_denied" || location.Query().Get("code") != "" || a.issued.Load() != 0 {
		t.Fatal("denial issued a credential")
	}
	if w := callHTTP(h, "POST", "consent", form, "browser-session", "https://issuer.example"); w.Code != 400 {
		t.Fatal("consent replay accepted")
	}
}

func TestNativeHTTPPKCEBindingAndConcurrentSingleUse(t *testing.T) {
	h, a, _, _ := newHTTPFixture(t)
	code := issueHTTPCode(t, h)
	for _, tc := range []struct{ field, value string }{{"code_verifier", strings.Repeat("x", 43)}, {"client_id", "other"}, {"redirect_uri", "http://127.0.0.1:49153/oauth/callback"}} {
		form := tokenForm(code)
		form.Set(tc.field, tc.value)
		if w := callHTTP(h, "POST", "token", form, "", ""); w.Code != 400 {
			t.Fatal("code binding not enforced")
		}
	}
	if w := callHTTP(h, "POST", "token", tokenForm(code), "", "https://issuer.example"); w.Code != 400 || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("browser token redemption allowed")
	}
	var successes atomic.Int32
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			if w := callHTTP(h, "POST", "token", tokenForm(code), "", ""); w.Code == 200 {
				successes.Add(1)
			}
		}()
	}
	group.Wait()
	if successes.Load() != 1 || a.issued.Load() != 1 {
		t.Fatalf("token success=%d issuance=%d", successes.Load(), a.issued.Load())
	}
}

func TestNativeHTTPAuditStorageRateAndCurrentAuthorityFailClosed(t *testing.T) {
	t.Run("audit", func(t *testing.T) {
		h, a, audit, _ := newHTTPFixture(t)
		form := consentForm(t, h)
		audit.fail = true
		w := callHTTP(h, "POST", "consent", form, "browser-session", "https://issuer.example")
		if w.Code != 503 || w.Header().Get("Location") != "" || a.issued.Load() != 0 {
			t.Fatal("audit failure granted access")
		}
	})
	t.Run("storage", func(t *testing.T) {
		h, _, _, server := newHTTPFixture(t)
		code := issueHTTPCode(t, h)
		server.Close()
		if w := callHTTP(h, "POST", "token", tokenForm(code), "", ""); w.Code != 503 {
			t.Fatal("storage outage granted access")
		}
	})
	t.Run("authority", func(t *testing.T) {
		h, a, _, _ := newHTTPFixture(t)
		code := issueHTTPCode(t, h)
		a.denied = true
		if w := callHTTP(h, "POST", "token", tokenForm(code), "", ""); w.Code != 403 || strings.Contains(w.Body.String(), "signed-fixture") {
			t.Fatal("removed authority granted access")
		}
	})
	t.Run("expiry", func(t *testing.T) {
		h, _, _, server := newHTTPFixture(t)
		code := issueHTTPCode(t, h)
		server.FastForward(2 * time.Minute)
		if w := callHTTP(h, "POST", "token", tokenForm(code), "", ""); w.Code != 400 {
			t.Fatal("expired code granted access")
		}
	})
	for _, limit := range []httpLimiter{{allowed: false}, {err: errors.New("private dependency detail")}} {
		h, _, _, _ := newHTTPFixture(t)
		h.options.Limiter = limit
		w := callHTTP(h, "GET", "authorize?"+authorizeValues().Encode(), nil, "", "")
		if w.Code != 429 && w.Code != 503 || strings.Contains(w.Body.String(), "private") {
			t.Fatal("limiter failure not closed")
		}
	}
}

func TestNativeMountNeverRedirectsCredentialAliasesOrRunsGenericCORS(t *testing.T) {
	h, _, _, _ := newHTTPFixture(t)
	mounted := Mount(h, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(202)
	}))
	for _, path := range []string{"authorize/", "token/", "resume/", "token/extra", "authorize//", "clients/desktop/"} {
		w := callHTTP(mounted, "GET", path+"?code=never-log-this", nil, "", "")
		if w.Code != 404 || w.Header().Get("Location") != "" || w.Header().Get("Access-Control-Allow-Origin") != "" || strings.Contains(w.Body.String(), "never-log-this") {
			t.Fatalf("unsafe alias: %s status=%d", path, w.Code)
		}
	}
	if w := callHTTP(mounted, "OPTIONS", "token", nil, "", "https://attacker.invalid"); w.Code != 405 || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("preflight reached generic CORS")
	}
}
