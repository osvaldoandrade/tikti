package saml

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// loginMockStore is a purpose-built Store mock for the Login handler tests.
type loginMockStore struct {
	stubStore // embed to satisfy the full interface

	getIdPFn    func(ctx context.Context, tid string) (IdPRecord, error)
	putRequests []RequestRecord
}

func (m *loginMockStore) GetIdP(ctx context.Context, tid string) (IdPRecord, error) {
	if m.getIdPFn != nil {
		return m.getIdPFn(ctx, tid)
	}
	return IdPRecord{}, nil
}

func (m *loginMockStore) PutRequest(_ context.Context, rec RequestRecord) error {
	m.putRequests = append(m.putRequests, rec)
	return nil
}

// loginMockProvider is a purpose-built Provider mock for the Login handler tests.
type loginMockProvider struct {
	stubProvider // embed to satisfy the full interface

	buildAuthnFn func(ctx context.Context, in BuildAuthnRequestInput) (*AuthnRequest, error)
}

func (m *loginMockProvider) BuildAuthnRequest(ctx context.Context, in BuildAuthnRequestInput) (*AuthnRequest, error) {
	if m.buildAuthnFn != nil {
		return m.buildAuthnFn(ctx, in)
	}
	return &AuthnRequest{
		ID:          "_" + in.RequestID,
		RedirectURL: "https://idp.example.com/sso?SAMLRequest=test",
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const testTID = "t-login-001"
const testSSOURL = "https://idp.example.com/sso"

func defaultIdP() IdPRecord {
	return IdPRecord{
		TenantID:     testTID,
		EntityID:     "https://idp.example.com",
		SSOURL:       testSSOURL,
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	}
}

func defaultCfg() config.SAMLConfig {
	return config.SAMLConfig{
		Enabled: true,
		SP: config.SPConfig{
			EntityID:   "https://auth.example.com/saml",
			ACSURL:     "https://auth.example.com/saml/acs",
			RequestTTL: 300 * time.Second,
		},
	}
}

// newLoginHandler wires a Handler with the given mock store and provider.
func newLoginHandler(store *loginMockStore, prov *loginMockProvider) *Handler {
	reg := prometheus.NewRegistry()
	return NewHandler(Deps{
		Store:    store,
		Provider: prov,
		Clock:    NewFakeClock(),
		Cfg:      defaultCfg(),
		Metrics:  NewMetrics(reg),
	})
}

// execLogin performs a GET /saml/login/{tid} through a chi router.
func execLogin(h *Handler, tid string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	r.Get("/saml/login/{tid}", h.Login)

	req := httptest.NewRequest(http.MethodGet, "/saml/login/"+tid, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestLogin_Redirects302(t *testing.T) {
	idp := defaultIdP()
	redirectURL := testSSOURL + "?SAMLRequest=encoded"

	store := &loginMockStore{
		getIdPFn: func(_ context.Context, tid string) (IdPRecord, error) {
			if tid == testTID {
				return idp, nil
			}
			return IdPRecord{}, ErrIdPNotFound
		},
	}
	prov := &loginMockProvider{
		buildAuthnFn: func(_ context.Context, _ BuildAuthnRequestInput) (*AuthnRequest, error) {
			return &AuthnRequest{ID: "_abc", RedirectURL: redirectURL}, nil
		},
	}

	h := newLoginHandler(store, prov)
	rr := execLogin(h, testTID)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
	}

	loc := rr.Header().Get("Location")
	if loc != redirectURL {
		t.Errorf("Location = %q, want %q", loc, redirectURL)
	}

	// Acceptance: RedirectURL under 8 KiB.
	if len(redirectURL) > 8192 {
		t.Errorf("redirect URL length %d exceeds 8 KiB", len(redirectURL))
	}
}

func TestLogin_StateCookieSet(t *testing.T) {
	store := &loginMockStore{
		getIdPFn: func(_ context.Context, _ string) (IdPRecord, error) {
			return defaultIdP(), nil
		},
	}
	prov := &loginMockProvider{}

	h := newLoginHandler(store, prov)
	rr := execLogin(h, testTID)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
	}

	var found *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "tikti_saml_state" {
			found = c
			break
		}
	}

	if found == nil {
		t.Fatal("tikti_saml_state cookie not set")
	}
	if found.Path != "/saml" {
		t.Errorf("cookie Path = %q, want /saml", found.Path)
	}
	if !found.Secure {
		t.Error("cookie Secure = false, want true")
	}
	if !found.HttpOnly {
		t.Error("cookie HttpOnly = false, want true")
	}
	if found.SameSite != http.SameSiteNoneMode {
		t.Errorf("cookie SameSite = %v, want SameSiteNoneMode", found.SameSite)
	}
	if found.MaxAge != 300 {
		t.Errorf("cookie MaxAge = %d, want 300", found.MaxAge)
	}
	if found.Value == "" {
		t.Error("cookie Value is empty, expected request ID")
	}
}

func TestLogin_RequestRecordPersisted(t *testing.T) {
	store := &loginMockStore{
		getIdPFn: func(_ context.Context, _ string) (IdPRecord, error) {
			return defaultIdP(), nil
		},
	}
	prov := &loginMockProvider{}

	h := newLoginHandler(store, prov)
	rr := execLogin(h, testTID)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
	}

	if len(store.putRequests) != 1 {
		t.Fatalf("PutRequest called %d times, want 1", len(store.putRequests))
	}

	rec := store.putRequests[0]
	if rec.TenantID != testTID {
		t.Errorf("TenantID = %q, want %q", rec.TenantID, testTID)
	}
	if rec.ID == "" {
		t.Error("request ID is empty")
	}
	if rec.ACSURL != "https://auth.example.com/saml/acs" {
		t.Errorf("ACSURL = %q, want %q", rec.ACSURL, "https://auth.example.com/saml/acs")
	}
	if rec.IssueInstant.IsZero() {
		t.Error("IssueInstant is zero")
	}

	// Verify the cookie value matches the persisted request ID.
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "tikti_saml_state" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatal("tikti_saml_state cookie not found")
	}
	if cookie.Value != rec.ID {
		t.Errorf("cookie value %q does not match persisted request ID %q", cookie.Value, rec.ID)
	}
}

func TestLogin_UnknownTenant_404(t *testing.T) {
	store := &loginMockStore{
		getIdPFn: func(_ context.Context, _ string) (IdPRecord, error) {
			return IdPRecord{}, ErrIdPNotFound
		},
	}
	prov := &loginMockProvider{}

	h := newLoginHandler(store, prov)
	rr := execLogin(h, "unknown-tid")

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}

	body := rr.Body.String()
	if !strings.Contains(body, string(ReasonTIDUnknown)) {
		t.Errorf("body = %q, want to contain %q", body, ReasonTIDUnknown)
	}
}
