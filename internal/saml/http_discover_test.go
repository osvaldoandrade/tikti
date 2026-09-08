package saml

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/osvaldoandrade/tikti/pkg/config"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// discoverMockStore is a purpose-built Store mock for the Discover handler tests.
type discoverMockStore struct {
	stubStore // embed to satisfy the full interface

	getDomainFn func(ctx context.Context, domain string) (string, error)
}

func (m *discoverMockStore) GetDomain(ctx context.Context, domain string) (string, error) {
	if m.getDomainFn != nil {
		return m.getDomainFn(ctx, domain)
	}
	return "", errors.New("saml: domain not found")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newDiscoverHandler(store *discoverMockStore) *Handler {
	reg := prometheus.NewRegistry()
	return NewHandler(Deps{
		Store:   store,
		Clock:   NewFakeClock(),
		Metrics: NewMetrics(reg),
		Cfg:     config.SAMLConfig{Discover: config.DiscoverConfig{Enabled: true}},
	})
}

func execDiscover(h *Handler, query string) *httptest.ResponseRecorder {
	target := "/saml/discover"
	method := http.MethodGet
	body := strings.NewReader("")
	if query != "" {
		method = http.MethodPost
		body = strings.NewReader(query)
	}
	req := httptest.NewRequest(method, target, body)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rr := httptest.NewRecorder()
	h.Discover(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestDiscover_KnownDomain_Redirect verifies that a known email domain
// produces a 302 redirect to /saml/login/{tid}.
func TestDiscover_KnownDomain_Redirect(t *testing.T) {
	store := &discoverMockStore{
		getDomainFn: func(_ context.Context, domain string) (string, error) {
			if domain == "acme.com" {
				return "t-acme-001", nil
			}
			return "", errors.New("saml: domain not found")
		},
	}
	h := newDiscoverHandler(store)
	rr := execDiscover(h, "email=alice@acme.com")

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
	}

	loc := rr.Header().Get("Location")
	want := "/saml/login/t-acme-001"
	if loc != want {
		t.Errorf("Location = %q, want %q", loc, want)
	}
}

// TestDiscover_UnknownDomain_ReRender verifies that an unknown email domain
// re-renders the form with a "Workspace not found." message.
func TestDiscover_UnknownDomain_ReRender(t *testing.T) {
	store := &discoverMockStore{
		getDomainFn: func(_ context.Context, _ string) (string, error) {
			return "", errors.New("saml: domain not found")
		},
	}
	h := newDiscoverHandler(store)
	rr := execDiscover(h, "email=bob@unknown.org")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Workspace not found.") {
		t.Errorf("body missing 'Workspace not found.' message:\n%s", body)
	}
	if strings.Contains(body, "bob@unknown.org") {
		t.Errorf("body reflected email value:\n%s", body)
	}
}

// TestDiscover_XSS_Escaped verifies that user-supplied input containing a
// <script> tag is rendered escaped in the HTML output (no unescaped reflection).
func TestDiscover_XSS_Escaped(t *testing.T) {
	store := &discoverMockStore{
		getDomainFn: func(_ context.Context, _ string) (string, error) {
			return "", errors.New("saml: domain not found")
		},
	}
	h := newDiscoverHandler(store)

	xss := `<script>alert(1)</script>@evil.com`
	rr := execDiscover(h, "email="+xss)

	body := rr.Body.String()

	// The literal <script> tag must NOT appear unescaped.
	if strings.Contains(body, "<script>") {
		t.Errorf("body contains unescaped <script> tag:\n%s", body)
	}

	// Submitted input must not be reflected even after escaping.
	if strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("body reflected escaped input:\n%s", body)
	}
}

func TestDiscoverRejectsEmailInURLAndSetsPrivacyHeaders(t *testing.T) {
	h := newDiscoverHandler(&discoverMockStore{})
	req := httptest.NewRequest(http.MethodGet, "/saml/discover?email=victim@example.com", nil)
	recorder := httptest.NewRecorder()
	h.Discover(recorder, req)
	if recorder.Code != http.StatusBadRequest || strings.Contains(recorder.Body.String(), "victim@example.com") {
		t.Fatalf("URL email response = %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("privacy headers = %v", recorder.Header())
	}
}

func TestDiscoverDisabledAtHandlerBoundary(t *testing.T) {
	h := NewHandler(Deps{Cfg: config.SAMLConfig{Discover: config.DiscoverConfig{Enabled: false}}})
	recorder := httptest.NewRecorder()
	h.Discover(recorder, httptest.NewRequest(http.MethodGet, "/saml/discover", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("disabled discovery status = %d", recorder.Code)
	}
}
