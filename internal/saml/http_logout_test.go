package saml

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
)

// ---------------------------------------------------------------------------
// Test helpers — stubs
// ---------------------------------------------------------------------------

// logoutTestProvider stubs Provider for logout handler tests.
type logoutTestProvider struct {
	logoutResult *LogoutRequest
	logoutErr    error
}

func (p *logoutTestProvider) BuildAuthnRequest(_ context.Context, _ BuildAuthnRequestInput) (*AuthnRequest, error) {
	return nil, nil
}

func (p *logoutTestProvider) ValidateResponse(_ context.Context, _ ValidateResponseInput) (*VerifiedAssertion, error) {
	return nil, nil
}

func (p *logoutTestProvider) BuildLogoutRequest(_ context.Context, _ BuildLogoutRequestInput) (*LogoutRequest, error) {
	return p.logoutResult, p.logoutErr
}

func (p *logoutTestProvider) BuildLogoutResponse(_ context.Context, _ BuildLogoutResponseInput) (*LogoutResponseResult, error) {
	return nil, nil
}

func (p *logoutTestProvider) ValidateLogoutMessage(_ context.Context, _ ValidateLogoutInput) (*VerifiedLogout, error) {
	return nil, nil
}

func (p *logoutTestProvider) SPMetadata(_ context.Context) ([]byte, error) {
	return nil, nil
}

func (p *logoutTestProvider) ParseIdPMetadata(_ context.Context, _ []byte) (*IdPRecord, error) {
	return nil, nil
}

// logoutTestStore stubs Store for logout handler tests.
type logoutTestStore struct {
	stubStore
	idp      IdPRecord
	idpErr   error
	index    IndexRecord
	indexErr error
}

func (s *logoutTestStore) GetIdP(_ context.Context, _ string) (IdPRecord, error) {
	return s.idp, s.idpErr
}

func (s *logoutTestStore) GetIndex(_ context.Context, _ string) (IndexRecord, error) {
	return s.index, s.indexErr
}

// fakeJWT builds a minimal JWT (header.payload.signature) whose payload
// contains the given subject. The token is not cryptographically signed;
// subjectFromToken only decodes the payload segment.
func fakeJWT(sub string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]string{"sub": sub})
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + payloadB64 + ".fakesig"
}

// newLogoutTestHandler builds a Handler wired with the given stubs.
func newLogoutTestHandler(prov Provider, store Store) *Handler {
	return NewHandler(Deps{
		Provider: prov,
		Store:    store,
		Bridge:   &stubSessionBridge{},
		Clock:    NewFakeClock(),
		Cfg: config.SAMLConfig{
			ACS: config.ACSConfig{CookieName: "tikti_idt"},
		},
		Metrics: NewMetrics(prometheus.NewRegistry()),
		Audit:   LogEmitter{},
	})
}

// serveLogout sets up a chi router and dispatches a single request through
// the Logout handler so that chi.URLParam works correctly in tests.
func serveLogout(h *Handler, req *http.Request) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	r.Get("/saml/logout/{tid}", h.Logout)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestLogout_302ToIdP(t *testing.T) {
	store := &logoutTestStore{
		idp: IdPRecord{
			TenantID: "t-001",
			EntityID: "https://idp.example.com",
			SLOURL:   "https://idp.example.com/slo",
		},
		index: IndexRecord{
			TenantID:     "t-001",
			Subject:      "user@example.com",
			SessionIndex: "si-001",
			NotOnOrAfter: time.Now().Add(time.Hour),
		},
	}

	prov := &logoutTestProvider{
		logoutResult: &LogoutRequest{
			ID:          "_abc123",
			RedirectURL: "https://idp.example.com/slo?SAMLRequest=xxx",
		},
	}

	h := newLogoutTestHandler(prov, store)
	token := fakeJWT("user@example.com")

	req := httptest.NewRequest(http.MethodGet, "/saml/logout/t-001", nil)
	req.AddCookie(&http.Cookie{Name: "tikti_idt", Value: token})

	rr := serveLogout(h, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
	}

	loc := rr.Header().Get("Location")
	if loc != "https://idp.example.com/slo?SAMLRequest=xxx" {
		t.Errorf("Location = %q, want %q", loc, "https://idp.example.com/slo?SAMLRequest=xxx")
	}
}

func TestLogout_NoSession_400(t *testing.T) {
	t.Run("no cookie", func(t *testing.T) {
		h := newLogoutTestHandler(&logoutTestProvider{}, &logoutTestStore{})

		req := httptest.NewRequest(http.MethodGet, "/saml/logout/t-001", nil)
		rr := serveLogout(h, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		h := newLogoutTestHandler(&logoutTestProvider{}, &logoutTestStore{})

		req := httptest.NewRequest(http.MethodGet, "/saml/logout/t-001", nil)
		req.AddCookie(&http.Cookie{Name: "tikti_idt", Value: "not-a-jwt"})
		rr := serveLogout(h, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("index not found", func(t *testing.T) {
		store := &logoutTestStore{
			indexErr: errors.New("saml: index not found"),
		}
		h := newLogoutTestHandler(&logoutTestProvider{}, store)
		token := fakeJWT("user@example.com")

		req := httptest.NewRequest(http.MethodGet, "/saml/logout/t-001", nil)
		req.AddCookie(&http.Cookie{Name: "tikti_idt", Value: token})
		rr := serveLogout(h, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})
}
