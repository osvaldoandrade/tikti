package saml

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
)

// ---------------------------------------------------------------------------
// Test helpers — stubs
// ---------------------------------------------------------------------------

// testProvider stubs Provider for handler tests.
type testProvider struct {
	logoutResult *LogoutRequest
	logoutErr    error
}

func (p *testProvider) BuildAuthnRequest(_ context.Context, _ BuildAuthnRequestInput) (*AuthnRequest, error) {
	return nil, nil
}

func (p *testProvider) ValidateResponse(_ context.Context, _ ValidateResponseInput) (*VerifiedAssertion, error) {
	return nil, nil
}

func (p *testProvider) BuildLogoutRequest(_ context.Context, _ BuildLogoutRequestInput) (*LogoutRequest, error) {
	return p.logoutResult, p.logoutErr
}

func (p *testProvider) ValidateLogoutMessage(_ context.Context, _ ValidateLogoutInput) (*VerifiedLogout, error) {
	return nil, nil
}

func (p *testProvider) SPMetadata(_ context.Context) ([]byte, error) {
	return nil, nil
}

func (p *testProvider) ParseIdPMetadata(_ context.Context, _ []byte) (*IdPRecord, error) {
	return nil, nil
}

// testStore stubs Store for handler tests.
type testStore struct {
	stubStore
	idp      IdPRecord
	idpErr   error
	index    IndexRecord
	indexErr error
}

func (s *testStore) GetIdP(_ context.Context, _ string) (IdPRecord, error) {
	return s.idp, s.idpErr
}

func (s *testStore) GetIndex(_ context.Context, _ string) (IndexRecord, error) {
	return s.index, s.indexErr
}

// signTestToken creates a valid HS256 JWT with the given subject.
func signTestToken(t *testing.T, sub, secret string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign test token: %v", err)
	}
	return signed
}

// newTestHandler builds a Handler wired with the given stubs.
func newTestHandler(prov Provider, store Store) *Handler {
	return NewHandler(Deps{
		Provider:  prov,
		Store:     store,
		Bridge:    &stubSessionBridge{},
		Clock:     NewFakeClock(),
		Cfg: config.SAMLConfig{
			ACS: config.ACSConfig{CookieName: "tikti_id"},
		},
		Metrics:   NewMetrics(prometheus.NewRegistry()),
		Audit:     LogEmitter{},
		JwtSecret: "test-secret",
	})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestLogout_302ToIdP(t *testing.T) {
	store := &testStore{
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

	prov := &testProvider{
		logoutResult: &LogoutRequest{
			ID:          "_abc123",
			RedirectURL: "https://idp.example.com/slo?SAMLRequest=xxx",
		},
	}

	h := newTestHandler(prov, store)
	token := signTestToken(t, "user@example.com", "test-secret")

	req := httptest.NewRequest(http.MethodGet, "/saml/logout/t-001", nil)
	req.SetPathValue("tid", "t-001")
	req.AddCookie(&http.Cookie{Name: "tikti_id", Value: token})

	rr := httptest.NewRecorder()
	h.Logout(rr, req)

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
		store := &testStore{}
		prov := &testProvider{}
		h := newTestHandler(prov, store)

		req := httptest.NewRequest(http.MethodGet, "/saml/logout/t-001", nil)
		req.SetPathValue("tid", "t-001")

		rr := httptest.NewRecorder()
		h.Logout(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		store := &testStore{}
		prov := &testProvider{}
		h := newTestHandler(prov, store)

		req := httptest.NewRequest(http.MethodGet, "/saml/logout/t-001", nil)
		req.SetPathValue("tid", "t-001")
		req.AddCookie(&http.Cookie{Name: "tikti_id", Value: "not-a-jwt"})

		rr := httptest.NewRecorder()
		h.Logout(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("index not found", func(t *testing.T) {
		store := &testStore{
			indexErr: errors.New("saml: index not found"),
		}
		prov := &testProvider{}
		h := newTestHandler(prov, store)
		token := signTestToken(t, "user@example.com", "test-secret")

		req := httptest.NewRequest(http.MethodGet, "/saml/logout/t-001", nil)
		req.SetPathValue("tid", "t-001")
		req.AddCookie(&http.Cookie{Name: "tikti_id", Value: token})

		rr := httptest.NewRecorder()
		h.Logout(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})
}
