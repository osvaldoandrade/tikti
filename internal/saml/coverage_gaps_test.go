package saml

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/osvaldoandrade/tikti/pkg/domain"
	"github.com/prometheus/client_golang/prometheus"
)

// ===========================================================================
// refresh.go — refreshOne success, parse error, store error, httpFetch
// ===========================================================================

func TestRefresh_RefreshOne_Success(t *testing.T) {
	// Use a real IdP metadata fixture so ParseIdPMetadata succeeds.
	metaXML, err := os.ReadFile("testdata/idp_okta.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	existing := IdPRecord{
		TenantID:    "t-ok",
		EntityID:    "http://www.okta.com/exk123abc",
		MetadataURL: "https://idp.example.com/metadata",
		SSOURL:      "https://old.example.com/sso",
		AttributeMap: map[string][]string{
			"email": {"mail"},
		},
	}
	store := newRefreshMemStore(existing)

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	r := NewRefresher(RefresherConfig{
		Store:     store,
		Metrics:   m,
		Interval:  1 * time.Hour,
		MaxJitter: 0,
		Fetcher:   func(_ string) ([]byte, error) { return metaXML, nil },
	})

	r.tick(context.Background())

	got, err := store.GetIdP(context.Background(), "t-ok")
	if err != nil {
		t.Fatalf("GetIdP: %v", err)
	}
	// Should have updated the entity ID from metadata.
	if got.EntityID != "http://www.okta.com/exk123abc" {
		t.Errorf("EntityID = %q, want %q", got.EntityID, "http://www.okta.com/exk123abc")
	}
	// MetadataURL and TenantID should be carried over.
	if got.MetadataURL != existing.MetadataURL {
		t.Errorf("MetadataURL = %q, want %q", got.MetadataURL, existing.MetadataURL)
	}
	if got.TenantID != "t-ok" {
		t.Errorf("TenantID = %q, want %q", got.TenantID, "t-ok")
	}
	// AttributeMap should be carried over if new one is nil.
	if got.AttributeMap == nil {
		t.Error("AttributeMap should be carried over from existing record")
	}
	// consecFails should be reset to 0.
	if r.consecFails["t-ok"] != 0 {
		t.Errorf("consecFails = %d, want 0", r.consecFails["t-ok"])
	}
}

func TestRefresh_RefreshOne_ParseFails(t *testing.T) {
	existing := IdPRecord{
		TenantID:    "t-parse",
		MetadataURL: "https://idp.example.com/metadata",
	}
	store := newRefreshMemStore(existing)

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	r := NewRefresher(RefresherConfig{
		Store:     store,
		Metrics:   m,
		Interval:  1 * time.Hour,
		MaxJitter: 0,
		Fetcher:   func(_ string) ([]byte, error) { return []byte("not xml"), nil },
	})

	r.tick(context.Background())

	// Record should be unchanged.
	got, _ := store.GetIdP(context.Background(), "t-parse")
	if got.EntityID != "" {
		t.Errorf("EntityID should not have been updated")
	}
}

func TestRefresh_RefreshOne_EmptyMetadataURL(t *testing.T) {
	existing := IdPRecord{
		TenantID:    "t-no-url",
		MetadataURL: "",
	}
	store := newRefreshMemStore(existing)

	r := NewRefresher(RefresherConfig{
		Store:     store,
		Interval:  1 * time.Hour,
		MaxJitter: 0,
		Fetcher:   func(_ string) ([]byte, error) { return nil, errors.New("should not be called") },
	})

	// refreshOne should return immediately for empty MetadataURL.
	r.refreshOne(context.Background(), existing)
}

func TestRefresh_RefreshOne_StorePutFails(t *testing.T) {
	metaXML, err := os.ReadFile("testdata/idp_okta.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	existing := IdPRecord{
		TenantID:    "t-store-err",
		MetadataURL: "https://idp.example.com/metadata",
	}
	putErr := errors.New("redis down")

	store := &failingPutStore{
		refreshMemStore: *newRefreshMemStore(existing),
		putErr:          putErr,
	}

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	r := NewRefresher(RefresherConfig{
		Store:     store,
		Metrics:   m,
		Interval:  1 * time.Hour,
		MaxJitter: 0,
		Fetcher:   func(_ string) ([]byte, error) { return metaXML, nil },
	})

	r.tick(context.Background())

	if r.consecFails["t-store-err"] != 1 {
		t.Errorf("consecFails = %d, want 1", r.consecFails["t-store-err"])
	}
}

// failingPutStore wraps refreshMemStore but returns an error from PutIdP.
type failingPutStore struct {
	refreshMemStore
	putErr error
}

func (s *failingPutStore) PutIdP(_ context.Context, _ IdPRecord) error {
	return s.putErr
}

func TestRefresh_Tick_ListError(t *testing.T) {
	store := &listErrorStore{}

	r := NewRefresher(RefresherConfig{
		Store:     store,
		Interval:  1 * time.Hour,
		MaxJitter: 0,
		Fetcher:   func(_ string) ([]byte, error) { return nil, nil },
	})

	// Should not panic.
	r.tick(context.Background())
}

type listErrorStore struct {
	stubStore
}

func (s *listErrorStore) ListIdPs(_ context.Context) ([]IdPRecord, error) {
	return nil, errors.New("list failed")
}

func TestRefresh_Run_CancelDuringJitter(t *testing.T) {
	store := &tickCountingStore{}
	r := NewRefresher(RefresherConfig{
		Store:     store,
		Interval:  50 * time.Millisecond,
		MaxJitter: 10 * time.Second, // long jitter
		Fetcher:   func(_ string) ([]byte, error) { return nil, errors.New("stub") },
	})

	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	// Cancel quickly while still in jitter.
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)
	// The goroutine should have exited.
}

func TestRefresh_HandleFailure_NilMetrics(t *testing.T) {
	r := NewRefresher(RefresherConfig{
		Store:     &stubStore{},
		Interval:  1 * time.Hour,
		MaxJitter: 0,
		Fetcher:   func(_ string) ([]byte, error) { return nil, nil },
	})

	// Should not panic with nil metrics.
	r.handleFailure("t-nil", errors.New("test err"))
	if r.consecFails["t-nil"] != 1 {
		t.Errorf("consecFails = %d, want 1", r.consecFails["t-nil"])
	}
}

func TestRefresh_RefreshOne_NilMetrics(t *testing.T) {
	metaXML, err := os.ReadFile("testdata/idp_okta.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	existing := IdPRecord{
		TenantID:    "t-nil-m",
		MetadataURL: "https://idp.example.com/metadata",
	}
	store := newRefreshMemStore(existing)

	r := NewRefresher(RefresherConfig{
		Store:     store,
		Interval:  1 * time.Hour,
		MaxJitter: 0,
		Fetcher:   func(_ string) ([]byte, error) { return metaXML, nil },
	})

	// Should not panic with nil metrics on success path.
	r.refreshOne(context.Background(), existing)
}

// ===========================================================================
// http_discover.go — empty email form, invalid email
// ===========================================================================

func TestDiscover_NoEmail_BlankForm(t *testing.T) {
	store := &discoverMockStore{}
	h := newDiscoverHandler(store)
	rr := execDiscover(h, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Discover your workspace") {
		t.Error("blank form not rendered")
	}
}

func TestDiscover_InvalidEmail_NoAt(t *testing.T) {
	store := &discoverMockStore{}
	h := newDiscoverHandler(store)
	rr := execDiscover(h, "email=nodomain")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "valid email") {
		t.Error("expected invalid email error message")
	}
}

func TestDiscover_InvalidEmail_TrailingAt(t *testing.T) {
	store := &discoverMockStore{}
	h := newDiscoverHandler(store)
	rr := execDiscover(h, "email=user@")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "valid email") {
		t.Error("expected invalid email error message")
	}
}

func TestDiscover_GetDomainReturnsEmpty(t *testing.T) {
	store := &discoverMockStore{
		getDomainFn: func(_ context.Context, _ string) (string, error) {
			return "", nil // empty TID but no error
		},
	}
	h := newDiscoverHandler(store)
	rr := execDiscover(h, "email=user@empty.com")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Workspace not found.") {
		t.Error("expected workspace not found message for empty tid")
	}
}

// ===========================================================================
// http_login.go — BuildAuthnRequest error, PutRequest error, internal GetIdP error
// ===========================================================================

func TestLogin_BuildAuthnRequestError_500(t *testing.T) {
	store := &loginMockStore{
		getIdPFn: func(_ context.Context, _ string) (IdPRecord, error) {
			return defaultIdP(), nil
		},
	}
	prov := &loginMockProvider{
		buildAuthnFn: func(_ context.Context, _ BuildAuthnRequestInput) (*AuthnRequest, error) {
			return nil, errors.New("build failed")
		},
	}

	h := newLoginHandler(store, prov)
	rr := execLogin(h, testTID)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestLogin_PutRequestError_500(t *testing.T) {
	putErrStore := &loginMockStoreWithPutError{
		loginMockStore: loginMockStore{
			getIdPFn: func(_ context.Context, _ string) (IdPRecord, error) {
				return defaultIdP(), nil
			},
		},
		putErr: errors.New("redis down"),
	}
	prov := &loginMockProvider{}

	h := newLoginHandler(&putErrStore.loginMockStore, prov)
	// Override the store on the handler.
	h.store = putErrStore

	rr := execLogin(h, testTID)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

// loginMockStoreWithPutError wraps loginMockStore and fails PutRequest.
type loginMockStoreWithPutError struct {
	loginMockStore
	putErr error
}

func (m *loginMockStoreWithPutError) PutRequest(_ context.Context, _ RequestRecord) error {
	return m.putErr
}

func TestLogin_GetIdPInternalError_500(t *testing.T) {
	store := &loginMockStore{
		getIdPFn: func(_ context.Context, _ string) (IdPRecord, error) {
			return IdPRecord{}, errors.New("internal db error")
		},
	}
	prov := &loginMockProvider{}

	h := newLoginHandler(store, prov)
	rr := execLogin(h, testTID)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

// ===========================================================================
// http_metadata.go — SPMetadata error path
// ===========================================================================

func TestMetadata_ProviderError_500(t *testing.T) {
	h := NewHandler(Deps{Provider: &metadataStubProvider{err: errors.New("broken")}})
	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	rec := httptest.NewRecorder()
	h.Metadata(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// ===========================================================================
// http_logout.go — IdP lookup error, BuildLogoutRequest error
// ===========================================================================

func TestLogout_IdPLookupError_400(t *testing.T) {
	store := &logoutTestStore{
		idpErr: ErrIdPNotFound,
		index: IndexRecord{
			TenantID:     "t-001",
			Subject:      "user@example.com",
			SessionIndex: "si-001",
		},
	}
	prov := &logoutTestProvider{}
	h := newLogoutTestHandler(prov, store)
	token := fakeJWT("user@example.com")

	req := httptest.NewRequest(http.MethodGet, "/saml/logout/t-001", nil)
	req.AddCookie(&http.Cookie{Name: "tikti_idt", Value: token})
	rr := serveLogout(h, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestLogout_BuildLogoutRequestError_500(t *testing.T) {
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
		},
	}
	prov := &logoutTestProvider{logoutErr: errors.New("build error")}
	h := newLogoutTestHandler(prov, store)
	token := fakeJWT("user@example.com")

	req := httptest.NewRequest(http.MethodGet, "/saml/logout/t-001", nil)
	req.AddCookie(&http.Cookie{Name: "tikti_idt", Value: token})
	rr := serveLogout(h, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

// ===========================================================================
// http_slo.go — error branches
// ===========================================================================

func TestSLO_MethodNotAllowed(t *testing.T) {
	store := newMockSLOStore_internal()
	prov := &sloInternalMockProvider{}
	h := newSLOInternalHandler(prov, store)

	req := httptest.NewRequest(http.MethodPut, "/saml/slo", nil)
	rr := httptest.NewRecorder()
	h.SLO(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestSLO_GET_ValidationError(t *testing.T) {
	store := newMockSLOStore_internal()
	prov := &sloInternalMockProvider{
		validateErr: errors.New("bad sig"),
	}
	h := newSLOInternalHandler(prov, store)

	req := httptest.NewRequest(http.MethodGet, "/saml/slo?SAMLResponse=dGVzdA==", nil)
	rr := httptest.NewRecorder()
	h.SLO(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestSLO_GET_NonSuccessStatus(t *testing.T) {
	store := newMockSLOStore_internal()
	prov := &sloInternalMockProvider{
		validateResult: &VerifiedLogout{
			IsResponse: true,
			Status:     "urn:oasis:names:tc:SAML:2.0:status:Requester",
		},
	}
	h := newSLOInternalHandler(prov, store)

	req := httptest.NewRequest(http.MethodGet, "/saml/slo?SAMLResponse=dGVzdA==", nil)
	rr := httptest.NewRecorder()
	h.SLO(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestSLO_GET_NotResponse(t *testing.T) {
	store := newMockSLOStore_internal()
	prov := &sloInternalMockProvider{
		validateResult: &VerifiedLogout{
			IsResponse: false,
		},
	}
	h := newSLOInternalHandler(prov, store)

	req := httptest.NewRequest(http.MethodGet, "/saml/slo?SAMLResponse=dGVzdA==", nil)
	rr := httptest.NewRecorder()
	h.SLO(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestSLO_GET_NoCookie(t *testing.T) {
	store := newMockSLOStore_internal()
	prov := &sloInternalMockProvider{
		validateResult: &VerifiedLogout{
			IsResponse: true,
			Status:     "urn:oasis:names:tc:SAML:2.0:status:Success",
		},
	}
	h := newSLOInternalHandler(prov, store)

	req := httptest.NewRequest(http.MethodGet, "/saml/slo?SAMLResponse=dGVzdA==", nil)
	// No SLO cookie — the handler should still redirect.
	rr := httptest.NewRecorder()
	h.SLO(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusFound)
	}
}

func TestSLO_POST_NoSAMLRequest(t *testing.T) {
	store := newMockSLOStore_internal()
	prov := &sloInternalMockProvider{}
	h := newSLOInternalHandler(prov, store)

	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/saml/slo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.SLO(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestSLO_POST_ValidationIsResponse(t *testing.T) {
	store := newMockSLOStore_internal()
	prov := &sloInternalMockProvider{
		validateResult: &VerifiedLogout{IsResponse: true}, // should be false for POST
	}
	h := newSLOInternalHandler(prov, store)

	encoded := base64.StdEncoding.EncodeToString([]byte(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_req1"/>`))
	form := url.Values{"SAMLRequest": {encoded}}
	req := httptest.NewRequest(http.MethodPost, "/saml/slo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.SLO(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestSLO_POST_GetIndexError(t *testing.T) {
	store := newMockSLOStore_internal()
	// No indexes in store → GetIndex will fail.
	prov := &sloInternalMockProvider{
		validateResult: &VerifiedLogout{
			IsResponse: false,
			NameID:     "unknown@example.com",
		},
	}
	h := newSLOInternalHandler(prov, store)

	encoded := base64.StdEncoding.EncodeToString([]byte(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_req1"/>`))
	form := url.Values{"SAMLRequest": {encoded}}
	req := httptest.NewRequest(http.MethodPost, "/saml/slo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.SLO(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestSLO_POST_GetIdPError(t *testing.T) {
	store := newMockSLOStore_internal()
	store.indexes["user@example.com"] = IndexRecord{TenantID: "t-missing"}
	// No idps → GetIdP will fail.
	prov := &sloInternalMockProvider{
		validateResult: &VerifiedLogout{
			IsResponse: false,
			NameID:     "user@example.com",
		},
	}
	h := newSLOInternalHandler(prov, store)

	encoded := base64.StdEncoding.EncodeToString([]byte(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_req1"/>`))
	form := url.Values{"SAMLRequest": {encoded}}
	req := httptest.NewRequest(http.MethodPost, "/saml/slo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.SLO(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestSLO_POST_BuildLogoutResponseError(t *testing.T) {
	store := newMockSLOStore_internal()
	store.indexes["user@example.com"] = IndexRecord{TenantID: "t-001"}
	store.idps["t-001"] = IdPRecord{TenantID: "t-001", SLOURL: "https://idp.example.com/slo"}

	prov := &sloInternalMockProvider{
		validateResult: &VerifiedLogout{
			IsResponse: false,
			NameID:     "user@example.com",
		},
		buildResponseErr: errors.New("build failed"),
	}
	h := newSLOInternalHandler(prov, store)

	encoded := base64.StdEncoding.EncodeToString([]byte(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_req1"/>`))
	form := url.Values{"SAMLRequest": {encoded}}
	req := httptest.NewRequest(http.MethodPost, "/saml/slo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.SLO(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

// Internal-package SLO test helpers (same pattern as external test but in-package).
type sloInternalMockProvider struct {
	stubProvider
	validateResult   *VerifiedLogout
	validateErr      error
	buildResponseErr error
}

func (m *sloInternalMockProvider) ValidateLogoutMessage(_ context.Context, _ ValidateLogoutInput) (*VerifiedLogout, error) {
	return m.validateResult, m.validateErr
}

func (m *sloInternalMockProvider) BuildLogoutResponse(_ context.Context, _ BuildLogoutResponseInput) (*LogoutResponseResult, error) {
	if m.buildResponseErr != nil {
		return nil, m.buildResponseErr
	}
	return &LogoutResponseResult{PostBody: []byte("<html>ok</html>")}, nil
}

type mockSLOInternalStore struct {
	stubStore
	indexes map[string]IndexRecord
	idps    map[string]IdPRecord
	deleted map[string]bool
}

func newMockSLOStore_internal() *mockSLOInternalStore {
	return &mockSLOInternalStore{
		indexes: make(map[string]IndexRecord),
		idps:    make(map[string]IdPRecord),
		deleted: make(map[string]bool),
	}
}

func (s *mockSLOInternalStore) GetIndex(_ context.Context, nameID string) (IndexRecord, error) {
	if rec, ok := s.indexes[nameID]; ok {
		return rec, nil
	}
	return IndexRecord{}, ErrIdPNotFound
}

func (s *mockSLOInternalStore) DeleteIndex(_ context.Context, nameID string) error {
	s.deleted[nameID] = true
	delete(s.indexes, nameID)
	return nil
}

func (s *mockSLOInternalStore) GetIdP(_ context.Context, tid string) (IdPRecord, error) {
	if rec, ok := s.idps[tid]; ok {
		return rec, nil
	}
	return IdPRecord{}, ErrIdPNotFound
}

func newSLOInternalHandler(prov Provider, store Store) *Handler {
	return NewHandler(Deps{
		Provider: prov,
		Store:    store,
		Clock:    NewFakeClock(),
		Metrics:  NewMetrics(prometheus.NewRegistry()),
	})
}

// ===========================================================================
// extractRequestID
// ===========================================================================

func TestExtractRequestID_Valid(t *testing.T) {
	reqXML := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_req-123" Version="2.0"/>`
	encoded := base64.StdEncoding.EncodeToString([]byte(reqXML))
	id := extractRequestID(encoded)
	if id != "_req-123" {
		t.Errorf("extractRequestID = %q, want %q", id, "_req-123")
	}
}

func TestExtractRequestID_InvalidBase64(t *testing.T) {
	id := extractRequestID("%%%not-base64")
	if id != "" {
		t.Errorf("extractRequestID = %q, want empty", id)
	}
}

func TestExtractRequestID_InvalidXML(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("not xml"))
	id := extractRequestID(encoded)
	if id != "" {
		t.Errorf("extractRequestID = %q, want empty", id)
	}
}

// ===========================================================================
// crypto.go — parseRSAPrivateKey, loadKeyPair edge cases, watch, reload
// ===========================================================================

func TestParseRSAPrivateKey_PKCS8_NonRSA(t *testing.T) {
	// Generate an EC key and marshal as PKCS#8 — parseRSAPrivateKey should
	// parse it but reject it as "not RSA".
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}

	_, err = parseRSAPrivateKey(der)
	if err == nil {
		t.Fatal("expected error for non-RSA PKCS#8 key")
	}
	if !strings.Contains(err.Error(), "not RSA") {
		t.Errorf("error = %v, want 'not RSA'", err)
	}
}

func TestParseRSAPrivateKey_PKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)

	parsed, err := parseRSAPrivateKey(der)
	if err != nil {
		t.Fatalf("parseRSAPrivateKey PKCS1: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestLoadKeyPair_NoPEMBlock_Key(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.key")
	certPath := filepath.Join(dir, "sp.crt")

	os.WriteFile(keyPath, []byte("not pem data"), 0600)
	// Write a valid cert PEM to certPath (won't be reached).
	writePEMKeyPair(t, dir, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	_, err := loadKeyPair(keyPath, certPath)
	if err == nil {
		t.Fatal("expected error for non-PEM key data")
	}
	if !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("error = %v, want 'no PEM block'", err)
	}
}

func TestLoadKeyPair_NoPEMBlock_Cert(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writePEMKeyPair(t, dir,
		time.Now().Add(-time.Hour),
		time.Now().Add(24*time.Hour),
	)
	certPath := filepath.Join(dir, "bad.crt")
	os.WriteFile(certPath, []byte("not pem data"), 0600)

	_, err := loadKeyPair(keyPath, certPath)
	if err == nil {
		t.Fatal("expected error for non-PEM cert data")
	}
	if !strings.Contains(err.Error(), "no CERTIFICATE PEM block") {
		t.Errorf("error = %v, want 'no CERTIFICATE PEM block'", err)
	}
}

func TestLoadKeyPair_NotYetValid(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := writePEMKeyPair(t, dir,
		time.Now().Add(24*time.Hour),  // not valid until tomorrow
		time.Now().Add(48*time.Hour),
	)

	_, err := loadKeyPair(keyPath, certPath)
	if err == nil {
		t.Fatal("expected error for not-yet-valid certificate")
	}
	if !strings.Contains(err.Error(), "not yet valid") {
		t.Errorf("error = %v, want 'not yet valid'", err)
	}
}

func TestLoadKeyPair_BadCertDER(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writePEMKeyPair(t, dir,
		time.Now().Add(-time.Hour),
		time.Now().Add(24*time.Hour),
	)
	certPath := filepath.Join(dir, "bad_der.crt")
	// Write a PEM with CERTIFICATE type but garbage DER.
	f, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}); err != nil {
		f.Close()
		t.Fatalf("encode PEM: %v", err)
	}
	f.Close()

	_, err = loadKeyPair(keyPath, certPath)
	if err == nil {
		t.Fatal("expected error for bad certificate DER")
	}
}

func TestKeyHolder_Watch_FileChange(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := writePEMKeyPair(t, dir,
		time.Now().Add(-time.Hour),
		time.Now().Add(24*time.Hour),
	)

	kh := NewKeyHolder(KeyHolderConfig{WatchFile: true})
	if err := kh.LoadKey(keyPath, certPath); err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	origSerial := kh.Cert().SerialNumber.String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kh.Start(ctx, keyPath, certPath)

	// Wait for watcher to be established.
	time.Sleep(200 * time.Millisecond)

	// Overwrite with a new key pair.
	writePEMKeyPair(t, dir,
		time.Now().Add(-time.Hour),
		time.Now().Add(48*time.Hour),
	)

	// Wait for reload.
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for key swap after file write")
		case <-ticker.C:
			if kh.Cert().SerialNumber.String() != origSerial {
				return // success
			}
		}
	}
}

func TestKeyHolder_Reload_Failure(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := writePEMKeyPair(t, dir,
		time.Now().Add(-time.Hour),
		time.Now().Add(24*time.Hour),
	)

	kh := NewKeyHolder(KeyHolderConfig{})
	if err := kh.LoadKey(keyPath, certPath); err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	origSerial := kh.Cert().SerialNumber.String()

	// Delete files so reload fails.
	os.Remove(keyPath)
	os.Remove(certPath)

	kh.reload(keyPath, certPath)

	// Key should remain unchanged.
	if kh.Cert().SerialNumber.String() != origSerial {
		t.Error("key should not have changed after failed reload")
	}
}

// ===========================================================================
// attr.go — AttrError.Error()
// ===========================================================================

func TestAttrError_Error(t *testing.T) {
	e := &AttrError{Reason: ReasonMissingAttribute, Field: "email"}
	s := e.Error()
	if !strings.Contains(s, "missing_attribute") || !strings.Contains(s, "email") {
		t.Errorf("Error() = %q, want to contain 'missing_attribute' and 'email'", s)
	}
}

// ===========================================================================
// clock.go — RealClock
// ===========================================================================

func TestSystemClock_Now(t *testing.T) {
	clk := SystemClock{}
	before := time.Now()
	now := clk.Now()
	after := time.Now()

	if now.Before(before) || now.After(after) {
		t.Errorf("SystemClock.Now() = %v, expected between %v and %v", now, before, after)
	}
}

func TestSystemClock_Since(t *testing.T) {
	clk := SystemClock{}
	t0 := time.Now()
	time.Sleep(5 * time.Millisecond)
	d := clk.Since(t0)
	if d < 5*time.Millisecond {
		t.Errorf("SystemClock.Since() = %v, expected >= 5ms", d)
	}
}

// ===========================================================================
// http_middleware.go — RequestID middleware
// ===========================================================================

func TestRequestID_GeneratesNew(t *testing.T) {
	var gotID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := RequestID(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotID == "" {
		t.Error("expected non-empty request ID in context")
	}
	if rec.Header().Get("X-Request-ID") != gotID {
		t.Errorf("response header X-Request-ID = %q, want %q", rec.Header().Get("X-Request-ID"), gotID)
	}
}

func TestRequestID_ReusesExisting(t *testing.T) {
	const existingID = "existing-req-id-123"
	var gotID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := RequestID(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", existingID)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotID != existingID {
		t.Errorf("gotID = %q, want %q", gotID, existingID)
	}
	if rec.Header().Get("X-Request-ID") != existingID {
		t.Errorf("response X-Request-ID = %q, want %q", rec.Header().Get("X-Request-ID"), existingID)
	}
}

// ===========================================================================
// errors_render.go — renderError with empty bucket, template execution
// ===========================================================================

func TestRenderError_AllBuckets(t *testing.T) {
	h := NewHandler(Deps{
		Metrics: NewMetrics(prometheus.NewRegistry()),
		Audit:   LogEmitter{},
		Clock:   NewFakeClock(),
	})

	for _, reason := range AllRejectReasons {
		t.Run(string(reason), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			h.renderError(rec, req, reason, http.StatusInternalServerError)

			if rec.Code != http.StatusInternalServerError {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
			}
			if rec.Header().Get("X-Tikti-Error-ID") == "" {
				t.Error("expected X-Tikti-Error-ID header")
			}
		})
	}
}

func TestRenderError_UnknownReason(t *testing.T) {
	h := NewHandler(Deps{
		Metrics: NewMetrics(prometheus.NewRegistry()),
		Audit:   LogEmitter{},
		Clock:   NewFakeClock(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.renderError(rec, req, Reason("unknown_reason"), http.StatusInternalServerError)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// ===========================================================================
// metadata.go — LoadCertFile, certPEMToBase64 edge cases, pickSSOURL
// ===========================================================================

func TestLoadCertFile_Valid(t *testing.T) {
	data, err := LoadCertFile("testdata/sp_signing.crt")
	if err != nil {
		t.Fatalf("LoadCertFile: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

func TestLoadCertFile_Nonexistent(t *testing.T) {
	_, err := LoadCertFile("testdata/nonexistent.crt")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestCertPEMToBase64_NonCertBlock(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	_, err := certPEMToBase64(keyPEM)
	if err == nil {
		t.Fatal("expected error for non-CERTIFICATE PEM block")
	}
}

func TestCertPEMToBase64_NilPEM(t *testing.T) {
	_, err := certPEMToBase64([]byte("not pem data"))
	if err == nil {
		t.Fatal("expected error for nil PEM block")
	}
}

func TestPickSSOURL_EmptyServices(t *testing.T) {
	_, err := pickSSOURL(nil)
	if err == nil {
		t.Fatal("expected error for empty services")
	}
}

func TestPickSSOURL_UnsupportedBinding(t *testing.T) {
	services := []singleSignOnService{
		{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", Location: "https://idp.example.com/sso"},
	}
	_, err := pickSSOURL(services)
	if err == nil {
		t.Fatal("expected error for unsupported binding")
	}
	if !errors.Is(err, ErrMetadataUnsupportedBind) {
		t.Errorf("err = %v, want ErrMetadataUnsupportedBind", err)
	}
}

func TestPickSSOURL_InsecureURL(t *testing.T) {
	services := []singleSignOnService{
		{Binding: BindingHTTPRedirect, Location: "http://idp.example.com/sso"},
	}
	_, err := pickSSOURL(services)
	if err == nil {
		t.Fatal("expected error for insecure URL")
	}
	if !errors.Is(err, ErrMetadataInsecureURL) {
		t.Errorf("err = %v, want ErrMetadataInsecureURL", err)
	}
}

// ===========================================================================
// provider_crewjam.go — ValidateResponse, SPMetadata, ParseIdPMetadata stubs
// ===========================================================================

func TestCrewjam_ValidateResponse_NotImplemented(t *testing.T) {
	prov := &CrewjamProvider{}
	_, err := prov.ValidateResponse(context.Background(), ValidateResponseInput{})
	if err == nil {
		t.Fatal("expected error from unimplemented ValidateResponse")
	}
}

func TestCrewjam_SPMetadata_NotImplemented(t *testing.T) {
	prov := &CrewjamProvider{}
	_, err := prov.SPMetadata(context.Background())
	if err == nil {
		t.Fatal("expected error from unimplemented SPMetadata")
	}
}

func TestCrewjam_ParseIdPMetadata_NotImplemented(t *testing.T) {
	prov := &CrewjamProvider{}
	_, err := prov.ParseIdPMetadata(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error from unimplemented ParseIdPMetadata")
	}
}

func TestCrewjam_ValidateLogoutMessage_UnsupportedBinding(t *testing.T) {
	prov := newTestProvider(t)
	_, err := prov.ValidateLogoutMessage(context.Background(), ValidateLogoutInput{
		RawMessage: base64.StdEncoding.EncodeToString([]byte("<msg/>")),
		Binding:    "urn:unsupported:binding",
	})
	if err == nil {
		t.Fatal("expected error for unsupported binding")
	}
}

func TestCrewjam_ValidateLogoutMessage_BadBase64_Redirect(t *testing.T) {
	prov := newTestProvider(t)
	_, err := prov.ValidateLogoutMessage(context.Background(), ValidateLogoutInput{
		RawMessage: "%%%invalid-base64",
		Binding:    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
	})
	if err == nil {
		t.Fatal("expected error for bad base64 in redirect binding")
	}
}

func TestCrewjam_ValidateLogoutMessage_BadBase64_Post(t *testing.T) {
	prov := newTestProvider(t)
	_, err := prov.ValidateLogoutMessage(context.Background(), ValidateLogoutInput{
		RawMessage: "%%%invalid-base64",
		Binding:    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	})
	if err == nil {
		t.Fatal("expected error for bad base64 in POST binding")
	}
}

func TestCrewjam_ValidateLogoutMessage_UnexpectedElement(t *testing.T) {
	prov := newTestProvider(t)
	encoded := base64.StdEncoding.EncodeToString([]byte(`<Unknown xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/>`))
	_, err := prov.ValidateLogoutMessage(context.Background(), ValidateLogoutInput{
		RawMessage: encoded,
		Binding:    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	})
	if err == nil {
		t.Fatal("expected error for unexpected root element")
	}
}

func TestCrewjam_ValidateLogoutMessage_MalformedXML(t *testing.T) {
	prov := newTestProvider(t)
	encoded := base64.StdEncoding.EncodeToString([]byte("not xml at all"))
	_, err := prov.ValidateLogoutMessage(context.Background(), ValidateLogoutInput{
		RawMessage: encoded,
		Binding:    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	})
	if err == nil {
		t.Fatal("expected error for malformed XML")
	}
}

func TestCrewjam_ValidateLogoutMessage_LogoutRequest_NoNameID(t *testing.T) {
	prov := newTestProvider(t)
	reqXML := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		ID="_req1" Version="2.0"/>`
	encoded := base64.StdEncoding.EncodeToString([]byte(reqXML))
	verified, err := prov.ValidateLogoutMessage(context.Background(), ValidateLogoutInput{
		RawMessage: encoded,
		Binding:    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified.NameID != "" {
		t.Errorf("NameID = %q, want empty", verified.NameID)
	}
	if verified.SessionIndex != "" {
		t.Errorf("SessionIndex = %q, want empty", verified.SessionIndex)
	}
}

func TestCrewjam_BuildLogoutResponse(t *testing.T) {
	prov := newTestProvider(t)
	resp, err := prov.BuildLogoutResponse(context.Background(), BuildLogoutResponseInput{
		IdP: IdPRecord{
			EntityID: "https://idp.example.com",
			SLOURL:   "https://idp.example.com/slo",
		},
		InResponseTo: "_req-001",
	})
	if err != nil {
		t.Fatalf("BuildLogoutResponse: %v", err)
	}
	if len(resp.PostBody) == 0 {
		t.Error("expected non-empty PostBody")
	}
}

// ===========================================================================
// handler.go — subjectFromToken edge cases
// ===========================================================================

func TestSubjectFromToken_InvalidBase64(t *testing.T) {
	// JWT with invalid base64 payload.
	s := subjectFromToken("header.%%%invalid.sig")
	if s != "" {
		t.Errorf("subjectFromToken = %q, want empty", s)
	}
}

func TestSubjectFromToken_InvalidJSON(t *testing.T) {
	// JWT with valid base64 but invalid JSON payload.
	payload := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	s := subjectFromToken("header." + payload + ".sig")
	if s != "" {
		t.Errorf("subjectFromToken = %q, want empty", s)
	}
}

func TestSubjectFromToken_TooFewParts(t *testing.T) {
	s := subjectFromToken("onlyonepart")
	if s != "" {
		t.Errorf("subjectFromToken = %q, want empty", s)
	}
}

// ===========================================================================
// audit.go — Emit error path (marshal failure)
// ===========================================================================

func TestLogEmitter_Emit(t *testing.T) {
	emitter := LogEmitter{}
	err := emitter.Emit(context.Background(), AuditRecord{
		Event:    "saml.assertion",
		Decision: "accept",
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
}

// ===========================================================================
// metadata.go — SPMetadataFromConfig edge cases
// ===========================================================================

func TestSPMetadataFromConfig_InvalidSigningCert(t *testing.T) {
	_, err := SPMetadataFromConfig(SPMetadataConfig{
		SigningCertPEM: []byte("not pem"),
	})
	if err == nil {
		t.Fatal("expected error for invalid signing cert PEM")
	}
}

func TestSPMetadataFromConfig_InvalidEncryptCert(t *testing.T) {
	sigPEM, _ := os.ReadFile("testdata/sp_signing.crt")
	_, err := SPMetadataFromConfig(SPMetadataConfig{
		SigningCertPEM: sigPEM,
		EncryptCertPEM: []byte("not pem"),
	})
	if err == nil {
		t.Fatal("expected error for invalid encryption cert PEM")
	}
}

func TestSPMetadataFromConfig_InvalidExtraCert(t *testing.T) {
	sigPEM, _ := os.ReadFile("testdata/sp_signing.crt")
	encPEM, _ := os.ReadFile("testdata/sp_encryption.crt")
	_, err := SPMetadataFromConfig(SPMetadataConfig{
		SigningCertPEM:       sigPEM,
		EncryptCertPEM:       encPEM,
		ExtraSigningCertPEMs: [][]byte{[]byte("not pem")},
	})
	if err == nil {
		t.Fatal("expected error for invalid extra signing cert PEM")
	}
}

// ===========================================================================
// metadata.go — ParseIdPMetadata edge cases
// ===========================================================================

func TestParseIdPMetadata_NoIDPSSODescriptor(t *testing.T) {
	raw := []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"/>`)
	_, err := ParseIdPMetadata(raw)
	if err == nil {
		t.Fatal("expected error for no IDPSSODescriptor")
	}
}

func TestParseIdPMetadata_DOCTYPE(t *testing.T) {
	raw := []byte(`<!DOCTYPE foo><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"/>`)
	_, err := ParseIdPMetadata(raw)
	if err == nil {
		t.Fatal("expected error for DOCTYPE")
	}
}

func TestParseIdPMetadata_EncryptionCertClassification(t *testing.T) {
	// Create a metadata doc with an encryption cert.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certB64 := base64.StdEncoding.EncodeToString(certDER)

	raw := []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
		xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
		entityID="https://idp.example.com">
		<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
			<KeyDescriptor use="signing">
				<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + certB64 + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
			</KeyDescriptor>
			<KeyDescriptor use="encryption">
				<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + certB64 + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
			</KeyDescriptor>
			<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
				Location="https://idp.example.com/sso"/>
		</IDPSSODescriptor>
	</EntityDescriptor>`)

	rec, err := ParseIdPMetadata(raw)
	if err != nil {
		t.Fatalf("ParseIdPMetadata: %v", err)
	}
	if len(rec.EncryptionCerts) != 1 {
		t.Errorf("expected 1 encryption cert, got %d", len(rec.EncryptionCerts))
	}
}

// ===========================================================================
// provider_crewjam.go — BuildAuthnRequest with ForceAuthn, default NameIDFormat
// ===========================================================================

func TestCrewjam_BuildAuthnRequest_ForceAuthn(t *testing.T) {
	prov := newTestProvider(t)
	in := testBuildInput()
	in.ForceAuthn = true

	result, err := prov.BuildAuthnRequest(context.Background(), in)
	if err != nil {
		t.Fatalf("BuildAuthnRequest: %v", err)
	}
	if result.RedirectURL == "" {
		t.Error("expected non-empty redirect URL")
	}

	xmlBytes := decodeSAMLRequestFromURL(t, result.RedirectURL)
	type authnReqFA struct {
		XMLName    xml.Name `xml:"AuthnRequest"`
		ForceAuthn string   `xml:"ForceAuthn,attr"`
	}
	var req authnReqFA
	if err := xml.Unmarshal(xmlBytes, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.ForceAuthn != "true" {
		t.Errorf("ForceAuthn = %q, want %q", req.ForceAuthn, "true")
	}
}

func TestCrewjam_BuildAuthnRequest_DefaultNameIDFormat(t *testing.T) {
	prov := newTestProvider(t)
	in := testBuildInput()
	in.NameIDFormat = "" // empty → should default to email

	result, err := prov.BuildAuthnRequest(context.Background(), in)
	if err != nil {
		t.Fatalf("BuildAuthnRequest: %v", err)
	}
	if result.RedirectURL == "" {
		t.Error("expected non-empty redirect URL")
	}
}

func TestCrewjam_BuildAuthnRequest_WithSigningCerts(t *testing.T) {
	prov := newTestProvider(t)
	in := testBuildInput()
	in.IdP.SigningCerts = [][]byte{prov.Cert.Raw}

	result, err := prov.BuildAuthnRequest(context.Background(), in)
	if err != nil {
		t.Fatalf("BuildAuthnRequest: %v", err)
	}
	if result.RedirectURL == "" {
		t.Error("expected non-empty redirect URL")
	}
}

func TestCrewjam_BuildLogoutRequest_DefaultNameIDFormat(t *testing.T) {
	prov := newTestProvider(t)
	in := testLogoutInput(nil)
	in.NameIDFormat = "" // empty → should default to email

	result, err := prov.BuildLogoutRequest(context.Background(), in)
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	if result.RedirectURL == "" {
		t.Error("expected non-empty redirect URL")
	}
}

func TestCrewjam_BuildLogoutRequest_NoOverrides(t *testing.T) {
	prov := newTestProvider(t)
	in := testLogoutInput(nil)
	in.RequestID = ""
	in.IssueInstant = time.Time{}
	in.SessionIndex = ""

	result, err := prov.BuildLogoutRequest(context.Background(), in)
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	if result.RedirectURL == "" {
		t.Error("expected non-empty redirect URL")
	}
}

// ===========================================================================
// normalizeDomain
// ===========================================================================

func TestNormalizeDomain_CaseInsensitive(t *testing.T) {
	d := normalizeDomain("USER@EXAMPLE.COM")
	if d != "example.com" {
		t.Errorf("normalizeDomain = %q, want %q", d, "example.com")
	}
}

// ===========================================================================
// Login handler — with RelayState
// ===========================================================================

func TestLogin_WithRelayState(t *testing.T) {
	store := &loginMockStore{
		getIdPFn: func(_ context.Context, _ string) (IdPRecord, error) {
			return defaultIdP(), nil
		},
	}
	prov := &loginMockProvider{}
	h := newLoginHandler(store, prov)

	r := chi.NewRouter()
	r.Get("/saml/login/{tid}", h.Login)

	req := httptest.NewRequest(http.MethodGet, "/saml/login/"+testTID+"?RelayState=/dashboard", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
	}
	if len(store.putRequests) == 0 {
		t.Fatal("no PutRequest calls")
	}
	if store.putRequests[0].RelayState != "/dashboard" {
		t.Errorf("RelayState = %q, want %q", store.putRequests[0].RelayState, "/dashboard")
	}
}

// ===========================================================================
// parseXML — malformed XML
// ===========================================================================

func TestParseXML_MalformedXML(t *testing.T) {
	_, err := parseXML([]byte("not xml at all <><>"))
	if err == nil {
		t.Fatal("expected error for malformed XML")
	}
}

// ===========================================================================
// session_auth.go — Issue with token issuer error
// ===========================================================================

func TestSessionBridge_IssuerError(t *testing.T) {
	repo := &fakeRepo{
		user: domain.User{Id: "u1", Email: "alice@example.com"},
	}
	issuer := &fakeIssuer{err: errors.New("signing failed")}
	bridge := NewSessionBridge(repo, issuer)

	_, err := bridge.Issue(context.Background(), IssueInput{
		TenantID:        "t-1",
		ExternalSubject: "ext-1",
		Email:           "alice@example.com",
		AMR:             []string{"saml"},
	})
	if err == nil {
		t.Fatal("expected error from issuer failure")
	}
}

func TestSessionBridge_EmptyTID(t *testing.T) {
	repo := &fakeRepo{
		user: domain.User{Id: "u1", Email: "alice@example.com"},
	}
	issuer := &fakeIssuer{token: "tok-empty-tid"}
	bridge := NewSessionBridge(repo, issuer)

	tok, err := bridge.Issue(context.Background(), IssueInput{
		TenantID:        "",
		ExternalSubject: "ext-1",
		Email:           "alice@example.com",
		AMR:             []string{"saml"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "tok-empty-tid" {
		t.Errorf("token = %q, want %q", tok, "tok-empty-tid")
	}
}
