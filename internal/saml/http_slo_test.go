package saml_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
)

var testSLOStateKey = []byte("test-slo-state-key-at-least-32-bytes")

// ---------------------------------------------------------------------------
// Test helpers — mock provider and store
// ---------------------------------------------------------------------------

// mockSLOProvider implements saml.Provider for SLO handler tests.
type mockSLOProvider struct {
	validateLogoutFunc      func(context.Context, saml.ValidateLogoutInput) (*saml.VerifiedLogout, error)
	buildLogoutResponseFunc func(context.Context, saml.BuildLogoutResponseInput) (*saml.LogoutResponseResult, error)
}

func (m *mockSLOProvider) BuildAuthnRequest(_ context.Context, _ saml.BuildAuthnRequestInput) (*saml.AuthnRequest, error) {
	return nil, nil
}

func (m *mockSLOProvider) ValidateResponse(_ context.Context, _ saml.ValidateResponseInput) (*saml.VerifiedAssertion, error) {
	return nil, nil
}

func (m *mockSLOProvider) BuildLogoutRequest(_ context.Context, _ saml.BuildLogoutRequestInput) (*saml.LogoutRequest, error) {
	return nil, nil
}

func (m *mockSLOProvider) BuildLogoutResponse(ctx context.Context, in saml.BuildLogoutResponseInput) (*saml.LogoutResponseResult, error) {
	if m.buildLogoutResponseFunc != nil {
		return m.buildLogoutResponseFunc(ctx, in)
	}
	return &saml.LogoutResponseResult{PostBody: []byte("<html>ok</html>")}, nil
}

func (m *mockSLOProvider) ValidateLogoutMessage(ctx context.Context, in saml.ValidateLogoutInput) (*saml.VerifiedLogout, error) {
	if m.validateLogoutFunc != nil {
		return m.validateLogoutFunc(ctx, in)
	}
	return nil, nil
}

func (m *mockSLOProvider) SPMetadata(_ context.Context) ([]byte, error) {
	return nil, nil
}

func (m *mockSLOProvider) ParseIdPMetadata(_ context.Context, _ []byte) (*saml.IdPRecord, error) {
	return nil, nil
}

// mockSLOStore implements saml.Store for SLO handler tests.
type mockSLOStore struct {
	indexes map[string]saml.IndexRecord
	idps    map[string]saml.IdPRecord
	deleted map[string]bool
}

func newMockSLOStore() *mockSLOStore {
	return &mockSLOStore{
		indexes: make(map[string]saml.IndexRecord),
		idps:    make(map[string]saml.IdPRecord),
		deleted: make(map[string]bool),
	}
}

func (s *mockSLOStore) PutRequest(_ context.Context, _ saml.RequestRecord) error { return nil }
func (s *mockSLOStore) ConsumeRequest(_ context.Context, _ string) (saml.RequestRecord, bool, error) {
	return saml.RequestRecord{}, false, nil
}
func (s *mockSLOStore) PutIdP(_ context.Context, _ saml.IdPRecord) error { return nil }
func (s *mockSLOStore) CompareAndSwapIdP(_ context.Context, _, _ saml.IdPRecord) (bool, error) {
	return true, nil
}
func (s *mockSLOStore) ListIdPs(_ context.Context) ([]saml.IdPRecord, error) {
	records := make([]saml.IdPRecord, 0, len(s.idps))
	for _, record := range s.idps {
		records = append(records, record)
	}
	return records, nil
}
func (s *mockSLOStore) DeleteIdP(_ context.Context, _ string) error { return nil }
func (s *mockSLOStore) PutIndex(_ context.Context, _ string, _ saml.IndexRecord) error {
	return nil
}
func (s *mockSLOStore) MarkSeen(_ context.Context, _ string, _ time.Duration) (bool, error) {
	return false, nil
}
func (s *mockSLOStore) PutDomain(_ context.Context, _, _ string) error        { return nil }
func (s *mockSLOStore) GetDomain(_ context.Context, _ string) (string, error) { return "", nil }
func (s *mockSLOStore) DeleteDomain(_ context.Context, _ string) error        { return nil }

func (s *mockSLOStore) GetIndex(_ context.Context, nameID string) (saml.IndexRecord, error) {
	if rec, ok := s.indexes[nameID]; ok {
		return rec, nil
	}
	return saml.IndexRecord{}, saml.ErrIdPNotFound
}

func (s *mockSLOStore) DeleteIndex(_ context.Context, nameID string) error {
	s.deleted[nameID] = true
	delete(s.indexes, nameID)
	return nil
}

func (s *mockSLOStore) PutSessionIndexes(_ context.Context, subjectKey, nameIDKey string, rec saml.IndexRecord) error {
	s.indexes[subjectKey] = rec
	s.indexes[nameIDKey] = rec
	return nil
}

func (s *mockSLOStore) DeleteSessionIndexes(_ context.Context, subjectKey, nameIDKey string) error {
	s.deleted[subjectKey] = true
	s.deleted[nameIDKey] = true
	delete(s.indexes, subjectKey)
	delete(s.indexes, nameIDKey)
	return nil
}

func (s *mockSLOStore) GetIdP(_ context.Context, tid string) (saml.IdPRecord, error) {
	if rec, ok := s.idps[tid]; ok {
		return rec, nil
	}
	return saml.IdPRecord{}, saml.ErrIdPNotFound
}

func seedSLOSession(store *mockSLOStore, record saml.IndexRecord) {
	store.indexes[saml.SessionSubjectIndexKey(record.TenantID, record.Subject)] = record
	store.indexes[saml.SessionNameIDIndexKey(record.TenantID, record.NameID)] = record
}

type mockSLOAuthority struct {
	revoked []string
	err     error
}

func (a *mockSLOAuthority) Validate(_ context.Context, _ string) (saml.SessionIdentity, error) {
	return saml.SessionIdentity{}, saml.ErrSessionAuthority
}

func (a *mockSLOAuthority) Revoke(_ context.Context, _ string, email string) error {
	a.revoked = append(a.revoked, email)
	return a.err
}

// ---------------------------------------------------------------------------
// Helper to build a handler with test dependencies.
// ---------------------------------------------------------------------------

func newTestSLOHandler(prov saml.Provider, store saml.Store) *saml.Handler {
	reg := prometheus.NewRegistry()
	m := saml.NewMetrics(reg)
	return saml.NewHandler(saml.Deps{
		Provider: prov,
		Store:    store,
		Clock:    saml.NewFakeClock(),
		Metrics:  m,
		Cfg: config.SAMLConfig{ACS: config.ACSConfig{
			CookieName:     "tikti_idt",
			CookieHTTPOnly: true,
		}},
		Authority:   &mockSLOAuthority{},
		SLOStateKey: testSLOStateKey,
	})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestSLO_GET_DeletesSession verifies that a valid SAMLResponse via GET
// removes the SAML session index and clears the session cookie.
func TestSLO_GET_DeletesSession(t *testing.T) {
	store := newMockSLOStore()
	record := saml.IndexRecord{
		TenantID:     "t-001",
		Subject:      "sub-001",
		NameID:       "user@example.com",
		Email:        "user@example.com",
		SessionIndex: "idx-001",
	}
	seedSLOSession(store, record)
	store.idps["t-001"] = saml.IdPRecord{TenantID: "t-001", EntityID: "https://idp.example.com"}

	prov := &mockSLOProvider{
		validateLogoutFunc: func(_ context.Context, _ saml.ValidateLogoutInput) (*saml.VerifiedLogout, error) {
			return &saml.VerifiedLogout{
				IsResponse: true,
				Status:     "urn:oasis:names:tc:SAML:2.0:status:Success",
			}, nil
		},
	}

	h := newTestSLOHandler(prov, store)

	// Build the GET request with SAMLResponse query param and SLO cookie.
	respXML := `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		ID="resp-001" Version="2.0"
		Destination="https://auth.example.com/saml/slo"
		InResponseTo="_req-001">
		<samlp:Status>
			<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
		</samlp:Status>
	</samlp:LogoutResponse>`
	encoded := base64.StdEncoding.EncodeToString([]byte(respXML))

	req := httptest.NewRequest(http.MethodGet,
		"/saml/slo?SAMLResponse="+url.QueryEscape(encoded), nil)
	state := saml.EncodeSLOState("t-001", "sub-001", "_req-001", testSLOStateKey)
	req.AddCookie(&http.Cookie{Name: "tikti_saml_slo", Value: state})
	rr := httptest.NewRecorder()

	h.SLO(rr, req)

	// Assert: redirect to "/"
	if rr.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusFound)
	}
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Referrer-Policy") != "no-referrer" || rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("GET SLO privacy headers = %v", rr.Header())
	}
	loc := rr.Header().Get("Location")
	if loc != "/" {
		t.Errorf("Location = %q, want %q", loc, "/")
	}

	// Assert: saml:idx removed
	if !store.deleted[saml.SessionSubjectIndexKey("t-001", "sub-001")] ||
		!store.deleted[saml.SessionNameIDIndexKey("t-001", "user@example.com")] {
		t.Error("expected both tenant-scoped SAML indexes to be deleted")
	}

	// Assert: SLO cookie cleared
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "tikti_saml_slo" && c.MaxAge < 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected tikti_saml_slo cookie to be cleared")
	}
}

// TestSLO_POST_Acknowledges verifies that an IdP-initiated LogoutRequest
// via POST produces a signed LogoutResponse HTML form.
func TestSLO_POST_Acknowledges(t *testing.T) {
	store := newMockSLOStore()
	record := saml.IndexRecord{
		TenantID:     "t-001",
		Subject:      "sub-001",
		NameID:       "user@example.com",
		Email:        "user@example.com",
		SessionIndex: "idx-001",
	}
	seedSLOSession(store, record)
	store.idps["t-001"] = saml.IdPRecord{
		TenantID: "t-001",
		EntityID: "https://idp.example.com",
		SLOURL:   "https://idp.example.com/slo",
	}

	var capturedBuildInput saml.BuildLogoutResponseInput
	prov := &mockSLOProvider{
		validateLogoutFunc: func(_ context.Context, _ saml.ValidateLogoutInput) (*saml.VerifiedLogout, error) {
			return &saml.VerifiedLogout{
				MessageID:    "_idp-req-001",
				IsResponse:   false,
				NameID:       "user@example.com",
				SessionIndex: "idx-001",
			}, nil
		},
		buildLogoutResponseFunc: func(_ context.Context, in saml.BuildLogoutResponseInput) (*saml.LogoutResponseResult, error) {
			capturedBuildInput = in
			return &saml.LogoutResponseResult{
				PostBody: []byte(`<form method="post" action="https://idp.example.com/slo">` +
					`<input type="hidden" name="SAMLResponse" value="signed-resp" />` +
					`</form><script>document.getElementById('SAMLResponseForm').submit();</script>`),
			}, nil
		},
	}

	h := newTestSLOHandler(prov, store)

	// Build a LogoutRequest XML and base64-encode it for POST.
	reqXML := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
		ID="_idp-req-001" Version="2.0"
		Destination="https://auth.example.com/saml/slo">
		<saml:Issuer>https://idp.example.com</saml:Issuer>
		<saml:NameID>user@example.com</saml:NameID>
		<samlp:SessionIndex>idx-001</samlp:SessionIndex>
	</samlp:LogoutRequest>`
	encodedReq := base64.StdEncoding.EncodeToString([]byte(reqXML))

	form := url.Values{"SAMLRequest": {encodedReq}}
	req := httptest.NewRequest(http.MethodPost, "/saml/slo",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.SLO(rr, req)

	// Assert: 200 with HTML form containing SAMLResponse
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "SAMLResponse") {
		t.Error("response body does not contain SAMLResponse")
	}
	if strings.Contains(body, "<script>") || !strings.Contains(body, `<script nonce="`) || !strings.Contains(rr.Header().Get("Content-Security-Policy"), "script-src 'nonce-") {
		t.Fatalf("POST SLO script was not nonce-bound: csp=%q body=%s", rr.Header().Get("Content-Security-Policy"), body)
	}
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Referrer-Policy") != "no-referrer" ||
		rr.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(rr.Header().Get("Content-Security-Policy"), "form-action https://idp.example.com") {
		t.Fatalf("POST SLO browser security headers = %v", rr.Header())
	}

	// Assert: index deleted
	if !store.deleted[saml.SessionSubjectIndexKey("t-001", "sub-001")] ||
		!store.deleted[saml.SessionNameIDIndexKey("t-001", "user@example.com")] {
		t.Error("expected both tenant-scoped SAML indexes to be deleted")
	}

	// Assert: BuildLogoutResponse was called with correct IdP
	if capturedBuildInput.IdP.TenantID != "t-001" {
		t.Errorf("BuildLogoutResponse IdP.TenantID = %q, want %q",
			capturedBuildInput.IdP.TenantID, "t-001")
	}
	if capturedBuildInput.InResponseTo != "_idp-req-001" {
		t.Errorf("BuildLogoutResponse InResponseTo = %q, want %q",
			capturedBuildInput.InResponseTo, "_idp-req-001")
	}
}

// TestSLO_POST_SignatureInvalid_Reject verifies that when validation fails,
// the session index is NOT deleted.
func TestSLO_POST_SignatureInvalid_Reject(t *testing.T) {
	store := newMockSLOStore()
	record := saml.IndexRecord{
		TenantID:     "t-001",
		Subject:      "sub-001",
		NameID:       "user@example.com",
		Email:        "user@example.com",
		SessionIndex: "idx-001",
	}
	seedSLOSession(store, record)
	store.idps["t-001"] = saml.IdPRecord{
		TenantID: "t-001", EntityID: "https://idp.example.com",
	}

	prov := &mockSLOProvider{
		validateLogoutFunc: func(_ context.Context, _ saml.ValidateLogoutInput) (*saml.VerifiedLogout, error) {
			return nil, saml.ErrSignatureInvalid
		},
	}

	h := newTestSLOHandler(prov, store)

	reqXML := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_bad-sig" Version="2.0">
		<saml:Issuer>https://idp.example.com</saml:Issuer>
		<saml:NameID>user@example.com</saml:NameID>
		<samlp:SessionIndex>idx-001</samlp:SessionIndex>
	</samlp:LogoutRequest>`
	encodedReq := base64.StdEncoding.EncodeToString([]byte(reqXML))

	form := url.Values{"SAMLRequest": {encodedReq}}
	req := httptest.NewRequest(http.MethodPost, "/saml/slo",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.SLO(rr, req)

	// Assert: rejected with 403
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	// Assert: no session deletion
	if store.deleted[saml.SessionNameIDIndexKey("t-001", "user@example.com")] {
		t.Error("session index should NOT have been deleted on invalid signature")
	}

	// Assert: index still present
	if _, ok := store.indexes[saml.SessionNameIDIndexKey("t-001", "user@example.com")]; !ok {
		t.Error("session index should still be present after rejection")
	}
}

// TestSLO_GET_WithoutResponse_Reject verifies that a GET without a
// SAMLResponse query parameter is rejected.
func TestSLO_GET_WithoutResponse_Reject(t *testing.T) {
	store := newMockSLOStore()
	prov := &mockSLOProvider{}

	h := newTestSLOHandler(prov, store)

	req := httptest.NewRequest(http.MethodGet, "/saml/slo", nil)
	rr := httptest.NewRecorder()

	h.SLO(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}
