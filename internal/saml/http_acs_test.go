package saml

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// mockACSStore is a configurable mock of the Store interface for ACS tests.
type mockACSStore struct {
	stubStore // embed for unimplemented methods

	consumeRec RequestRecord
	consumeOK  bool
	consumeErr error
	consumeID  string

	getIdPRec IdPRecord
	getIdPErr error

	markSeenFresh bool
	markSeenErr   error

	putIndexErr error
}

func (m *mockACSStore) ConsumeRequest(_ context.Context, id string) (RequestRecord, bool, error) {
	m.consumeID = id
	return m.consumeRec, m.consumeOK, m.consumeErr
}

func (m *mockACSStore) GetIdP(_ context.Context, _ string) (IdPRecord, error) {
	return m.getIdPRec, m.getIdPErr
}

func (m *mockACSStore) MarkSeen(_ context.Context, _ string, _ time.Duration) (bool, error) {
	return m.markSeenFresh, m.markSeenErr
}

func (m *mockACSStore) PutIndex(_ context.Context, _ string, _ IndexRecord) error {
	return m.putIndexErr
}

// mockACSProvider is a mock Provider for ACS handler tests.
type mockACSProvider struct {
	stubProvider
	va  *VerifiedAssertion
	err error
}

func (m *mockACSProvider) ValidateResponse(_ context.Context, _ ValidateResponseInput) (*VerifiedAssertion, error) {
	return m.va, m.err
}

// mockACSBridge is a mock SessionBridge for ACS handler tests.
type mockACSBridge struct {
	token string
	err   error
}

func (m *mockACSBridge) Issue(_ context.Context, _ IssueInput) (string, error) {
	return m.token, m.err
}

// mockACSEmitter captures audit records for verification.
type mockACSEmitter struct {
	records []AuditRecord
}

func (m *mockACSEmitter) Emit(_ context.Context, rec AuditRecord) error {
	m.records = append(m.records, rec)
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// goldenSAMLConfig returns a minimal SAMLConfig for ACS tests.
func goldenSAMLConfig() config.SAMLConfig {
	return config.SAMLConfig{
		Enabled: true,
		SP: config.SPConfig{
			EntityID:       "https://sp.example.com/metadata",
			ACSURL:         "https://sp.example.com/saml/acs",
			ClockSkew:      120 * time.Second,
			AllowedSigAlgs: []string{"rsa-sha256"},
		},
		ACS: config.ACSConfig{
			DeliveryMode:   "cookie",
			CookieName:     "tikti_idt",
			CookieSameSite: "Lax",
			CookieSecure:   true,
			CookieHTTPOnly: true,
			SessionTTL:     3600,
			PostLoginURL:   "/dashboard",
		},
	}
}

// goldenIDToken returns a minimal HS256 JWT token string for tests.
// The payload contains {"sub":"user-001","tid":"t-001"}.
// The signature is intentionally invalid — this token is only used in tests
// to verify cookie setting and subject extraction, never for real auth.
func goldenIDToken() string {
	// header: {"alg":"HS256","typ":"JWT"}
	// payload: {"sub":"user-001","tid":"t-001","iat":1767225600,"exp":1767229200}
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiJ1c2VyLTAwMSIsInRpZCI6InQtMDAxIiwiaWF0IjoxNzY3MjI1NjAwLCJleHAiOjE3NjcyMjkyMDB9." +
		"fakesignature"
}

// newACSRequest builds an HTTP POST request to /saml/acs with the given
// SAMLResponse, RelayState, and state cookie.
func newACSRequest(samlResponse, relayState, stateCookie string) *http.Request {
	return newACSRequestWithRetry(samlResponse, relayState, stateCookie, false)
}

func newACSRequestWithRetry(
	samlResponse, relayState, stateCookie string,
	retry bool,
) *http.Request {
	form := url.Values{}
	form.Set("SAMLResponse", samlResponse)
	form.Set("RelayState", relayState)
	if retry {
		form.Set(stateCookieRetryField, "1")
	}

	r := httptest.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if stateCookie != "" {
		r.AddCookie(&http.Cookie{Name: stateCookieName, Value: stateCookie})
	}
	return r
}

// buildHandler creates a Handler with the given mocks for ACS tests. It
// returns the handler, the recorder, and the audit emitter for inspection.
func buildHandler(
	store *mockACSStore,
	prov *mockACSProvider,
	bridge *mockACSBridge,
	emitter *mockACSEmitter,
) *Handler {
	reg := prometheus.NewRegistry()
	return NewHandler(Deps{
		Provider: prov,
		Store:    store,
		Bridge:   bridge,
		Clock:    NewFakeClock(),
		Cfg:      goldenSAMLConfig(),
		Metrics:  NewMetrics(reg),
		Audit:    emitter,
	})
}

// happyStore returns a mockACSStore configured for the accept path.
func happyStore() *mockACSStore {
	return &mockACSStore{
		consumeRec: RequestRecord{
			ID:         "req-001",
			TenantID:   "t-001",
			RelayState: "/app",
			ACSURL:     "https://sp.example.com/saml/acs",
		},
		consumeOK:     true,
		getIdPRec:     goldenIdP(),
		markSeenFresh: true,
	}
}

// happyProvider returns a mockACSProvider configured for the accept path.
func happyProvider() *mockACSProvider {
	return &mockACSProvider{va: goldenAssertion()}
}

// happyBridge returns a mockACSBridge configured for the accept path.
func happyBridge() *mockACSBridge {
	return &mockACSBridge{token: goldenIDToken()}
}

// ---------------------------------------------------------------------------
// Accept-path tests
// ---------------------------------------------------------------------------

func TestACS_Accept_SetsCookie(t *testing.T) {
	emitter := &mockACSEmitter{}
	h := buildHandler(happyStore(), happyProvider(), happyBridge(), emitter)

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == "tikti_idt" {
			found = true
			if c.Value != goldenIDToken() {
				t.Errorf("cookie value = %q, want %q", c.Value, goldenIDToken())
			}
			if !c.HttpOnly {
				t.Error("idToken cookie should be HttpOnly")
			}
			if !c.Secure {
				t.Error("idToken cookie should be Secure")
			}
		}
	}
	if !found {
		t.Fatal("idToken cookie not found in response")
	}
}

func TestACS_Accept_302ToRelayState(t *testing.T) {
	emitter := &mockACSEmitter{}
	h := buildHandler(happyStore(), happyProvider(), happyBridge(), emitter)

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	loc := resp.Header.Get("Location")
	if loc != "/app" {
		t.Errorf("Location = %q, want %q", loc, "/app")
	}
}

func TestACS_Accept_EmptyRelayState_RedirectsToPostLoginURL(t *testing.T) {
	store := happyStore()
	store.consumeRec.RelayState = ""

	emitter := &mockACSEmitter{}
	h := buildHandler(store, happyProvider(), happyBridge(), emitter)

	r := newACSRequest(goldenResponseBase64(), "", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	loc := resp.Header.Get("Location")
	if loc != "/dashboard" {
		t.Errorf("Location = %q, want %q (PostLoginURL)", loc, "/dashboard")
	}
}

func TestACS_Accept_ClearsStateCookie(t *testing.T) {
	emitter := &mockACSEmitter{}
	h := buildHandler(happyStore(), happyProvider(), happyBridge(), emitter)

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	for _, c := range resp.Cookies() {
		if c.Name == stateCookieName {
			if c.MaxAge != -1 {
				t.Errorf("state cookie MaxAge = %d, want -1 (deleted)", c.MaxAge)
			}
			return
		}
	}
	t.Fatal("state cookie deletion not found in response")
}

func TestACS_LegacyStateCookieCannotShadowHostCookie(t *testing.T) {
	store := happyStore()
	h := buildHandler(store, happyProvider(), happyBridge(), &mockACSEmitter{})

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	r.AddCookie(&http.Cookie{Name: "tikti_saml_state", Value: "stale-request"})
	w := httptest.NewRecorder()

	h.ACS(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	if got := w.Header().Get("Location"); got != "/app" {
		t.Errorf("Location = %q, want /app", got)
	}
	if store.consumeID != "req-001" {
		t.Errorf("consumed request ID = %q, want host-bound request", store.consumeID)
	}
}

func TestACS_LegacyStateCookieAloneUsesMissingCookieRecovery(t *testing.T) {
	store := happyStore()
	h := buildHandler(store, happyProvider(), happyBridge(), &mockACSEmitter{})

	r := newACSRequest(goldenResponseBase64(), "/app", "")
	r.AddCookie(&http.Cookie{Name: "tikti_saml_state", Value: "stale-request"})
	w := httptest.NewRecorder()

	h.ACS(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if store.consumeID != "" {
		t.Errorf("legacy cookie consumed request ID %q", store.consumeID)
	}
}

func TestACS_Accept_AuditRecord(t *testing.T) {
	emitter := &mockACSEmitter{}
	h := buildHandler(happyStore(), happyProvider(), happyBridge(), emitter)

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	if len(emitter.records) == 0 {
		t.Fatal("no audit records emitted")
	}
	rec := emitter.records[len(emitter.records)-1]
	if rec.Decision != "accept" {
		t.Errorf("audit decision = %q, want %q", rec.Decision, "accept")
	}
	if rec.TenantID != "t-001" {
		t.Errorf("audit TenantID = %q, want %q", rec.TenantID, "t-001")
	}
}

// ---------------------------------------------------------------------------
// Reject-path tests
// ---------------------------------------------------------------------------

func TestACS_MissingState_RepostsOnce(t *testing.T) {
	emitter := &mockACSEmitter{}
	h := buildHandler(happyStore(), happyProvider(), happyBridge(), emitter)

	// No state cookie attached.
	r := newACSRequest(goldenResponseBase64(), "/app?next=<dashboard>", "")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
	if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self'") ||
		!strings.Contains(csp, "frame-ancestors 'none'") ||
		!strings.Contains(csp, "script-src 'nonce-") {
		t.Errorf("unexpected Content-Security-Policy: %q", csp)
	}
	body := w.Body.String()
	if !strings.Contains(body, `name="`+stateCookieRetryField+`" value="1"`) {
		t.Errorf("repost marker missing from body: %s", body)
	}
	if strings.Contains(body, "<dashboard>") ||
		!strings.Contains(body, "&lt;dashboard&gt;") {
		t.Errorf("RelayState was not HTML escaped: %s", body)
	}
	if len(emitter.records) != 0 {
		t.Fatalf("repost must not emit a final audit decision, got %d records", len(emitter.records))
	}
}

func TestACS_MissingStateAfterRepost_Rejects(t *testing.T) {
	emitter := &mockACSEmitter{}
	h := buildHandler(happyStore(), happyProvider(), happyBridge(), emitter)

	r := newACSRequestWithRetry(goldenResponseBase64(), "/app", "", true)
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	wantStatus := bucketToStatus(ReasonRequestNotFound.Bucket())
	if resp.StatusCode != wantStatus {
		t.Errorf("status = %d, want %d", resp.StatusCode, wantStatus)
	}
	if strings.Contains(w.Body.String(), stateCookieRetryField) {
		t.Fatal("second missing-cookie request must not render another repost")
	}
	if len(emitter.records) != 1 {
		t.Fatalf("expected one rejection audit record, got %d", len(emitter.records))
	}
	if emitter.records[0].Reason != string(ReasonRequestNotFound) {
		t.Errorf("audit reason = %q, want %q", emitter.records[0].Reason, ReasonRequestNotFound)
	}
}

func TestACS_RepostWithState_Accepts(t *testing.T) {
	emitter := &mockACSEmitter{}
	h := buildHandler(happyStore(), happyProvider(), happyBridge(), emitter)

	r := newACSRequestWithRetry(goldenResponseBase64(), "/app", "req-001", true)
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if got := resp.Header.Get("Location"); got != "/app" {
		t.Errorf("Location = %q, want /app", got)
	}
}

func TestACS_MissingStateRepostEligibility(t *testing.T) {
	tests := []struct {
		name         string
		samlResponse string
		relayState   string
		wantStatus   int
	}{
		{
			name:         "valid response and relay",
			samlResponse: goldenResponseBase64(),
			relayState:   "/app",
			wantStatus:   http.StatusOK,
		},
		{
			name:         "empty response",
			samlResponse: "",
			relayState:   "/app",
			wantStatus:   bucketToStatus(ReasonRequestNotFound.Bucket()),
		},
		{
			name:         "oversized response",
			samlResponse: strings.Repeat("A", maxRepostResponseSize+1),
			relayState:   "/app",
			wantStatus:   bucketToStatus(ReasonRequestNotFound.Bucket()),
		},
		{
			name:         "oversized relay",
			samlResponse: goldenResponseBase64(),
			relayState:   strings.Repeat("A", maxRepostRelaySize+1),
			wantStatus:   bucketToStatus(ReasonRequestNotFound.Bucket()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := buildHandler(happyStore(), happyProvider(), happyBridge(), &mockACSEmitter{})
			r := newACSRequest(tt.samlResponse, tt.relayState, "")
			w := httptest.NewRecorder()

			h.ACS(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestACS_ConsumeRequestFails_Reject(t *testing.T) {
	store := happyStore()
	store.consumeOK = false

	emitter := &mockACSEmitter{}
	h := buildHandler(store, happyProvider(), happyBridge(), emitter)

	r := newACSRequest(goldenResponseBase64(), "/app", "unknown-state")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	wantStatus := bucketToStatus(ReasonRequestNotFound.Bucket())
	if resp.StatusCode != wantStatus {
		t.Errorf("status = %d, want %d", resp.StatusCode, wantStatus)
	}
}

func TestACS_ConsumeRequestError_Reject(t *testing.T) {
	store := happyStore()
	store.consumeErr = errors.New("redis down")

	emitter := &mockACSEmitter{}
	h := buildHandler(store, happyProvider(), happyBridge(), emitter)

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	wantStatus := bucketToStatus(ReasonRequestNotFound.Bucket())
	if resp.StatusCode != wantStatus {
		t.Errorf("status = %d, want %d", resp.StatusCode, wantStatus)
	}
}

func TestACS_ReplayedAssertion_Reject(t *testing.T) {
	store := happyStore()
	store.markSeenFresh = false

	emitter := &mockACSEmitter{}
	h := buildHandler(store, happyProvider(), happyBridge(), emitter)

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	wantStatus := bucketToStatus(ReasonRequestReplay.Bucket())
	if resp.StatusCode != wantStatus {
		t.Errorf("status = %d, want %d (replay)", resp.StatusCode, wantStatus)
	}

	// Verify audit.
	found := false
	for _, rec := range emitter.records {
		if rec.Reason == string(ReasonRequestReplay) {
			found = true
		}
	}
	if !found {
		t.Error("no audit record with replay reason")
	}
}

func TestACS_MarkSeenError_Reject(t *testing.T) {
	store := happyStore()
	store.markSeenErr = errors.New("redis timeout")

	emitter := &mockACSEmitter{}
	h := buildHandler(store, happyProvider(), happyBridge(), emitter)

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	wantStatus := bucketToStatus(ReasonInternal.Bucket())
	if resp.StatusCode != wantStatus {
		t.Errorf("status = %d, want %d (MarkSeen error)", resp.StatusCode, wantStatus)
	}
}

func TestACS_GetIdPFails_Reject(t *testing.T) {
	store := happyStore()
	store.getIdPErr = ErrIdPNotFound

	emitter := &mockACSEmitter{}
	h := buildHandler(store, happyProvider(), happyBridge(), emitter)

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	wantStatus := bucketToStatus(ReasonTIDUnknown.Bucket())
	if resp.StatusCode != wantStatus {
		t.Errorf("status = %d, want %d (TID unknown)", resp.StatusCode, wantStatus)
	}
}

func TestACS_BridgeIssueFails_Reject(t *testing.T) {
	bridge := &mockACSBridge{err: errors.New("bridge failure")}

	emitter := &mockACSEmitter{}
	h := buildHandler(happyStore(), happyProvider(), bridge, emitter)

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	wantStatus := bucketToStatus(ReasonInternal.Bucket())
	if resp.StatusCode != wantStatus {
		t.Errorf("status = %d, want %d (bridge error)", resp.StatusCode, wantStatus)
	}
}

// ---------------------------------------------------------------------------
// Validation reject reasons — covers every ACS-reachable reason per HLD §19
// ---------------------------------------------------------------------------

func TestACS_Reject_ValidationReasons(t *testing.T) {
	// ACS-reachable validation rejection reasons. These are the reasons
	// that the validateResponse function can return, tested at the HTTP
	// handler level.
	cases := []struct {
		name       string
		provErr    error
		wantReason Reason
	}{
		{"DestinationMismatch", ErrDestinationMismatch, ReasonDestinationMismatch},
		{"IssuerMismatch", ErrIssuerMismatch, ReasonIssuerMismatch},
		{"StatusNotSuccess", ErrStatusNotSuccess, ReasonStatusNotSuccess},
		{"AudienceMismatch", ErrAudienceMismatch, ReasonAudienceMismatch},
		{"SignatureInvalid", ErrSignatureInvalid, ReasonSignatureInvalid},
		{"DecryptFailed", ErrDecryptFailed, ReasonDecryptFailed},
		{"AssertionSignatureInvalid", ErrAssertionSignatureInvalid, ReasonAssertionSignatureInvalid},
		{"ClockSkew", ErrClockSkew, ReasonClockSkew},
		{"SubjectConfirmationMismatch", ErrSubjectConfirmation, ReasonSubjectConfirmationMismatch},
		{"SignatureWrapping", ErrSignatureWrapping, ReasonSignatureWrapping},
		{"XXE", ErrXXE, ReasonXXE},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prov := &mockACSProvider{err: tc.provErr}
			emitter := &mockACSEmitter{}
			h := buildHandler(happyStore(), prov, happyBridge(), emitter)

			r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
			w := httptest.NewRecorder()

			h.ACS(w, r)

			resp := w.Result()
			defer resp.Body.Close()

			wantStatus := bucketToStatus(tc.wantReason.Bucket())
			if resp.StatusCode != wantStatus {
				t.Errorf("status = %d, want %d for reason %q",
					resp.StatusCode, wantStatus, tc.wantReason)
			}

			// Verify audit record contains the correct reason.
			found := false
			for _, rec := range emitter.records {
				if rec.Reason == string(tc.wantReason) {
					found = true
				}
			}
			if !found {
				t.Errorf("no audit record with reason %q", tc.wantReason)
			}
		})
	}
}

func TestACS_Reject_MissingAttribute(t *testing.T) {
	a := goldenAssertion()
	a.NameID = ""
	prov := &mockACSProvider{va: a}

	emitter := &mockACSEmitter{}
	h := buildHandler(happyStore(), prov, happyBridge(), emitter)

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	wantStatus := bucketToStatus(ReasonMissingAttribute.Bucket())
	if resp.StatusCode != wantStatus {
		t.Errorf("status = %d, want %d for missing attribute",
			resp.StatusCode, wantStatus)
	}
}

func TestACS_Reject_ProviderInternalError(t *testing.T) {
	prov := &mockACSProvider{err: errors.New("unexpected internal failure")}

	emitter := &mockACSEmitter{}
	h := buildHandler(happyStore(), prov, happyBridge(), emitter)

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	wantStatus := bucketToStatus(ReasonInternal.Bucket())
	if resp.StatusCode != wantStatus {
		t.Errorf("status = %d, want %d for internal error",
			resp.StatusCode, wantStatus)
	}
}

// ---------------------------------------------------------------------------
// Validation duration histogram
// ---------------------------------------------------------------------------

func TestACS_Accept_ValidationDurationObserved(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	emitter := &mockACSEmitter{}
	h := NewHandler(Deps{
		Provider: happyProvider(),
		Store:    happyStore(),
		Bridge:   happyBridge(),
		Clock:    NewFakeClock(),
		Cfg:      goldenSAMLConfig(),
		Metrics:  metrics,
		Audit:    emitter,
	})

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	// Gather metrics and verify the histogram has at least one observation.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() == "tikti_saml_response_validation_duration_seconds" {
			for _, m := range mf.GetMetric() {
				if m.GetHistogram().GetSampleCount() > 0 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("validation duration histogram has no observations after accept")
	}
}

func TestACS_ReplayedAssertion_ReplayBlockedMetric(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	store := happyStore()
	store.markSeenFresh = false

	emitter := &mockACSEmitter{}
	h := NewHandler(Deps{
		Provider: happyProvider(),
		Store:    store,
		Bridge:   happyBridge(),
		Clock:    NewFakeClock(),
		Cfg:      goldenSAMLConfig(),
		Metrics:  metrics,
		Audit:    emitter,
	})

	r := newACSRequest(goldenResponseBase64(), "/app", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	// Gather metrics and verify replay_blocked counter was incremented.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() == "tikti_saml_replay_blocked_total" {
			for _, m := range mf.GetMetric() {
				if m.GetCounter().GetValue() == 1 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("replay_blocked counter not incremented after replayed assertion")
	}
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestParseSameSite(t *testing.T) {
	cases := []struct {
		input string
		want  http.SameSite
	}{
		{"Strict", http.SameSiteStrictMode},
		{"strict", http.SameSiteStrictMode},
		{"Lax", http.SameSiteLaxMode},
		{"lax", http.SameSiteLaxMode},
		{"None", http.SameSiteNoneMode},
		{"none", http.SameSiteNoneMode},
		{"", http.SameSiteDefaultMode},
		{"unknown", http.SameSiteDefaultMode},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := parseSameSite(tc.input)
			if got != tc.want {
				t.Errorf("parseSameSite(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestFirstAttr(t *testing.T) {
	va := &VerifiedAssertion{
		Attributes: map[string][]string{
			"email": {"a@example.com", "b@example.com"},
			"name":  {"Test User"},
		},
	}
	if got := firstAttr(va, "email"); got != "a@example.com" {
		t.Errorf("firstAttr(email) = %q, want %q", got, "a@example.com")
	}
	if got := firstAttr(va, "missing"); got != "" {
		t.Errorf("firstAttr(missing) = %q, want empty", got)
	}
}

func TestAllAttrs(t *testing.T) {
	va := &VerifiedAssertion{
		Attributes: map[string][]string{
			"roles": {"admin", "viewer"},
		},
	}
	got := allAttrs(va, "roles")
	if len(got) != 2 || got[0] != "admin" || got[1] != "viewer" {
		t.Errorf("allAttrs(roles) = %v, want [admin viewer]", got)
	}
	if got := allAttrs(va, "missing"); got != nil {
		t.Errorf("allAttrs(missing) = %v, want nil", got)
	}
}

func TestSubjectFromToken(t *testing.T) {
	t.Run("ValidJWT", func(t *testing.T) {
		got := subjectFromToken(goldenIDToken())
		if got != "user-001" {
			t.Errorf("subjectFromToken = %q, want %q", got, "user-001")
		}
	})

	t.Run("InvalidJWT", func(t *testing.T) {
		if got := subjectFromToken("not.a.jwt"); got != "" {
			t.Errorf("subjectFromToken(invalid) = %q, want empty", got)
		}
	})

	t.Run("EmptyString", func(t *testing.T) {
		if got := subjectFromToken(""); got != "" {
			t.Errorf("subjectFromToken(empty) = %q, want empty", got)
		}
	})
}

func TestBucketToStatus(t *testing.T) {
	cases := []struct {
		bucket ErrorBucket
		want   int
	}{
		{BucketBadRequest, http.StatusBadRequest},
		{BucketForbidden, http.StatusForbidden},
		{BucketNotConfigured, http.StatusNotFound},
		{BucketInternal, http.StatusInternalServerError},
		{"", http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(string(tc.bucket), func(t *testing.T) {
			if got := bucketToStatus(tc.bucket); got != tc.want {
				t.Errorf("bucketToStatus(%q) = %d, want %d", tc.bucket, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Reject audit: verify every ACS-reachable rejection emits an audit record
// ---------------------------------------------------------------------------

func TestACS_AllRejectPaths_EmitAudit(t *testing.T) {
	// Map of reject scenario → expected reason.
	scenarios := []struct {
		name       string
		setup      func() (*mockACSStore, *mockACSProvider, *mockACSBridge, string)
		wantReason Reason
	}{
		{
			name: "MissingStateCookie",
			setup: func() (*mockACSStore, *mockACSProvider, *mockACSBridge, string) {
				return happyStore(), happyProvider(), happyBridge(), "" // no cookie
			},
			wantReason: ReasonRequestNotFound,
		},
		{
			name: "ConsumeRequestNotFound",
			setup: func() (*mockACSStore, *mockACSProvider, *mockACSBridge, string) {
				s := happyStore()
				s.consumeOK = false
				return s, happyProvider(), happyBridge(), "req-001"
			},
			wantReason: ReasonRequestNotFound,
		},
		{
			name: "GetIdPError",
			setup: func() (*mockACSStore, *mockACSProvider, *mockACSBridge, string) {
				s := happyStore()
				s.getIdPErr = ErrIdPNotFound
				return s, happyProvider(), happyBridge(), "req-001"
			},
			wantReason: ReasonTIDUnknown,
		},
		{
			name: "ReplayedAssertion",
			setup: func() (*mockACSStore, *mockACSProvider, *mockACSBridge, string) {
				s := happyStore()
				s.markSeenFresh = false
				return s, happyProvider(), happyBridge(), "req-001"
			},
			wantReason: ReasonRequestReplay,
		},
		{
			name: "BridgeFailure",
			setup: func() (*mockACSStore, *mockACSProvider, *mockACSBridge, string) {
				b := &mockACSBridge{err: errors.New("bridge down")}
				return happyStore(), happyProvider(), b, "req-001"
			},
			wantReason: ReasonInternal,
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			store, prov, bridge, cookie := sc.setup()
			emitter := &mockACSEmitter{}
			h := buildHandler(store, prov, bridge, emitter)

			retry := sc.name == "MissingStateCookie"
			r := newACSRequestWithRetry(goldenResponseBase64(), "/app", cookie, retry)
			w := httptest.NewRecorder()

			h.ACS(w, r)

			if len(emitter.records) == 0 {
				t.Fatal("no audit record emitted")
			}
			last := emitter.records[len(emitter.records)-1]
			if last.Decision != "reject" {
				t.Errorf("audit decision = %q, want reject", last.Decision)
			}
			if last.Reason != string(sc.wantReason) {
				t.Errorf("audit reason = %q, want %q", last.Reason, sc.wantReason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isSafeRedirect — unit tests
// ---------------------------------------------------------------------------

func TestIsSafeRedirect(t *testing.T) {
	tests := []struct {
		uri  string
		want bool
	}{
		// Safe relative paths
		{"/dashboard", true},
		{"/app", true},
		{"/app/settings?tab=profile", true},
		{"/", true},

		// Absolute URLs — open redirect
		{"https://evil.com", false},
		{"http://evil.com/path", false},

		// Protocol-relative — open redirect
		{"//evil.com", false},
		{"//evil.com/path", false},

		// Backslash trick
		{"/\\evil.com", false},

		// Userinfo trick
		{"/@evil.com", false},

		// Empty
		{"", false},

		// No leading slash
		{"evil.com", false},
		{"relative/path", false},
	}

	for _, tc := range tests {
		t.Run(tc.uri, func(t *testing.T) {
			got := isSafeRedirect(tc.uri)
			if got != tc.want {
				t.Errorf("isSafeRedirect(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ACS open-redirect protection
// ---------------------------------------------------------------------------

func TestACS_AbsoluteRelayState_FallsBackToPostLoginURL(t *testing.T) {
	emitter := &mockACSEmitter{}
	h := buildHandler(happyStore(), happyProvider(), happyBridge(), emitter)

	// Attacker-controlled RelayState pointing to an external site.
	r := newACSRequest(goldenResponseBase64(), "https://evil.com/phish", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	loc := resp.Header.Get("Location")
	if loc != "/dashboard" {
		t.Errorf("Location = %q, want %q (PostLoginURL fallback)", loc, "/dashboard")
	}
}

func TestACS_ProtocolRelativeRelayState_FallsBackToPostLoginURL(t *testing.T) {
	emitter := &mockACSEmitter{}
	h := buildHandler(happyStore(), happyProvider(), happyBridge(), emitter)

	r := newACSRequest(goldenResponseBase64(), "//evil.com", "req-001")
	w := httptest.NewRecorder()

	h.ACS(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	loc := resp.Header.Get("Location")
	if loc != "/dashboard" {
		t.Errorf("Location = %q, want %q (PostLoginURL fallback for //)", loc, "/dashboard")
	}
}
