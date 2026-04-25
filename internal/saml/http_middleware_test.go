package saml

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// ---------------------------------------------------------------------------
// TestBodyLimit_413
// ---------------------------------------------------------------------------

// TestBodyLimit_413 verifies that a request body larger than the configured
// limit is rejected with HTTP 413 before the handler does any work.
func TestBodyLimit_413(t *testing.T) {
	const limit = 1 << 20 // 1 MiB

	handlerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the body — MaxBytesReader returns an error for
		// oversized payloads.
		buf := make([]byte, limit+1)
		_, err := r.Body.Read(buf)
		if err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	mw := BodyLimit(limit)
	handler := mw(inner)

	// Build a 2 MiB body — twice the limit.
	body := bytes.NewReader(make([]byte, 2<<20))
	req := httptest.NewRequest(http.MethodPost, "/saml/acs", body)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	if handlerCalled {
		t.Fatal("handler performed work on an oversized body")
	}
}

// ---------------------------------------------------------------------------
// TestTenantContext_Populates
// ---------------------------------------------------------------------------

// TestTenantContext_Populates verifies that TenantContext middleware reads the
// chi route parameter "tid" and stores it on the request context.
func TestTenantContext_Populates(t *testing.T) {
	const wantTID = "tenant-42"

	var gotTID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTID = TIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	r := chi.NewRouter()
	r.Route("/saml/login/{tid}", func(s chi.Router) {
		s.Use(TenantContext)
		s.Get("/", inner)
	})

	req := httptest.NewRequest(http.MethodGet, "/saml/login/"+wantTID+"/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotTID != wantTID {
		t.Fatalf("TIDFromContext = %q, want %q", gotTID, wantTID)
	}
}

// ---------------------------------------------------------------------------
// TestLogger_FieldsPresent
// ---------------------------------------------------------------------------

// TestLogger_FieldsPresent verifies that the Logger middleware emits a log
// line containing both tid and requestID fields.
func TestLogger_FieldsPresent(t *testing.T) {
	const tid = "tenant-99"
	const reqID = "req-abc-123"

	// Capture log output.
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0) // no timestamp prefix
	defer log.SetOutput(os.Stderr)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Compose: RequestID → TenantContext → Logger → handler.
	// We inject known values via context so the test is deterministic.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate RequestID + TenantContext having already run.
		ctx := r.Context()
		ctx = withTID(ctx, tid)
		ctx = withRequestID(ctx, reqID)
		Logger(inner).ServeHTTP(w, r.WithContext(ctx))
	})

	req := httptest.NewRequest(http.MethodGet, "/saml/login/"+tid, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	line := buf.String()
	if !strings.Contains(line, "tid="+tid) {
		t.Errorf("log line missing tid field: %s", line)
	}
	if !strings.Contains(line, "requestID="+reqID) {
		t.Errorf("log line missing requestID field: %s", line)
	}
}
