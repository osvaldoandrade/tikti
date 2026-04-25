package saml

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRender_BadRequest_400 verifies that a reason in the bad_request bucket
// produces HTTP 400 and uses the bad-request template.
func TestRender_BadRequest_400(t *testing.T) {
	h := &Handler{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h.renderError(rec, req, ReasonDestinationMismatch, http.StatusBadRequest)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Bad Request") {
		t.Errorf("body does not contain expected heading; got:\n%s", body)
	}
}

// TestRender_Forbidden_403 verifies that a reason in the forbidden bucket
// produces HTTP 403 and uses the forbidden template.
func TestRender_Forbidden_403(t *testing.T) {
	h := &Handler{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h.renderError(rec, req, ReasonSignatureInvalid, http.StatusForbidden)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Access Denied") {
		t.Errorf("body does not contain expected heading; got:\n%s", body)
	}
}

// TestRender_ErrorIDHeader verifies that the X-Tikti-Error-ID header is
// present and is exactly 12 characters long.
func TestRender_ErrorIDHeader(t *testing.T) {
	h := &Handler{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h.renderError(rec, req, ReasonInternal, http.StatusInternalServerError)

	eid := rec.Header().Get("X-Tikti-Error-ID")
	if eid == "" {
		t.Fatal("X-Tikti-Error-ID header missing")
	}
	if len(eid) != 12 {
		t.Errorf("X-Tikti-Error-ID length = %d, want 12; value = %q", len(eid), eid)
	}
}

// TestRender_NoReasonLeakedInBody ensures that the internal reason string
// never appears in the HTML body rendered to the user.
func TestRender_NoReasonLeakedInBody(t *testing.T) {
	h := &Handler{}

	for _, reason := range AllRejectReasons {
		t.Run(string(reason), func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			bucket := reason.Bucket()
			status := bucketToStatus(bucket)
			h.renderError(rec, req, reason, status)

			body := rec.Body.String()
			if strings.Contains(body, string(reason)) {
				t.Errorf("body leaks reason %q:\n%s", reason, body)
			}
		})
	}
}
