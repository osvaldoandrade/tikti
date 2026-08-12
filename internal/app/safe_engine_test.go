package app

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSafeEngineAccessLogOmitsRequestSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var access, recovery bytes.Buffer
	engine := newSafeEngineWithWriters(&access, &recovery)
	engine.POST("/probe/:id", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	request := httptest.NewRequest(http.MethodPost, "/probe/path-value-canary?key=query-key-canary&pageToken=cursor-canary", strings.NewReader("body-canary"))
	request.RemoteAddr = "192.0.2.10:4321"
	request.Header.Set("X-API-Key", "header-key-canary")
	request.Header.Set("X-Page-Token", "header-cursor-canary")
	request.Header.Set("Cookie", "session=cookie-canary")
	request.Header.Set("X-Request-Id", "req-safe-1")
	recorder := httptest.NewRecorder()

	engine.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("response status = %d", recorder.Code)
	}
	entry := access.String()
	for _, expected := range []string{`method="POST"`, `path="/probe/:id"`, "status=204", `remote_ip="192.0.2.10"`, `request_id="req-safe-1"`} {
		if !strings.Contains(entry, expected) {
			t.Fatalf("access log missing %q: %s", expected, entry)
		}
	}
	assertSafeLogCanariesAbsent(t, entry+recovery.String())

	access.Reset()
	unmatched := httptest.NewRequest(http.MethodGet, "/unmatched-path-canary?key=query-key-canary", nil)
	engine.ServeHTTP(httptest.NewRecorder(), unmatched)
	if entry = access.String(); !strings.Contains(entry, `path="<unmatched>"`) {
		t.Fatalf("unmatched access log = %s", entry)
	}
	assertSafeLogCanariesAbsent(t, entry)
}

func TestSafeEngineRecoveryOmitsPanicAndRequestSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var logs bytes.Buffer
	engine := newSafeEngineWithWriters(&logs, &logs)
	engine.POST("/panic/:id", func(*gin.Context) { panic(errors.New("panic-value-canary")) })
	request := httptest.NewRequest(http.MethodPost, "/panic/path-value-canary?key=query-key-canary&pageToken=cursor-canary", strings.NewReader("body-canary"))
	request.Header.Set("X-API-Key", "header-key-canary")
	request.Header.Set("X-Page-Token", "header-cursor-canary")
	request.Header.Set("Cookie", "session=cookie-canary")
	request.Header.Set("Authorization", "Bearer authorization-canary")
	request.Header.Set("X-Request-Id", "req-panic-1")
	recorder := httptest.NewRecorder()

	engine.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("response status = %d", recorder.Code)
	}
	entry := logs.String()
	for _, expected := range []string{"recovery", `path="/panic/:id"`, `request_id="req-panic-1"`, "panic_type=*errors.errorString", "status=500"} {
		if !strings.Contains(entry, expected) {
			t.Fatalf("recovery log missing %q: %s", expected, entry)
		}
	}
	assertSafeLogCanariesAbsent(t, entry)
}

func TestSafeLogValueAndRemoteIPAreBounded(t *testing.T) {
	long := strings.Repeat("x", safeLogValueLimit+1)
	if got := safeLogValue(long); len(got) != safeLogValueLimit {
		t.Fatalf("safeLogValue length = %d", len(got))
	}
	if got := remoteIP("[2001:db8::1]:443"); got != "2001:db8::1" {
		t.Fatalf("remoteIP = %q", got)
	}
	if got := remoteIP(long); len(got) != safeLogValueLimit {
		t.Fatalf("fallback remoteIP length = %d", len(got))
	}
	if got := safeRequestID("bad request id"); got != "" {
		t.Fatalf("unsafe request ID = %q", got)
	}
	if got := safeRequestID(""); got != "" {
		t.Fatalf("empty request ID = %q", got)
	}
}

func assertSafeLogCanariesAbsent(t *testing.T, value string) {
	t.Helper()
	for _, forbidden := range []string{
		"path-value-canary", "unmatched-path-canary", "query-key-canary", "cursor-canary", "body-canary", "header-key-canary",
		"header-cursor-canary", "cookie-canary", "authorization-canary", "panic-value-canary",
		"RawQuery", "X-API-Key", "X-Page-Token", "Authorization", "Cookie",
	} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("safe log contains %q: %s", forbidden, value)
		}
	}
}
