package saml

import (
	"embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

//go:embed templates/error_*.html
var errorTemplateFS embed.FS

// errorTemplates is a compiled set of the four error-bucket HTML templates.
var errorTemplates = template.Must(
	template.ParseFS(errorTemplateFS, "templates/error_*.html"),
)

// errorTemplateData carries the data exposed to error-page templates.
type errorTemplateData struct {
	ErrorID string
}

// newErrorID returns a 12-character hex string derived from a UUIDv7.
// The truncation preserves the millisecond-timestamp prefix so that error
// IDs sort chronologically, while remaining short enough for users to
// read aloud to support.
func newErrorID() string {
	id := uuid.Must(uuid.NewV7())
	return strings.ReplaceAll(id.String(), "-", "")[:12]
}

// bucketTemplate maps an ErrorBucket to its template file name.
func bucketTemplate(b ErrorBucket) string {
	switch b {
	case BucketBadRequest:
		return "error_bad_request.html"
	case BucketForbidden:
		return "error_forbidden.html"
	case BucketNotConfigured:
		return "error_not_configured.html"
	default:
		return "error_internal.html"
	}
}

// renderError writes a neutral HTML error page for the given reason and
// HTTP status code. It sets the X-Tikti-Error-ID response header so that
// support can correlate the user-visible error with server-side logs
// without leaking the internal reason to the end-user.
func (h *Handler) renderError(w http.ResponseWriter, _ *http.Request, reason Reason, status int) {
	bucket := reason.Bucket()
	if bucket == "" {
		bucket = BucketInternal
	}

	eid := newErrorID()

	w.Header().Set("X-Tikti-Error-ID", eid)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	data := errorTemplateData{ErrorID: eid}
	tmplName := bucketTemplate(bucket)
	if err := errorTemplates.ExecuteTemplate(w, tmplName, data); err != nil {
		// Fallback: the header and status are already written.
		_, _ = w.Write([]byte("An error occurred."))
	}
}
