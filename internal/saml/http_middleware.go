package saml

import (
	"context"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Context keys for SAML middleware values.
const (
	ctxKeyTID       ctxKeyType = iota + 10 // avoid collision with ctxKeyT0
	ctxKeyRequestID ctxKeyType = iota + 10
)

// TIDFromContext returns the tenant ID stored by TenantContext middleware.
func TIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyTID).(string)
	return v
}

// RequestIDFromContext returns the request ID stored by RequestID middleware.
func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyRequestID).(string)
	return v
}

// BodyLimit returns middleware that rejects request bodies larger than n bytes
// with HTTP 413 (Request Entity Too Large). The limit is enforced before the
// next handler is invoked, so no handler work is performed on oversized bodies.
func BodyLimit(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// TenantContext reads the "tid" route parameter (chi.URLParam) and stores it
// in the request context so downstream handlers can retrieve it via
// TIDFromContext.
func TenantContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tid := chi.URLParam(r, "tid")
		if tid != "" {
			ctx := context.WithValue(r.Context(), ctxKeyTID, tid)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// RequestID injects a unique X-Request-ID into the request context and the
// response header. If the incoming request already carries the header, the
// existing value is reused.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// withTID stores a tenant ID in the context (used by TenantContext middleware
// and available for testing).
func withTID(ctx context.Context, tid string) context.Context {
	return context.WithValue(ctx, ctxKeyTID, tid)
}

// withRequestID stores a request ID in the context (used by RequestID
// middleware and available for testing).
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

// Logger is middleware that emits a structured log line at the end of each
// request, including tid and requestID fields when present in the context.
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)

		tid := TIDFromContext(r.Context())
		reqID := RequestIDFromContext(r.Context())
		log.Printf("method=%s path=%s tid=%s requestID=%s", r.Method, r.URL.Path, tid, reqID)
	})
}
