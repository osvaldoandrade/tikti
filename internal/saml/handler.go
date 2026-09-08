package saml

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/osvaldoandrade/tikti/pkg/config"
)

type AuthenticationAttemptLimiter interface {
	AllowAuthenticationAttempt(context.Context, string, string, int, time.Duration) (bool, error)
}

type TenantStatusAuthority interface {
	IsTenantActive(context.Context, string) (bool, error)
}

// Deps groups all dependencies needed to construct a Handler.
type Deps struct {
	Provider              Provider
	Store                 Store
	Bridge                SessionBridge
	Clock                 Clock
	Cfg                   config.SAMLConfig
	Metrics               *Metrics
	Audit                 Emitter
	Authority             SessionAuthority
	Tenants               TenantStatusAuthority
	SLOStateKey           []byte
	AuthenticationLimiter AuthenticationAttemptLimiter
	ResolveClientIP       func(*http.Request) string
	RateLimit             config.RateLimitConfig
}

// Handler implements the SAML HTTP handlers (ACS, Login, Metadata, etc.).
type Handler struct {
	prov                  Provider
	store                 Store
	bridge                SessionBridge
	clock                 Clock
	cfg                   config.SAMLConfig
	metrics               *Metrics
	audit                 Emitter
	authority             SessionAuthority
	tenants               TenantStatusAuthority
	sloStateKey           []byte
	authenticationLimiter AuthenticationAttemptLimiter
	resolveClientIP       func(*http.Request) string
	rateLimit             config.RateLimitConfig
}

// NewHandler constructs a Handler from its dependencies.
func NewHandler(d Deps) *Handler {
	return &Handler{
		prov:                  d.Provider,
		store:                 d.Store,
		bridge:                d.Bridge,
		clock:                 d.Clock,
		cfg:                   d.Cfg,
		metrics:               d.Metrics,
		audit:                 d.Audit,
		authority:             d.Authority,
		tenants:               d.Tenants,
		sloStateKey:           append([]byte(nil), d.SLOStateKey...),
		authenticationLimiter: d.AuthenticationLimiter,
		resolveClientIP:       d.ResolveClientIP,
		rateLimit:             d.RateLimit,
	}
}

func secureBrowserAuthenticationResponse(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func (h *Handler) allowSAMLAuthenticationAttempt(w http.ResponseWriter, r *http.Request, bucket string) bool {
	if h.authenticationLimiter == nil || h.resolveClientIP == nil {
		return true
	}
	limit := h.rateLimit
	if limit.Requests < 1 || limit.WindowSeconds < 1 {
		limit = config.DefaultAuthenticationRateLimits().SAML
	}
	allowed, err := h.authenticationLimiter.AllowAuthenticationAttempt(
		r.Context(), bucket, h.resolveClientIP(r), limit.Requests, time.Duration(limit.WindowSeconds)*time.Second,
	)
	if err != nil {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("{\"error\":\"authentication unavailable\"}\n"))
		return false
	}
	if !allowed {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("{\"error\":\"too many attempts\"}\n"))
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// ctxKeyType is an unexported type used for context keys to avoid collisions.
type ctxKeyType int

const ctxKeyT0 ctxKeyType = iota

// reject writes an error response for a failed ACS request. It records
// metrics and emits an audit record. The start time t0 must have been
// stored in the request context via context.WithValue.
func (h *Handler) reject(w http.ResponseWriter, r *http.Request, tid string, reason Reason) {
	t0, _ := r.Context().Value(ctxKeyT0).(time.Time)
	dur := h.clock.Since(t0)

	if tid != "" {
		h.metrics.Responses.WithLabelValues(tid, "reject").Inc()
		h.metrics.ValidationFailures.WithLabelValues(tid, string(reason)).Inc()
	}
	if err := h.emitAudit(r.Context(), NewRejectRecord(tid, "", reason, dur)); err != nil {
		h.observeAuditFailure(tid, "reject")
		h.writeAuditUnavailable(w)
		return
	}

	status := bucketToStatus(reason.Bucket())
	http.Error(w, http.StatusText(status), status)
}

func (h *Handler) rejectAfterIntent(w http.ResponseWriter, r *http.Request, tid string, assertion VerifiedAssertion, requestID, audience string, reason Reason) {
	t0, _ := r.Context().Value(ctxKeyT0).(time.Time)
	dur := h.clock.Since(t0)
	if tid != "" {
		h.metrics.Responses.WithLabelValues(tid, "reject").Inc()
		h.metrics.ValidationFailures.WithLabelValues(tid, string(reason)).Inc()
	}
	if err := h.emitAudit(r.Context(), NewRejectOutcomeRecord(tid, assertion, requestID, audience, reason, dur)); err != nil {
		h.observeAuditFailure(tid, "reject")
		h.writeAuditUnavailable(w)
		return
	}
	http.Error(w, http.StatusText(bucketToStatus(reason.Bucket())), bucketToStatus(reason.Bucket()))
}

func (h *Handler) emitAudit(ctx context.Context, record AuditRecord) error {
	if h == nil || h.audit == nil {
		return errors.New("saml audit emitter is unavailable")
	}
	return h.audit.Emit(ctx, record)
}

func (h *Handler) observeAuditFailure(tenantID, decision string) {
	if h != nil && h.metrics != nil && h.metrics.AuditFailures != nil {
		h.metrics.AuditFailures.WithLabelValues(tenantID, decision).Inc()
	}
	log.Printf("event=saml.audit_failure tenant=%s decision=%s", tenantID, decision)
}

func (h *Handler) writeAuditUnavailable(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte("Internal Server Error\n"))
}

// bucketToStatus maps an ErrorBucket to the corresponding HTTP status code.
func bucketToStatus(b ErrorBucket) int {
	switch b {
	case BucketBadRequest:
		return http.StatusBadRequest
	case BucketForbidden:
		return http.StatusForbidden
	case BucketNotConfigured:
		return http.StatusNotFound
	case BucketInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// firstAttr returns the first value of the named attribute from a
// VerifiedAssertion, or "" if absent.
func firstAttr(va *VerifiedAssertion, name string) string {
	if vals, ok := va.Attributes[name]; ok && len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// allAttrs returns all values of the named attribute from a
// VerifiedAssertion, or nil if absent.
func allAttrs(va *VerifiedAssertion, name string) []string {
	if vals, ok := va.Attributes[name]; ok {
		return vals
	}
	return nil
}
