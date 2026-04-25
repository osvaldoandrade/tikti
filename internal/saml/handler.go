package saml

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/osvaldoandrade/tikti/pkg/config"
)

// Deps groups all dependencies needed to construct a Handler.
type Deps struct {
	Provider Provider
	Store    Store
	Bridge   SessionBridge
	Clock    Clock
	Cfg      config.SAMLConfig
	Metrics  *Metrics
	Audit    Emitter
}

// Handler implements the SAML HTTP handlers (ACS, Login, Metadata, etc.).
type Handler struct {
	prov    Provider
	store   Store
	bridge  SessionBridge
	clock   Clock
	cfg     config.SAMLConfig
	metrics *Metrics
	audit   Emitter
}

// NewHandler constructs a Handler from its dependencies.
func NewHandler(d Deps) *Handler {
	return &Handler{
		prov:    d.Provider,
		store:   d.Store,
		bridge:  d.Bridge,
		clock:   d.Clock,
		cfg:     d.Cfg,
		metrics: d.Metrics,
		audit:   d.Audit,
	}
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
	_ = h.audit.Emit(r.Context(), NewRejectRecord(tid, "", reason, dur))

	status := bucketToStatus(reason.Bucket())
	http.Error(w, http.StatusText(status), status)
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

// setIDTokenCookie writes the idToken as an HTTP cookie per HLD App. A.9.
func (h *Handler) setIDTokenCookie(w http.ResponseWriter, idt string) {
	c := &http.Cookie{
		Name:     h.cfg.ACS.CookieName,
		Value:    idt,
		Path:     "/",
		Domain:   h.cfg.ACS.CookieDomain,
		Secure:   h.cfg.ACS.CookieSecure,
		HttpOnly: h.cfg.ACS.CookieHTTPOnly,
		SameSite: parseSameSite(h.cfg.ACS.CookieSameSite),
		MaxAge:   h.cfg.ACS.SessionTTL,
	}
	http.SetCookie(w, c)
}

// parseSameSite converts a string cookie SameSite value to http.SameSite.
// Unrecognized or empty values return http.SameSiteDefaultMode.
func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
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

// subjectFromToken extracts the "sub" claim from a JWT token string
// by decoding the payload (second segment). It does not verify the
// signature because the token was just issued by the local bridge.
func subjectFromToken(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Sub
}
