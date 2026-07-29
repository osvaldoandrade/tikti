package saml

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ACS handles POST /saml/acs — the Assertion Consumer Service endpoint.
// It validates the SAML Response, guards against replay, issues a local
// idToken via the SessionBridge, and redirects the user to the RelayState.
// Implementation follows HLD §9 / Appendix A.3.
func (h *Handler) ACS(w http.ResponseWriter, r *http.Request) {
	t0 := h.clock.Now()
	ctx := context.WithValue(r.Context(), ctxKeyT0, t0)
	r = r.WithContext(ctx)

	if err := r.ParseForm(); err != nil {
		h.reject(w, r, "", ReasonInternal)
		return
	}
	raw := r.PostFormValue("SAMLResponse")
	relay := r.PostFormValue("RelayState")
	retry := r.PostFormValue(stateCookieRetryField) == "1"

	// 1. Require state cookie set at /saml/login and discover tid from it.
	state, err := stateCookieForResponse(r, raw)
	if err != nil {
		if !retry && canRepostACS(raw, relay) {
			h.observeStateCookieRecovery(stateCookieRecoveryRepost)
			writeStateCookieRepost(w, raw, relay)
			return
		}
		if retry {
			h.observeStateCookieRecovery(stateCookieRecoveryFailure)
		}
		h.reject(w, r, "", ReasonRequestNotFound)
		return
	}
	if retry {
		h.observeStateCookieRecovery(stateCookieRecoverySuccess)
	}
	// The browser state is single-use even when the server-side request has
	// already expired or was consumed by a prior callback.
	h.clearStateCookie(w)
	req, ok, err := h.store.ConsumeRequest(ctx, state.Value)
	if err != nil || !ok {
		h.reject(w, r, "", ReasonRequestNotFound)
		return
	}

	// 2. Look up IdP trust material.
	idp, err := h.store.GetIdP(ctx, req.TenantID)
	if err != nil {
		h.reject(w, r, req.TenantID, ReasonTIDUnknown)
		return
	}

	// 3. Validate the SAML Response (10-step pipeline).
	va, reason, err := validateResponse(ctx, h.prov, h.clock, idp, raw, req, h.cfg.SP)
	if err != nil {
		h.reject(w, r, req.TenantID, ReasonInternal)
		return
	}
	if reason != ReasonOK {
		h.reject(w, r, req.TenantID, reason)
		return
	}

	// 4. Replay guard — after validation (fail fast on crypto first).
	fresh, err := h.store.MarkSeen(ctx, va.AssertionID, time.Hour)
	if err != nil {
		h.reject(w, r, req.TenantID, ReasonInternal)
		return
	}
	if !fresh {
		h.metrics.ReplayBlocked.WithLabelValues(req.TenantID).Inc()
		h.reject(w, r, req.TenantID, ReasonRequestReplay)
		return
	}

	// 5. JIT user + session bridge: issue a local idToken.
	idt, err := h.bridge.Issue(ctx, IssueInput{
		TenantID:        req.TenantID,
		ExternalSubject: va.NameID,
		Email:           firstAttr(va, "email"),
		Name:            firstAttr(va, "name"),
		Roles:           allAttrs(va, "roles"),
		AMR:             []string{"saml"},
		AuthnInstant:    h.clock.Now(),
	})
	if err != nil {
		h.reject(w, r, req.TenantID, ReasonInternal)
		return
	}

	// 6. Record session index for SLO.
	_ = h.store.PutIndex(ctx, va.NameID, IndexRecord{
		TenantID:     req.TenantID,
		Subject:      subjectFromToken(idt),
		SessionIndex: va.SessionIndex,
		NotOnOrAfter: va.NotOnOrAfter,
	})

	// 7. Set idToken cookie, record metrics + audit, redirect.
	h.setIDTokenCookie(w, idt)
	h.metrics.Responses.WithLabelValues(req.TenantID, "accept").Inc()
	h.metrics.ValidationDuration.WithLabelValues(req.TenantID).Observe(h.clock.Since(t0).Seconds())
	_ = h.audit.Emit(ctx, NewAcceptRecord(req.TenantID, *va, req.ID, h.cfg.SP.EntityID, h.clock.Since(t0)))

	redirectURL := relay
	if redirectURL == "" || !isSafeRedirect(redirectURL) {
		redirectURL = h.cfg.ACS.PostLoginURL
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// isSafeRedirect returns true when uri is a relative path safe from open-
// redirect attacks.  It rejects absolute URLs, protocol-relative URLs
// (//evil.com), backslash tricks (\evil.com), and data/javascript URIs.
func isSafeRedirect(uri string) bool {
	// Must be non-empty and start with a single forward slash.
	if uri == "" || uri[0] != '/' {
		return false
	}
	// Reject protocol-relative URLs  "//evil.com/…"
	if len(uri) > 1 && uri[1] == '/' {
		return false
	}
	// Reject backslash after leading slash  "/\evil.com"
	if len(uri) > 1 && uri[1] == '\\' {
		return false
	}
	// Parse to ensure the result is indeed relative (no scheme, no host).
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	if u.Scheme != "" || u.Host != "" {
		return false
	}
	// Reject userinfo tricks ("/@evil.com") — not dangerous for Location
	// headers, but a defence-in-depth measure.
	if strings.HasPrefix(uri, "/@") {
		return false
	}
	return true
}
