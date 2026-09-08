package saml

import (
	"context"
	"log"
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
	secureBrowserAuthenticationResponse(w)
	if !h.allowSAMLAuthenticationAttempt(w, r, "saml-acs:ip") {
		return
	}
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
		diagnostics := diagnoseStateCorrelation(r, raw, state.Value)
		log.Printf(
			"event=saml.state_correlation responseIDPresent=%t stateCookieCount=%d matchingCookiePresent=%t selectedMatchesResponse=%t consumeError=%t requestFound=%t",
			diagnostics.ResponseIDPresent,
			diagnostics.StateCookieCount,
			diagnostics.MatchingCookiePresent,
			diagnostics.SelectedMatchesResponse,
			err != nil,
			ok,
		)
		h.reject(w, r, "", ReasonRequestNotFound)
		return
	}
	// RelayState is part of the single-use login correlation record. Never
	// accept a callback-selected redirect, even when it is locally shaped.
	if relay != req.RelayState {
		h.reject(w, r, req.TenantID, ReasonRequestNotFound)
		return
	}
	if h.tenants == nil {
		h.reject(w, r, req.TenantID, ReasonInternal)
		return
	}
	active, tenantErr := h.tenants.IsTenantActive(ctx, req.TenantID)
	if tenantErr != nil {
		h.reject(w, r, req.TenantID, ReasonInternal)
		return
	}
	if !active {
		h.reject(w, r, req.TenantID, ReasonTIDUnknown)
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
	sessionNow := h.clock.Now()
	sessionExpiresAt := boundedSessionExpiry(h.cfg.ACS.SessionTTL, va.NotOnOrAfter, sessionNow)
	cookieMaxAge := int(sessionExpiresAt.Sub(sessionNow).Seconds())
	if cookieMaxAge <= 0 {
		h.reject(w, r, req.TenantID, ReasonClockSkew)
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
	if h.authority == nil {
		h.reject(w, r, req.TenantID, ReasonInternal)
		return
	}
	if err := h.emitAudit(ctx, NewAcceptIntentRecord(req.TenantID, *va, req.ID, h.cfg.SP.EntityID, h.clock.Since(t0))); err != nil {
		h.observeAuditFailure(req.TenantID, "intent")
		h.writeAuditUnavailable(w)
		return
	}
	idt, err := h.bridge.Issue(ctx, IssueInput{
		TenantID:        req.TenantID,
		ExternalSubject: va.NameID,
		Email:           firstAttr(va, "email"),
		Name:            firstAttr(va, "name"),
		Roles:           allAttrs(va, "roles"),
		AMR:             []string{"saml"},
		AuthnInstant:    sessionNow,
		NotOnOrAfter:    sessionExpiresAt,
	})
	if err != nil {
		h.rejectAfterIntent(w, r, req.TenantID, *va, req.ID, h.cfg.SP.EntityID, ReasonInternal)
		return
	}

	// 6. Record tenant-scoped local-subject and external-NameID indexes for
	// SLO. Validate the newly issued token through the same current-session
	// authority used at the HTTP logout boundary.
	identity, authorityErr := h.authority.Validate(ctx, idt)
	if authorityErr != nil || identity.TenantID != req.TenantID {
		h.rejectAfterIntent(w, r, req.TenantID, *va, req.ID, h.cfg.SP.EntityID, ReasonInternal)
		return
	}
	if err := putSessionIndex(ctx, h.store, IndexRecord{
		TenantID:     req.TenantID,
		Subject:      identity.Subject,
		NameID:       va.NameID,
		Email:        identity.Email,
		SessionIndex: va.SessionIndex,
		NotOnOrAfter: sessionExpiresAt,
	}); err != nil {
		h.rejectAfterIntent(w, r, req.TenantID, *va, req.ID, h.cfg.SP.EntityID, ReasonInternal)
		return
	}

	// 7. Persist the acceptance decision before exposing the session. A local
	// token must never reach the browser when its audit trail is unavailable.
	if err := h.emitAudit(ctx, NewAcceptRecord(req.TenantID, *va, req.ID, h.cfg.SP.EntityID, h.clock.Since(t0))); err != nil {
		h.observeAuditFailure(req.TenantID, "accept")
		_ = deleteSessionIndex(ctx, h.store, IndexRecord{TenantID: req.TenantID, Subject: identity.Subject, NameID: va.NameID})
		h.clearIDTokenCookie(w)
		h.writeAuditUnavailable(w)
		return
	}

	// 8. Expose the audited session, record metrics, and redirect.
	h.setIDTokenCookie(w, idt, cookieMaxAge)
	h.metrics.Responses.WithLabelValues(req.TenantID, "accept").Inc()
	h.metrics.ValidationDuration.WithLabelValues(req.TenantID).Observe(h.clock.Since(t0).Seconds())

	redirectURL := req.RelayState
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
