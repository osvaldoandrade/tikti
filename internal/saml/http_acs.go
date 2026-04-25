package saml

import (
	"context"
	"net/http"
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

	// 1. Require state cookie set at /saml/login and discover tid from it.
	state, err := r.Cookie("tikti_saml_state")
	if err != nil {
		h.reject(w, r, "", ReasonRequestNotFound)
		return
	}
	req, ok, err := h.store.ConsumeRequest(ctx, state.Value)
	if err != nil || !ok {
		h.reject(w, r, "", ReasonRequestNotFound)
		return
	}

	// Clear the state cookie.
	http.SetCookie(w, &http.Cookie{
		Name: "tikti_saml_state", Path: "/saml", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode,
	})

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

	dest := relay
	if dest == "" {
		dest = h.cfg.ACS.PostLoginURL
	}
	http.Redirect(w, r, dest, http.StatusFound)
}
