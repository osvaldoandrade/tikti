package saml

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Logout initiates SP-initiated Single Logout (SLO).
//
// Flow: validate current idToken cookie → bind its local subject and tenant → look up session
// index → build signed LogoutRequest → 302 redirect to IdP SLO URL.
//
// The session is NOT deleted here; deletion happens when the LogoutResponse
// is received (P3.5).
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tid := chi.URLParam(r, "tid")

	if tid == "" || strings.TrimSpace(tid) != tid || h.authority == nil || len(h.sloStateKey) < 32 {
		h.renderError(w, r, ReasonRequestNotFound, http.StatusBadRequest)
		return
	}

	// 1. Validate the browser session cryptographically and against current
	// user status/tokenVersion before touching any SAML session state.
	ck, err := r.Cookie(h.cfg.ACS.CookieName)
	if err != nil {
		h.renderError(w, r, ReasonRequestNotFound, http.StatusBadRequest)
		return
	}

	identity, err := h.authority.Validate(ctx, ck.Value)
	if err != nil || identity.TenantID != tid {
		h.renderError(w, r, ReasonRequestNotFound, http.StatusBadRequest)
		return
	}

	idx, err := h.store.GetIndex(ctx, SessionSubjectIndexKey(tid, identity.Subject))
	if err != nil || !validSessionIndex(idx, tid, identity.Subject, "") || !strings.EqualFold(idx.Email, identity.Email) {
		h.renderError(w, r, ReasonRequestNotFound, http.StatusBadRequest)
		return
	}

	// 2. Retrieve IdP trust material for this tenant.
	idp, err := h.store.GetIdP(ctx, tid)
	if err != nil {
		h.renderError(w, r, ReasonTIDUnknown, http.StatusBadRequest)
		return
	}
	if _, safe := secureSLOURL(idp.SLOURL); !safe {
		h.renderError(w, r, ReasonTIDUnknown, http.StatusBadRequest)
		return
	}

	// 3. Build signed LogoutRequest with NameID and SessionIndex.
	now := h.clock.Now().UTC()
	lr, err := h.prov.BuildLogoutRequest(ctx, BuildLogoutRequestInput{
		TenantID:     tid,
		IdP:          idp,
		NameID:       idx.NameID,
		SessionIndex: idx.SessionIndex,
		RequestID:    hexRandom(20),
		IssueInstant: now,
		NameIDFormat: idp.NameIDFormat,
	})
	if err != nil {
		h.renderError(w, r, ReasonInternal, http.StatusInternalServerError)
		return
	}

	h.metrics.LogoutRequests.WithLabelValues(tid).Inc()
	state := EncodeSLOState(tid, identity.Subject, lr.ID, h.sloStateKey)
	if state == "" {
		h.renderError(w, r, ReasonInternal, http.StatusInternalServerError)
		return
	}
	// #nosec G124 -- all browser security attributes are explicit below.
	http.SetCookie(w, &http.Cookie{
		Name:     "tikti_saml_slo",
		Value:    state,
		Path:     "/saml",
		MaxAge:   int(h.cfg.SP.RequestTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})
	http.Redirect(w, r, lr.RedirectURL, http.StatusFound)
}
