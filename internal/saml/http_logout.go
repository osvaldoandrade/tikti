package saml

import (
	"encoding/base64"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Logout initiates SP-initiated Single Logout (SLO).
//
// Flow: read idToken cookie → extract subject (nameID) → look up session
// index → build signed LogoutRequest → 302 redirect to IdP SLO URL.
//
// The session is NOT deleted here; deletion happens when the LogoutResponse
// is received (P3.5).
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tid := chi.URLParam(r, "tid")

	// 1. Read idToken cookie → subject → saml:idx:{nameID}.
	ck, err := r.Cookie(h.cfg.ACS.CookieName)
	if err != nil {
		h.renderError(w, r, ReasonRequestNotFound, http.StatusBadRequest)
		return
	}

	nameID := subjectFromToken(ck.Value)
	if nameID == "" {
		h.renderError(w, r, ReasonRequestNotFound, http.StatusBadRequest)
		return
	}

	idx, err := h.store.GetIndex(ctx, nameID)
	if err != nil {
		h.renderError(w, r, ReasonRequestNotFound, http.StatusBadRequest)
		return
	}

	// 2. Retrieve IdP trust material for this tenant.
	idp, err := h.store.GetIdP(ctx, tid)
	if err != nil {
		h.renderError(w, r, ReasonTIDUnknown, http.StatusBadRequest)
		return
	}

	// 3. Build signed LogoutRequest with NameID and SessionIndex.
	now := h.clock.Now().UTC()
	lr, err := h.prov.BuildLogoutRequest(ctx, BuildLogoutRequestInput{
		TenantID:     tid,
		IdP:          idp,
		NameID:       nameID,
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
	state := base64.RawURLEncoding.EncodeToString([]byte(nameID)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(lr.ID))
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
