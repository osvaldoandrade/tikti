package saml

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Login handles GET /saml/login/{tid}. It builds an AuthnRequest, persists
// the request record, sets a state cookie, and 302-redirects to the IdP.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tid := chi.URLParam(r, "tid")
	relay := r.URL.Query().Get("RelayState")

	idp, err := h.store.GetIdP(ctx, tid)
	if errors.Is(err, ErrIdPNotFound) {
		h.renderError(w, r, ReasonTIDUnknown, http.StatusNotFound)
		return
	}
	if err != nil {
		h.renderError(w, r, ReasonInternal, http.StatusInternalServerError)
		return
	}

	reqID := hexRandom(20)
	now := h.clock.Now().UTC()

	authn, err := h.prov.BuildAuthnRequest(ctx, BuildAuthnRequestInput{
		TenantID:     tid,
		IdP:          idp,
		RelayState:   relay,
		ACSURL:       h.cfg.SP.ACSURL,
		RequestID:    reqID,
		IssueInstant: now,
		NameIDFormat: idp.NameIDFormat,
	})
	if err != nil {
		h.renderError(w, r, ReasonInternal, http.StatusInternalServerError)
		return
	}

	if err := h.store.PutRequest(ctx, RequestRecord{
		ID:           reqID,
		TenantID:     tid,
		RelayState:   relay,
		ACSURL:       h.cfg.SP.ACSURL,
		IssueInstant: now,
	}); err != nil {
		h.renderError(w, r, ReasonInternal, http.StatusInternalServerError)
		return
	}

	// State cookie — SameSite=None so the IdP POST-back carries it.
	h.setStateCookie(w, reqID, h.cfg.SP.RequestTTL)

	h.metrics.AuthnRequests.WithLabelValues(tid).Inc()
	http.Redirect(w, r, authn.RedirectURL, http.StatusFound)
}

// renderError writes a plain-text error response for the given reason and
// HTTP status code.
func (h *Handler) renderError(w http.ResponseWriter, _ *http.Request, reason Reason, code int) {
	http.Error(w, string(reason), code)
}

// hexRandom returns a hex-encoded string of n random bytes (2n hex chars).
func hexRandom(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("saml: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
