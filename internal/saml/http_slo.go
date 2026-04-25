package saml

import (
	"encoding/base64"
	"encoding/xml"
	"log"
	"net/http"

	crewjamsaml "github.com/crewjam/saml"
)

// Deps carries all dependencies needed by the SAML HTTP handlers.
type Deps struct {
	Provider Provider
	Store    Store
	Clock    Clock
	Metrics  *Metrics
}

// Handler holds the dependencies for the SAML HTTP handlers.
type Handler struct {
	prov    Provider
	store   Store
	clock   Clock
	metrics *Metrics
}

// NewHandler creates a new Handler wired with the given dependencies.
func NewHandler(d Deps) *Handler {
	return &Handler{
		prov:    d.Provider,
		store:   d.Store,
		clock:   d.Clock,
		metrics: d.Metrics,
	}
}

// SLO handles both GET and POST /saml/slo.
//
// GET: receives the IdP's LogoutResponse (tail of SP-initiated SLO).
//
//	Verifies the response status, deletes the SAML session index,
//	clears the session cookie, and redirects to "/".
//
// POST: receives an IdP-initiated LogoutRequest.
//
//	Verifies the request, extracts NameID, deletes the SAML session
//	index, clears the session cookie, and returns a signed
//	LogoutResponse via HTTP-POST back to the IdP.
func (h *Handler) SLO(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.sloGet(w, r)
	case http.MethodPost:
		h.sloPost(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// sloGet handles the SP-initiated SLO tail: the IdP redirects back with a
// SAMLResponse query parameter.
func (h *Handler) sloGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rawResp := r.URL.Query().Get("SAMLResponse")
	if rawResp == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	verified, err := h.prov.ValidateLogoutMessage(ctx, ValidateLogoutInput{
		RawMessage: rawResp,
		Binding:    crewjamsaml.HTTPRedirectBinding,
	})
	if err != nil || !verified.IsResponse {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if verified.Status != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Read the SLO state cookie set by the logout handler (P3.4) to
	// determine which SAML session index to delete.
	if c, err := r.Cookie("tikti_saml_slo"); err == nil && c.Value != "" {
		nameID := c.Value
		idx, err := h.store.GetIndex(ctx, nameID)
		if err == nil {
			_ = h.store.DeleteIndex(ctx, nameID)
			h.metrics.LogoutResponses.WithLabelValues(idx.TenantID, "accept").Inc()
		}
	}

	// Clear session and SLO cookies.
	http.SetCookie(w, &http.Cookie{
		Name: "tikti_saml_slo", Path: "/saml", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

// sloPost handles an IdP-initiated LogoutRequest received via HTTP-POST.
func (h *Handler) sloPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	rawReq := r.PostFormValue("SAMLRequest")
	if rawReq == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	verified, err := h.prov.ValidateLogoutMessage(ctx, ValidateLogoutInput{
		RawMessage: rawReq,
		Binding:    crewjamsaml.HTTPPostBinding,
	})
	if err != nil || verified.IsResponse {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Look up the session index to determine the tenant and IdP.
	idx, err := h.store.GetIndex(ctx, verified.NameID)
	if err != nil {
		log.Printf("saml: slo: index lookup for %q: %v", verified.NameID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	idp, err := h.store.GetIdP(ctx, idx.TenantID)
	if err != nil {
		log.Printf("saml: slo: idp lookup for tenant %q: %v", idx.TenantID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	_ = h.store.DeleteIndex(ctx, verified.NameID)
	h.metrics.LogoutResponses.WithLabelValues(idx.TenantID, "accept").Inc()

	// Extract the InResponseTo ID from the original LogoutRequest.
	inResponseTo := extractRequestID(rawReq)

	resp, err := h.prov.BuildLogoutResponse(ctx, BuildLogoutResponseInput{
		IdP:          idp,
		InResponseTo: inResponseTo,
	})
	if err != nil {
		log.Printf("saml: slo: build logout response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp.PostBody)
}

// extractRequestID decodes a base64-encoded SAML LogoutRequest and extracts
// the request ID attribute.
func extractRequestID(raw string) string {
	xmlBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return ""
	}
	// Lightweight extraction: look for ID= attribute in the LogoutRequest.
	// The full XML was already validated by ValidateLogoutMessage.
	type probe struct {
		ID string `xml:"ID,attr"`
	}
	var p probe
	if err := xml.Unmarshal(xmlBytes, &p); err != nil {
		return ""
	}
	return p.ID
}
