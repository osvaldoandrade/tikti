package saml

import (
	"encoding/base64"
	"log"
	"net/http"
	"strings"

	"github.com/beevik/etree"
	crewjamsaml "github.com/crewjam/saml"
)

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

	state, err := r.Cookie("tikti_saml_slo")
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	nameID, expectedID, ok := decodeSLOState(state.Value)
	if !ok {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	idx, err := h.store.GetIndex(ctx, nameID)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	idp, err := h.store.GetIdP(ctx, idx.TenantID)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	verified, err := h.prov.ValidateLogoutMessage(ctx, ValidateLogoutInput{
		TenantID:             idx.TenantID,
		IdP:                  idp,
		RawMessage:           rawResp,
		Binding:              crewjamsaml.HTTPRedirectBinding,
		ExpectedInResponseTo: expectedID,
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
	_ = h.store.DeleteIndex(ctx, nameID)
	h.metrics.LogoutResponses.WithLabelValues(idx.TenantID, "accept").Inc()

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

	nameID, ok := untrustedLogoutNameID(rawReq)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	idx, err := h.store.GetIndex(ctx, nameID)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	idp, err := h.store.GetIdP(ctx, idx.TenantID)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	verified, err := h.prov.ValidateLogoutMessage(ctx, ValidateLogoutInput{
		TenantID:   idx.TenantID,
		IdP:        idp,
		RawMessage: rawReq,
		Binding:    crewjamsaml.HTTPPostBinding,
	})
	if err != nil || verified.IsResponse {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Look up the session index to determine the tenant and IdP.
	_ = h.store.DeleteIndex(ctx, verified.NameID)
	h.metrics.LogoutResponses.WithLabelValues(idx.TenantID, "accept").Inc()

	resp, err := h.prov.BuildLogoutResponse(ctx, BuildLogoutResponseInput{
		IdP:          idp,
		InResponseTo: verified.MessageID,
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

func decodeSLOState(value string) (string, string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return "", "", false
	}
	nameID, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return "", "", false
	}
	requestID, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(nameID) == 0 || len(requestID) == 0 {
		return "", "", false
	}
	return string(nameID), string(requestID), true
}

func untrustedLogoutNameID(raw string) (string, bool) {
	xmlBytes, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(xmlBytes) == 0 || len(xmlBytes) > 1<<20 || containsDOCTYPE(xmlBytes) {
		return "", false
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil || doc.Root() == nil ||
		doc.Root().Tag != "LogoutRequest" ||
		doc.Root().NamespaceURI() != "urn:oasis:names:tc:SAML:2.0:protocol" {
		return "", false
	}
	for _, element := range doc.Root().ChildElements() {
		if element.Tag == "NameID" && element.NamespaceURI() == "urn:oasis:names:tc:SAML:2.0:assertion" {
			value := strings.TrimSpace(element.Text())
			return value, value != ""
		}
	}
	return "", false
}

func extractRequestID(raw string) string {
	xmlBytes, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(xmlBytes) == 0 || len(xmlBytes) > 1<<20 || containsDOCTYPE(xmlBytes) {
		return ""
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil || doc.Root() == nil ||
		doc.Root().NamespaceURI() != "urn:oasis:names:tc:SAML:2.0:protocol" ||
		doc.Root().Tag != "LogoutRequest" {
		return ""
	}
	return strings.TrimSpace(doc.Root().SelectAttrValue("ID", ""))
}
