package saml

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
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
	setSLOSecurityHeaders(w)
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
	tenantID, subject, expectedID, ok := decodeSLOState(state.Value, h.sloStateKey)
	if !ok {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	idx, err := h.store.GetIndex(ctx, SessionSubjectIndexKey(tenantID, subject))
	if err != nil || !validSessionIndex(idx, tenantID, subject, "") {
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
	if err != nil || verified == nil || !verified.IsResponse {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if verified.Status != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if h.authority == nil || h.authority.Revoke(ctx, idx.Subject, idx.Email) != nil {
		h.clearIDTokenCookie(w)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := deleteSessionIndex(ctx, h.store, idx); err != nil {
		h.clearIDTokenCookie(w)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.metrics.LogoutResponses.WithLabelValues(idx.TenantID, "accept").Inc()

	// Clear both the browser identity session and the correlation state.
	h.clearIDTokenCookie(w)
	clearSLOStateCookie(w)

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

	nameID, issuer, ok := untrustedLogoutIdentity(rawReq)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	idps, err := h.store.ListIdPs(ctx)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	idp, ok := exactIdPForIssuer(idps, issuer)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	sloURL, safe := secureSLOURL(idp.SLOURL)
	if !safe {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	verified, err := h.prov.ValidateLogoutMessage(ctx, ValidateLogoutInput{
		TenantID:   idp.TenantID,
		IdP:        idp,
		RawMessage: rawReq,
		Binding:    crewjamsaml.HTTPPostBinding,
	})
	if err != nil || verified == nil || verified.IsResponse || verified.NameID != nameID || verified.SessionIndex == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	idx, err := h.store.GetIndex(ctx, SessionNameIDIndexKey(idp.TenantID, verified.NameID))
	if err != nil || !validSessionIndex(idx, idp.TenantID, "", verified.NameID) || idx.SessionIndex != verified.SessionIndex {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	resp, err := h.prov.BuildLogoutResponse(ctx, BuildLogoutResponseInput{
		IdP:          idp,
		InResponseTo: verified.MessageID,
	})
	if err != nil {
		log.Printf("saml: slo: build logout response failed")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if h.authority == nil || h.authority.Revoke(ctx, idx.Subject, idx.Email) != nil {
		h.clearIDTokenCookie(w)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := deleteSessionIndex(ctx, h.store, idx); err != nil {
		h.clearIDTokenCookie(w)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.metrics.LogoutResponses.WithLabelValues(idx.TenantID, "accept").Inc()
	h.clearIDTokenCookie(w)

	nonce := hexRandom(16)
	body := bytes.Replace(resp.PostBody, []byte("<script>"), []byte(`<script nonce="`+nonce+`">`), 1)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; form-action "+sloURL.Scheme+"://"+sloURL.Host+"; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func setSLOSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
}

func EncodeSLOState(tenantID, subject, requestID string, key []byte) string {
	if len(key) < 32 || tenantID == "" || subject == "" || requestID == "" ||
		len(tenantID) > 128 || len(subject) > 1024 || len(requestID) > 256 {
		return ""
	}
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(tenantID)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(subject)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(requestID))
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func decodeSLOState(value string, key []byte) (string, string, string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 4 || len(key) < 32 {
		return "", "", "", false
	}
	providedMAC, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil {
		return "", "", "", false
	}
	unsigned := strings.Join(parts[:3], ".")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(unsigned))
	if !hmac.Equal(providedMAC, mac.Sum(nil)) {
		return "", "", "", false
	}
	tenantID, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return "", "", "", false
	}
	subject, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return "", "", "", false
	}
	requestID, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(tenantID) == 0 || len(subject) == 0 || len(requestID) == 0 ||
		len(tenantID) > 128 || len(subject) > 1024 || len(requestID) > 256 {
		return "", "", "", false
	}
	return string(tenantID), string(subject), string(requestID), true
}

func untrustedLogoutNameID(raw string) (string, bool) {
	nameID, _, ok := untrustedLogoutIdentity(raw)
	return nameID, ok
}

func untrustedLogoutIdentity(raw string) (string, string, bool) {
	xmlBytes, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(xmlBytes) == 0 || len(xmlBytes) > 1<<20 || containsDOCTYPE(xmlBytes) {
		return "", "", false
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil || doc.Root() == nil ||
		doc.Root().Tag != "LogoutRequest" ||
		doc.Root().NamespaceURI() != "urn:oasis:names:tc:SAML:2.0:protocol" {
		return "", "", false
	}
	nameID, issuer := "", ""
	for _, element := range doc.Root().ChildElements() {
		if element.Tag == "NameID" && element.NamespaceURI() == "urn:oasis:names:tc:SAML:2.0:assertion" {
			if nameID != "" {
				return "", "", false
			}
			nameID = strings.TrimSpace(element.Text())
		}
		if element.Tag == "Issuer" && element.NamespaceURI() == "urn:oasis:names:tc:SAML:2.0:assertion" {
			if issuer != "" {
				return "", "", false
			}
			issuer = strings.TrimSpace(element.Text())
		}
	}
	return nameID, issuer, nameID != "" && issuer != ""
}

func exactIdPForIssuer(records []IdPRecord, issuer string) (IdPRecord, bool) {
	var selected IdPRecord
	found := false
	for _, record := range records {
		if record.EntityID != issuer || record.TenantID == "" {
			continue
		}
		if found {
			return IdPRecord{}, false
		}
		selected, found = record, true
	}
	return selected, found
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
