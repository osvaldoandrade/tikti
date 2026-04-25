package saml

import (
	"net/http"
)

// Handler exposes SAML HTTP endpoints.
type Handler struct {
	prov Provider
}

// NewHandler creates a Handler backed by the given Provider.
func NewHandler(prov Provider) *Handler {
	return &Handler{prov: prov}
}

// Metadata serves the SP metadata XML document.
//
//	GET /saml/metadata
//
// Response headers:
//
//	Content-Type:  application/samlmetadata+xml; charset=utf-8
//	Cache-Control: public, max-age=86400
func (h *Handler) Metadata(w http.ResponseWriter, r *http.Request) {
	meta, err := h.prov.SPMetadata(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	w.Write(meta)
}
