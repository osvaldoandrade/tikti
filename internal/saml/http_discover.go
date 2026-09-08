package saml

import (
	"html/template"
	"net/http"
	"strings"
)

// discoverTmpl is the parsed HTML template for the discover page.
// html/template auto-escapes dynamic values, preventing XSS.
var discoverTmpl = template.Must(template.New("discover").Parse(discoverHTML))

const discoverHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Tikti – Discover Workspace</title>
</head>
<body>
    <h1>Discover your workspace</h1>
    {{if .Error}}<p>{{.Error}}</p>{{end}}
    <form method="post" action="/saml/discover">
        <label for="email">Work email</label>
        <input id="email" name="email" type="email" autocomplete="email" required>
        <button type="submit">Continue</button>
    </form>
</body>
</html>`

// discoverData holds the template data for the discover page.
type discoverData struct {
	Error string
}

// Discover renders the form on GET and accepts an email only in a POST body.
// The address is never reflected into HTML or placed in a URL.
func (h *Handler) Discover(w http.ResponseWriter, r *http.Request) {
	setDiscoverSecurityHeaders(w)
	if h == nil || !h.cfg.Discover.Enabled {
		http.NotFound(w, r)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		renderDiscover(w, discoverData{})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.PostFormValue("email"))

	// Extract domain from email address.
	domain := normalizeDomain(email)
	if domain == "" {
		renderDiscover(w, discoverData{
			Error: "Please enter a valid email address.",
		})
		return
	}

	// Look up the domain in the store.
	tid, err := h.store.GetDomain(r.Context(), domain)
	if err != nil || tid == "" {
		// Unknown domain — re-render with a neutral message.
		renderDiscover(w, discoverData{
			Error: "Workspace not found.",
		})
		return
	}

	// Known domain — redirect to the login handler.
	if !adminTenantPattern.MatchString(tid) {
		renderDiscover(w, discoverData{Error: "Workspace not found."})
		return
	}
	// #nosec G710 -- tid is a strict DNS label and the target is a fixed-origin relative path.
	http.Redirect(w, r, "/saml/login/"+tid, http.StatusFound)
}

// normalizeDomain extracts and lowercases the domain part of an email address.
// Returns "" if the email does not contain exactly one '@' with a non-empty domain.
func normalizeDomain(email string) string {
	if strings.Count(email, "@") != 1 {
		return ""
	}
	at := strings.IndexByte(email, '@')
	if at < 1 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

func setDiscoverSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
}

// renderDiscover writes the discover HTML page to w. If template execution
// fails (e.g. the writer is closed), it falls back to a 500 error.
func renderDiscover(w http.ResponseWriter, data discoverData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := discoverTmpl.Execute(w, data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
