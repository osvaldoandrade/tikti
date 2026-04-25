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
    <form method="get" action="/saml/discover">
        <label for="email">Work email</label>
        <input id="email" name="email" type="email" value="{{.Email}}" required>
        <button type="submit">Continue</button>
    </form>
</body>
</html>`

// discoverData holds the template data for the discover page.
type discoverData struct {
	Email string
	Error string
}

// Discover handles GET /saml/discover. Without an email parameter it renders
// the discovery form. With an email it extracts the domain, looks up the
// tenant via Store.GetDomain, and either redirects to /saml/login/{tid} or
// re-renders the form with a neutral error message.
func (h *Handler) Discover(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.URL.Query().Get("email"))

	// No email supplied — render the blank form.
	if email == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		discoverTmpl.Execute(w, discoverData{})
		return
	}

	// Extract domain from email address.
	domain := normalizeDomain(email)
	if domain == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		discoverTmpl.Execute(w, discoverData{
			Email: email,
			Error: "Please enter a valid email address.",
		})
		return
	}

	// Look up the domain in the store.
	tid, err := h.store.GetDomain(r.Context(), domain)
	if err != nil || tid == "" {
		// Unknown domain — re-render with a neutral message.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		discoverTmpl.Execute(w, discoverData{
			Email: email,
			Error: "Workspace not found.",
		})
		return
	}

	// Known domain — redirect to the login handler.
	http.Redirect(w, r, "/saml/login/"+tid, http.StatusFound)
}

// normalizeDomain extracts and lowercases the domain part of an email address.
// Returns "" if the email does not contain exactly one '@' with a non-empty domain.
func normalizeDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(email[at+1:])
}
