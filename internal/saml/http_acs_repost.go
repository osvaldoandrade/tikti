package saml

import (
	"bytes"
	"html/template"
	"net/http"
)

const (
	stateCookieRetryField      = "_tikti_state_retry"
	stateCookieRecoveryRepost  = "repost"
	stateCookieRecoverySuccess = "success"
	stateCookieRecoveryFailure = "failure"
	maxRepostResponseSize      = 2 << 20
	maxRepostRelaySize         = 8 << 10
)

const stateCookieRepostDocument = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex,nofollow">
  <title>Completing sign-in</title>
</head>
<body>
  <form id="tikti-saml-repost" method="post" action="/saml/acs">
    <input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}">
    <input type="hidden" name="RelayState" value="{{.RelayState}}">
    <input type="hidden" name="` + stateCookieRetryField + `" value="1">
    <noscript><button type="submit">Continue sign-in</button></noscript>
  </form>
  <script nonce="{{.Nonce}}">document.getElementById("tikti-saml-repost").submit();</script>
</body>
</html>`

// The template is a compile-time constant with no external functions. A parse
// failure is therefore an application invariant and must stop startup.
var stateCookieRepostTemplate = template.Must(
	template.New("saml-state-cookie-repost").Parse(stateCookieRepostDocument),
)

type stateCookieRepostData struct {
	SAMLResponse string
	RelayState   string
	Nonce        string
}

func canRepostACS(response, relay string) bool {
	return response != "" &&
		len(response) <= maxRepostResponseSize &&
		len(relay) <= maxRepostRelaySize
}

func writeStateCookieRepost(w http.ResponseWriter, response, relay string) {
	nonce := hexRandom(16)
	var body bytes.Buffer
	if err := stateCookieRepostTemplate.Execute(&body, stateCookieRepostData{
		SAMLResponse: response,
		RelayState:   relay,
		Nonce:        nonce,
	}); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'nonce-"+nonce+
			"'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	// The response has already been committed; a disconnected client is the
	// only expected write failure and there is no safe recovery path here.
	_, _ = w.Write(body.Bytes())
}

func (h *Handler) observeStateCookieRecovery(result string) {
	if h.metrics != nil && h.metrics.StateCookieRecovery != nil {
		h.metrics.StateCookieRecovery.WithLabelValues(result).Inc()
	}
}
