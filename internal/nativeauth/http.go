package nativeauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/osvaldoandrade/tikti/internal/nativepolicy"
)

const PublicPrefix = "/identity/v1/native/"

type AttemptLimiter interface {
	AllowAuthenticationAttempt(context.Context, string, string, int, time.Duration) (bool, error)
}

type AuditRecord struct {
	Event            string `json:"event"`
	Phase            string `json:"phase"`
	Decision         string `json:"decision"`
	ClientID         string `json:"clientId"`
	TenantID         string `json:"tenantId"`
	IdentityTenantID string `json:"identityTenantId"`
	SubjectHash      string `json:"subjectHash,omitempty"`
	Timestamp        string `json:"timestamp"`
}

type Auditor interface {
	Emit(context.Context, AuditRecord) error
}

type HTTPOptions struct {
	Issuer       string
	CookieName   string
	CSRFKey      []byte
	Clients      *nativepolicy.Registry
	Store        *Store
	Authority    Authority
	Audit        Auditor
	Limiter      AttemptLimiter
	ResolveIP    func(*http.Request) string
	RateRequests int
	RateWindow   time.Duration
}

type Handler struct{ options HTTPOptions }

func NewHandler(options HTTPOptions) (*Handler, error) {
	origin, err := url.Parse(options.Issuer)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" ||
		(origin.Path != "" && origin.Path != "/") || len(options.CSRFKey) < 32 || options.CookieName == "" ||
		options.Clients == nil || options.Store == nil || options.Authority == nil || options.Audit == nil || options.Limiter == nil || options.ResolveIP == nil ||
		options.RateRequests < 1 || options.RateWindow < time.Second {
		return nil, ErrUnavailable
	}
	options.CSRFKey = append([]byte(nil), options.CSRFKey...)
	return &Handler{options: options}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	styleHash := sha256.Sum256([]byte(consentStyle))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'sha256-"+base64.StdEncoding.EncodeToString(styleHash[:])+"'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	// Dispatch before Gin/CORS: neither redirects nor preflights may forward
	// a native credential to another path or expose it to browser scripts.
	path := strings.TrimPrefix(r.URL.Path, PublicPrefix)
	if path == r.URL.Path {
		path = strings.TrimPrefix(r.URL.Path, "/v1/native/")
	}
	if r.URL.RawPath != "" || strings.Contains(path, "/") && !strings.HasPrefix(path, "clients/") {
		fail(w, http.StatusNotFound, "invalid_request")
		return
	}
	if strings.HasPrefix(path, "clients/") && r.Method == http.MethodGet {
		id := strings.TrimPrefix(path, "clients/")
		client, ok := h.options.Clients.Get(id)
		if !ok || r.URL.RawQuery != "" {
			fail(w, 404, "invalid_client")
			return
		}
		writeJSON(w, 200, map[string]any{
			"issuer": h.options.Issuer, "client_id": client.ID, "tenant_id": client.TenantID, "audience": client.Audience,
			"authorization_endpoint": strings.TrimSuffix(h.options.Issuer, "/") + PublicPrefix + "authorize",
			"token_endpoint":         strings.TrimSuffix(h.options.Issuer, "/") + PublicPrefix + "token",
			"redirect_path":          client.RedirectPath, "code_challenge_methods_supported": []string{"S256"},
		})
		return
	}
	wantedMethod := http.MethodGet
	if path == "token" || path == "consent" {
		wantedMethod = http.MethodPost
	}
	if path != "authorize" && path != "resume" && path != "consent" && path != "token" {
		fail(w, 404, "invalid_request")
		return
	}
	if r.Method != wantedMethod {
		fail(w, 405, "invalid_request")
		return
	}
	allowed, err := h.options.Limiter.AllowAuthenticationAttempt(r.Context(), "native:"+path+":ip", h.options.ResolveIP(r), h.options.RateRequests, h.options.RateWindow)
	if err != nil {
		fail(w, 503, "temporarily_unavailable")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(h.options.RateWindow.Seconds())))
		fail(w, 429, "temporarily_unavailable")
		return
	}
	switch path {
	case "authorize":
		h.authorize(w, r)
	case "resume":
		h.resume(w, r)
	case "consent":
		h.consent(w, r)
	case "token":
		h.token(w, r)
	}
}

func strictValues(raw string, fields ...string) (url.Values, bool) {
	if len(raw) > 8192 {
		return nil, false
	}
	values, err := url.ParseQuery(raw)
	if err != nil || len(values) != len(fields) {
		return nil, false
	}
	for _, field := range fields {
		value := values[field]
		if len(value) != 1 || value[0] == "" {
			return nil, false
		}
	}
	return values, true
}

func readForm(w http.ResponseWriter, r *http.Request, fields ...string) (url.Values, bool) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil {
		return nil, false
	}
	return strictValues(r.PostForm.Encode(), fields...)
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	values, ok := strictValues(r.URL.RawQuery, "client_id", "response_type", "redirect_uri", "state", "code_challenge", "code_challenge_method")
	if !ok {
		fail(w, 400, "invalid_request")
		return
	}
	client, registered := h.options.Clients.Get(values.Get("client_id"))
	if !registered || client.ValidateRedirect(values.Get("redirect_uri")) != nil || values.Get("response_type") != "code" ||
		values.Get("code_challenge_method") != "S256" || !nativepolicy.ValidS256Challenge(values.Get("code_challenge")) || !nativepolicy.ValidState(values.Get("state")) {
		fail(w, 400, "invalid_request")
		return
	}
	policy, _ := client.Fingerprint()
	id, err := h.options.Store.CreateRequest(r.Context(), Request{ClientID: client.ID, ClientFingerprint: policy,
		RedirectURI: values.Get("redirect_uri"), State: values.Get("state"), Challenge: values.Get("code_challenge")})
	if err != nil {
		nativeFailure(w, err)
		return
	}
	h.showConsent(w, r, id, client)
}

func (h *Handler) request(r *http.Request, id string) (RequestSnapshot, nativepolicy.Client, error) {
	snapshot, err := h.options.Store.Request(r.Context(), id)
	if err != nil {
		return RequestSnapshot{}, nativepolicy.Client{}, err
	}
	client, ok := h.options.Clients.Get(snapshot.Value.ClientID)
	policy, policyErr := client.Fingerprint()
	if !ok || policyErr != nil || policy != snapshot.Value.ClientFingerprint || client.ValidateRedirect(snapshot.Value.RedirectURI) != nil {
		return RequestSnapshot{}, nativepolicy.Client{}, ErrInvalidGrant
	}
	return snapshot, client, nil
}

func (h *Handler) resume(w http.ResponseWriter, r *http.Request) {
	values, ok := strictValues(r.URL.RawQuery, "request")
	if !ok {
		fail(w, 400, "invalid_request")
		return
	}
	_, client, err := h.request(r, values.Get("request"))
	if err != nil {
		nativeFailure(w, err)
		return
	}
	h.showConsent(w, r, values.Get("request"), client)
}

func (h *Handler) session(r *http.Request) string {
	var value string
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == h.options.CookieName {
			count++
			value = cookie.Value
		}
	}
	if count != 1 || len(value) > 32768 {
		return ""
	}
	return value
}

func (h *Handler) csrf(id string, identity Identity, session string) string {
	mac := hmac.New(sha256.New, h.options.CSRFKey)
	cookieHash := sha256.Sum256([]byte(session))
	_, _ = mac.Write([]byte("native-consent-csrf-v1\x00" + id + "\x00" + identity.Fingerprint() + "\x00" + strconv.FormatInt(identity.TokenVersion, 10) + "\x00"))
	_, _ = mac.Write(cookieHash[:])
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

const consentStyle = `:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;padding:32px 16px;background:#101719;color:#edf4f4;font:16px/1.6 system-ui,sans-serif}main{max-width:580px;margin:6vh auto;padding:28px;border:1px solid #526164;border-radius:12px;background:#1a2528}h1{font-size:26px;line-height:1.25;margin:0 0 24px}p{overflow-wrap:anywhere}ul{padding-left:24px}form{display:flex;gap:12px;flex-wrap:wrap;margin-top:28px}button{min-height:44px;padding:10px 18px;border:1px solid #829598;border-radius:6px;font:inherit;cursor:pointer;background:#1a2528;color:#edf4f4}button[value=approve]{background:#8ee1d2;border-color:#8ee1d2;color:#0b2823;font-weight:600}button:focus-visible{outline:3px solid #e3b66d;outline-offset:4px}@media(max-width:420px){main{padding:20px;margin:2vh auto}button{width:100%}}`

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Entrar em {{.App}}</title><style>` + consentStyle + `</style><main><h1>Entrar em {{.App}}</h1><p>Conta: {{.Email}}</p><p>Organização: {{.Tenant}} ({{.TenantID}})</p><p>Ao continuar, esta aplicação poderá:</p><ul>{{range .Permissions}}<li>{{.}}</li>{{end}}</ul><form action="/identity/v1/native/consent" method="post"><input type="hidden" name="request" value="{{.Request}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><button name="decision" value="approve" type="submit">Continuar para {{.App}}</button> <button name="decision" value="deny" type="submit">Cancelar</button></form></main></html>`))

func permissionLabels(scopes []string) []string {
	labels := map[string]string{
		"code-forge-desktop:session": "Manter sua sessão no Code Forge", "code-forge:access": "Acessar sua organização no Code Forge",
		"code-forge:workspace:read": "Consultar arquivos e iniciativas", "code-forge:workspace:write": "Criar e editar arquivos e iniciativas",
		"code-forge:planner:read": "Consultar planos de trabalho", "code-forge:planner:write": "Criar e editar planos de trabalho",
		"code-forge:terminal:run": "Executar comandos no terminal", "code-forge:code:execute": "Executar código",
		"code-forge:ai:use": "Usar os recursos de inteligência artificial", "code-forge:secrets:manage": "Gerenciar credenciais dos serviços de IA",
		"code-forge:github:connect": "Conectar sua conta do GitHub", "code-forge:github:write": "Publicar alterações no GitHub",
	}
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		label := labels[scope]
		if label == "" {
			label = scope
		}
		result = append(result, label)
	}
	return result
}

func (h *Handler) showConsent(w http.ResponseWriter, r *http.Request, id string, client nativepolicy.Client) {
	session := h.session(r)
	identity, err := h.options.Authority.BrowserIdentity(r.Context(), session, client)
	if errors.Is(err, ErrNoSession) {
		relay := PublicPrefix + "resume?request=" + url.QueryEscape(id)
		http.Redirect(w, r, "/saml/login/"+client.IdentityTenantID+"?RelayState="+url.QueryEscape(relay), http.StatusSeeOther)
		return
	}
	if err != nil {
		nativeFailure(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentTemplate.Execute(w, map[string]any{"App": client.Name, "Email": identity.Email, "Tenant": identity.TenantName, "TenantID": client.TenantID,
		"Permissions": permissionLabels(identity.Scopes), "Request": id, "CSRF": h.csrf(id, identity, session)})
}

func (h *Handler) audit(ctx context.Context, event, phase, decision string, client nativepolicy.Client, identity Identity) error {
	digest := sha256.Sum256([]byte("native-audit-subject-v1\x00" + identity.IdentityTenantID + "\x00" + identity.Subject))
	return h.options.Audit.Emit(ctx, AuditRecord{Event: event, Phase: phase, Decision: decision, ClientID: client.ID, TenantID: client.TenantID,
		IdentityTenantID: client.IdentityTenantID, SubjectHash: fmt.Sprintf("%x", digest[:]), Timestamp: time.Now().UTC().Format(time.RFC3339Nano)})
}

func (h *Handler) consent(w http.ResponseWriter, r *http.Request) {
	origin := strings.TrimSuffix(h.options.Issuer, "/")
	if r.Header.Get("Origin") != origin || len(r.Header.Values("Origin")) != 1 {
		fail(w, 403, "access_denied")
		return
	}
	values, ok := readForm(w, r, "request", "csrf", "decision")
	if !ok || values.Get("decision") != "approve" && values.Get("decision") != "deny" {
		fail(w, 400, "invalid_request")
		return
	}
	id := values.Get("request")
	snapshot, client, err := h.request(r, id)
	if err != nil {
		nativeFailure(w, err)
		return
	}
	session := h.session(r)
	identity, err := h.options.Authority.BrowserIdentity(r.Context(), session, client)
	if err != nil {
		nativeFailure(w, err)
		return
	}
	if !hmac.Equal([]byte(values.Get("csrf")), []byte(h.csrf(id, identity, session))) {
		fail(w, 403, "access_denied")
		return
	}
	decision := values.Get("decision")
	if h.audit(r.Context(), "native.consent", "intent", decision, client, identity) != nil {
		fail(w, 503, "temporarily_unavailable")
		return
	}
	consumed, err := h.options.Store.ConsumeRequest(r.Context(), id, snapshot)
	if err != nil {
		nativeFailure(w, err)
		return
	}
	if !consumed {
		fail(w, 400, "invalid_grant")
		return
	}
	callback, _ := url.Parse(snapshot.Value.RedirectURI)
	query := url.Values{"state": {snapshot.Value.State}, "iss": {h.options.Issuer}}
	if decision == "deny" {
		query.Set("error", "access_denied")
	} else {
		code, err := h.options.Store.CreateCode(r.Context(), Grant{
			ClientID: client.ID, ClientFingerprint: snapshot.Value.ClientFingerprint, RedirectURI: snapshot.Value.RedirectURI,
			Challenge: snapshot.Value.Challenge, Subject: identity.Subject, IdentityTenantID: identity.IdentityTenantID,
			IdentityFingerprint: identity.Fingerprint(), TokenVersion: identity.TokenVersion, ApprovedScopes: identity.Scopes, SessionExpiresAt: identity.SessionExpiresAt,
		})
		if err != nil {
			nativeFailure(w, err)
			return
		}
		query.Set("code", code)
	}
	if h.audit(r.Context(), "native.consent", "outcome", decision, client, identity) != nil {
		fail(w, 503, "temporarily_unavailable")
		return
	}
	callback.RawQuery = query.Encode()
	http.Redirect(w, r, callback.String(), http.StatusSeeOther)
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values("Origin")) != 0 || r.Header.Get("Authorization") != "" {
		fail(w, 400, "invalid_request")
		return
	}
	values, ok := readForm(w, r, "grant_type", "client_id", "code", "redirect_uri", "code_verifier")
	if !ok || values.Get("grant_type") != "authorization_code" {
		fail(w, 400, "invalid_request")
		return
	}
	snapshot, err := h.options.Store.Code(r.Context(), values.Get("code"))
	if err != nil {
		nativeFailure(w, err)
		return
	}
	grant := snapshot.Value
	client, exists := h.options.Clients.Get(values.Get("client_id"))
	policy, policyErr := client.Fingerprint()
	if !exists || policyErr != nil || client.ID != grant.ClientID || policy != grant.ClientFingerprint || values.Get("redirect_uri") != grant.RedirectURI ||
		client.ValidateRedirect(grant.RedirectURI) != nil || !nativepolicy.VerifyS256(values.Get("code_verifier"), grant.Challenge) {
		fail(w, 400, "invalid_grant")
		return
	}
	identity := Identity{Subject: grant.Subject, IdentityTenantID: grant.IdentityTenantID}
	if h.audit(r.Context(), "native.token", "intent", "approve", client, identity) != nil {
		fail(w, 503, "temporarily_unavailable")
		return
	}
	consumed, err := h.options.Store.ConsumeCode(r.Context(), values.Get("code"), snapshot)
	if err != nil {
		nativeFailure(w, err)
		return
	}
	if !consumed {
		fail(w, 400, "invalid_grant")
		return
	}
	token, err := h.options.Authority.IssueNativeToken(r.Context(), client, grant)
	if err != nil {
		nativeFailure(w, err)
		return
	}
	if h.audit(r.Context(), "native.token", "outcome", "approve", client, identity) != nil {
		fail(w, 503, "temporarily_unavailable")
		return
	}
	writeJSON(w, 200, token)
}

func nativeFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnavailable):
		fail(w, 503, "temporarily_unavailable")
	case errors.Is(err, ErrAccessDenied), errors.Is(err, ErrNoSession):
		fail(w, 403, "access_denied")
	default:
		fail(w, 400, "invalid_grant")
	}
}

func fail(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
