package integration

import (
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/osvaldoandrade/tikti/internal/saml"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
)

// ---------------------------------------------------------------------------
// In-memory Store (implements saml.Store without Redis)
// ---------------------------------------------------------------------------

type memStore struct {
	requests map[string]saml.RequestRecord
	idps     map[string]saml.IdPRecord
	indexes  map[string]saml.IndexRecord
	seen     map[string]bool
	domains  map[string]string
}

func newMemStore() *memStore {
	return &memStore{
		requests: make(map[string]saml.RequestRecord),
		idps:     make(map[string]saml.IdPRecord),
		indexes:  make(map[string]saml.IndexRecord),
		seen:     make(map[string]bool),
		domains:  make(map[string]string),
	}
}

func (s *memStore) PutRequest(_ context.Context, rec saml.RequestRecord) error {
	s.requests[rec.ID] = rec
	return nil
}
func (s *memStore) ConsumeRequest(_ context.Context, id string) (saml.RequestRecord, bool, error) {
	rec, ok := s.requests[id]
	if ok {
		delete(s.requests, id)
	}
	return rec, ok, nil
}
func (s *memStore) PutIdP(_ context.Context, rec saml.IdPRecord) error {
	s.idps[rec.TenantID] = rec
	return nil
}
func (s *memStore) GetIdP(_ context.Context, tid string) (saml.IdPRecord, error) {
	rec, ok := s.idps[tid]
	if !ok {
		return saml.IdPRecord{}, saml.ErrIdPNotFound
	}
	return rec, nil
}
func (s *memStore) ListIdPs(_ context.Context) ([]saml.IdPRecord, error) {
	out := make([]saml.IdPRecord, 0, len(s.idps))
	for _, r := range s.idps {
		out = append(out, r)
	}
	return out, nil
}
func (s *memStore) DeleteIdP(_ context.Context, tid string) error {
	delete(s.idps, tid)
	return nil
}
func (s *memStore) PutIndex(_ context.Context, nameID string, rec saml.IndexRecord) error {
	s.indexes[nameID] = rec
	return nil
}
func (s *memStore) GetIndex(_ context.Context, nameID string) (saml.IndexRecord, error) {
	rec, ok := s.indexes[nameID]
	if !ok {
		return saml.IndexRecord{}, saml.ErrIdPNotFound
	}
	return rec, nil
}
func (s *memStore) DeleteIndex(_ context.Context, nameID string) error {
	delete(s.indexes, nameID)
	return nil
}
func (s *memStore) MarkSeen(_ context.Context, id string, _ time.Duration) (bool, error) {
	if s.seen[id] {
		return false, nil
	}
	s.seen[id] = true
	return true, nil
}
func (s *memStore) PutDomain(_ context.Context, domain, tid string) error {
	s.domains[domain] = tid
	return nil
}
func (s *memStore) GetDomain(_ context.Context, domain string) (string, error) {
	return s.domains[domain], nil
}
func (s *memStore) DeleteDomain(_ context.Context, domain string) error {
	delete(s.domains, domain)
	return nil
}

// ---------------------------------------------------------------------------
// Stub SessionBridge + noop Emitter
// ---------------------------------------------------------------------------

type stubBridge struct{ token string }

func (b *stubBridge) Issue(_ context.Context, _ saml.IssueInput) (string, error) {
	return b.token, nil
}

type noopEmitter struct{}

func (noopEmitter) Emit(_ context.Context, _ saml.AuditRecord) error { return nil }

// ---------------------------------------------------------------------------
// Ephemeral RSA key pair
// ---------------------------------------------------------------------------

func genKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tikti-e2e-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	return key, cert
}

// ---------------------------------------------------------------------------
// Test Provider — validates SAML responses without signature verification
// ---------------------------------------------------------------------------

// testProvider wraps CrewjamProvider for request building and implements
// a lenient ValidateResponse that parses the XML without verifying
// cryptographic signatures. This keeps the tests self-contained.
type testProvider struct {
	entityID string
	acsURL   string
	sloURL   string
	key      *rsa.PrivateKey
	cert     *x509.Certificate
}

func (p *testProvider) crewjam() *saml.CrewjamProvider {
	return &saml.CrewjamProvider{
		EntityID: p.entityID,
		ACSURL:   p.acsURL,
		SLOURL:   p.sloURL,
		Key:      p.key,
		Cert:     p.cert,
	}
}

func (p *testProvider) BuildAuthnRequest(ctx context.Context, in saml.BuildAuthnRequestInput) (*saml.AuthnRequest, error) {
	return p.crewjam().BuildAuthnRequest(ctx, in)
}

func (p *testProvider) ValidateResponse(_ context.Context, in saml.ValidateResponseInput) (*saml.VerifiedAssertion, error) {
	xmlBytes, err := base64.StdEncoding.DecodeString(in.RawBase64)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	var resp xmlResponse
	if err := xml.Unmarshal(xmlBytes, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	if resp.Status.Code.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return nil, saml.ErrStatusNotSuccess
	}
	a := resp.Assertion
	attrs := make(map[string][]string)
	for _, at := range a.AttrStmt.Attrs {
		for _, v := range at.Values {
			attrs[at.Name] = append(attrs[at.Name], v.Value)
		}
	}
	notAfter := time.Now().Add(5 * time.Minute)
	if a.Conditions.NotOnOrAfter != "" {
		if t, err := time.Parse(time.RFC3339, a.Conditions.NotOnOrAfter); err == nil {
			notAfter = t
		}
	}
	return &saml.VerifiedAssertion{
		AssertionID:    a.ID,
		NameID:         a.Subject.NameID.Value,
		NameIDFormat:   a.Subject.NameID.Format,
		SessionIndex:   a.AuthnStmt.SessionIndex,
		NotOnOrAfter:   notAfter,
		Attributes:     attrs,
		IssuerEntityID: resp.Issuer,
	}, nil
}

func (p *testProvider) BuildLogoutRequest(ctx context.Context, in saml.BuildLogoutRequestInput) (*saml.LogoutRequest, error) {
	return p.crewjam().BuildLogoutRequest(ctx, in)
}

func (p *testProvider) BuildLogoutResponse(ctx context.Context, in saml.BuildLogoutResponseInput) (*saml.LogoutResponseResult, error) {
	return p.crewjam().BuildLogoutResponse(ctx, in)
}

func (p *testProvider) ValidateLogoutMessage(_ context.Context, in saml.ValidateLogoutInput) (*saml.VerifiedLogout, error) {
	xmlBytes, err := base64.StdEncoding.DecodeString(in.RawMessage)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	var probe struct{ XMLName xml.Name }
	if err := xml.Unmarshal(xmlBytes, &probe); err != nil {
		return nil, err
	}
	switch probe.XMLName.Local {
	case "LogoutResponse":
		var r xmlLogoutResp
		if err := xml.Unmarshal(xmlBytes, &r); err != nil {
			return nil, err
		}
		return &saml.VerifiedLogout{
			IsResponse: true,
			Status:     r.Status.Code.Value,
		}, nil
	case "LogoutRequest":
		var r xmlLogoutReq
		if err := xml.Unmarshal(xmlBytes, &r); err != nil {
			return nil, err
		}
		return &saml.VerifiedLogout{
			IsResponse:   false,
			NameID:       r.NameID,
			SessionIndex: r.SessionIndex,
		}, nil
	default:
		return nil, fmt.Errorf("unexpected element: %s", probe.XMLName.Local)
	}
}

func (p *testProvider) SPMetadata(_ context.Context) ([]byte, error) {
	return []byte("<EntityDescriptor/>"), nil
}

func (p *testProvider) ParseIdPMetadata(_ context.Context, _ []byte) (*saml.IdPRecord, error) {
	return nil, fmt.Errorf("not implemented")
}

// ---------------------------------------------------------------------------
// Minimal XML structs for parsing mock SAML responses
// ---------------------------------------------------------------------------

type xmlResponse struct {
	XMLName   xml.Name     `xml:"Response"`
	Issuer    string       `xml:"Issuer"`
	Status    xmlStatus    `xml:"Status"`
	Assertion xmlAssertion `xml:"Assertion"`
}
type xmlStatus struct {
	Code xmlStatusCode `xml:"StatusCode"`
}
type xmlStatusCode struct {
	Value string `xml:"Value,attr"`
}
type xmlAssertion struct {
	ID         string           `xml:"ID,attr"`
	Subject    xmlSubject       `xml:"Subject"`
	Conditions xmlConditions    `xml:"Conditions"`
	AuthnStmt  xmlAuthnStmt     `xml:"AuthnStatement"`
	AttrStmt   xmlAttrStatement `xml:"AttributeStatement"`
}
type xmlSubject struct {
	NameID xmlNameID `xml:"NameID"`
}
type xmlNameID struct {
	Value  string `xml:",chardata"`
	Format string `xml:"Format,attr"`
}
type xmlConditions struct {
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
}
type xmlAuthnStmt struct {
	SessionIndex string `xml:"SessionIndex,attr"`
}
type xmlAttrStatement struct {
	Attrs []xmlAttr `xml:"Attribute"`
}
type xmlAttr struct {
	Name   string        `xml:"Name,attr"`
	Values []xmlAttrVal  `xml:"AttributeValue"`
}
type xmlAttrVal struct {
	Value string `xml:",chardata"`
}
type xmlLogoutResp struct {
	XMLName xml.Name  `xml:"LogoutResponse"`
	Status  xmlStatus `xml:"Status"`
}
type xmlLogoutReq struct {
	XMLName      xml.Name `xml:"LogoutRequest"`
	ID           string   `xml:"ID,attr"`
	NameID       string   `xml:"NameID"`
	SessionIndex string   `xml:"SessionIndex"`
}

// ---------------------------------------------------------------------------
// Mock IdP — in-process, returns unsigned SAML responses
// ---------------------------------------------------------------------------

type mockIdP struct {
	entityID string
}

func (idp *mockIdP) samlResponseXML(inResponseTo, acsURL, nameID string, now time.Time) string {
	return fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_resp-001" Version="2.0" IssueInstant="%s"
  Destination="%s" InResponseTo="%s">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_assertion-e2e" Version="2.0" IssueInstant="%s">
    <saml:Issuer>%s</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>dGVzdA==</ds:DigestValue></ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>dGVzdA==</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotOnOrAfter="%s">
      <saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement SessionIndex="_session-e2e">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="name"><saml:AttributeValue>Test User</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`,
		now.UTC().Format(time.RFC3339),
		acsURL, inResponseTo, idp.entityID,
		now.UTC().Format(time.RFC3339), idp.entityID,
		nameID,
		now.Add(5*time.Minute).UTC().Format(time.RFC3339),
		acsURL,
		nameID,
	)
}

func (idp *mockIdP) handler(t *testing.T, spACSURL string) http.Handler {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		samlReq := r.URL.Query().Get("SAMLRequest")
		if samlReq == "" {
			http.Error(w, "missing SAMLRequest", http.StatusBadRequest)
			return
		}
		inResponseTo := deflateDecodeID(samlReq)
		relayState := r.URL.Query().Get("RelayState")

		respXML := idp.samlResponseXML(inResponseTo, spACSURL, "user@example.com", time.Now())
		respB64 := base64.StdEncoding.EncodeToString([]byte(respXML))

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>
<form id="f" method="post" action="%s">
<input type="hidden" name="SAMLResponse" value="%s"/>
<input type="hidden" name="RelayState" value="%s"/>
</form></body></html>`, spACSURL, respB64, relayState)
	})

	return mux
}

// deflateDecodeID inflates a deflate-compressed, base64-encoded
// SAMLRequest and extracts the ID attribute.
func deflateDecodeID(encoded string) string {
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "_unknown"
	}
	reader := flate.NewReader(strings.NewReader(string(compressed)))
	xmlBytes, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		return "_unknown"
	}
	var req struct {
		ID string `xml:"ID,attr"`
	}
	if err := xml.Unmarshal(xmlBytes, &req); err != nil {
		return "_unknown"
	}
	return req.ID
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

func makeTestJWT(sub string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	p := base64.RawURLEncoding.EncodeToString(
		[]byte(fmt.Sprintf(`{"sub":"%s","tid":"t-001","iat":1767225600,"exp":1767229200}`, sub)))
	return h + "." + p + ".fakesig"
}

func jwtClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		t.Fatalf("bad JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal JWT: %v", err)
	}
	return m
}

// extractFormValue extracts a hidden input value from an HTML form.
// It searches for input elements containing the given name attribute and
// extracts their value. Handles both orderings of name/value attributes.
func extractFormValue(html, name string) string {
	// Look for the input element containing name="<name>".
	needle := `name="` + name + `"`
	idx := strings.Index(html, needle)
	if idx < 0 {
		return ""
	}

	// Find the start of the <input tag containing this attribute.
	tagStart := strings.LastIndex(html[:idx], "<input")
	if tagStart < 0 {
		tagStart = strings.LastIndex(html[:idx], "<INPUT")
	}
	if tagStart < 0 {
		return ""
	}

	// Find the end of the tag ("/>").
	tagEnd := strings.Index(html[tagStart:], "/>")
	if tagEnd < 0 {
		return ""
	}
	tag := html[tagStart : tagStart+tagEnd+2]

	// Extract value="..." from the tag.
	vi := strings.Index(tag, `value="`)
	if vi < 0 {
		return ""
	}
	vs := vi + len(`value="`)
	ve := strings.Index(tag[vs:], `"`)
	if ve < 0 {
		return ""
	}
	return tag[vs : vs+ve]
}

// ---------------------------------------------------------------------------
// E2E tests
// ---------------------------------------------------------------------------

func TestSAMLE2E(t *testing.T) {
	t.Run("SSO_Flow", testSSOFlow)
	t.Run("SLO_IdPInitiated", testSLOIdPInitiated)
	t.Run("SLO_SPInitiatedTail", testSLOSPInitiatedTail)
}

// testSSOFlow drives the complete SSO flow:
//
//	Login → IdP redirect → mock SAMLResponse → ACS → idToken cookie
func testSSOFlow(t *testing.T) {
	spKey, spCert := genKeyPair(t)
	_, idpCert := genKeyPair(t)

	store := newMemStore()
	idp := &mockIdP{entityID: "https://idp.e2e.test"}

	testToken := makeTestJWT("user@example.com")

	prov := &testProvider{
		entityID: "https://sp.e2e.test/metadata",
		key:      spKey,
		cert:     spCert,
	}
	cfg := config.SAMLConfig{
		Enabled: true,
		SP: config.SPConfig{
			EntityID:       prov.entityID,
			ClockSkew:      120 * time.Second,
			RequestTTL:     300 * time.Second,
			AllowedSigAlgs: []string{"rsa-sha256"},
		},
		ACS: config.ACSConfig{
			CookieName:     "tikti_idt",
			CookieSameSite: "None",
			CookieHTTPOnly: true,
			SessionTTL:     3600,
			PostLoginURL:   "/dashboard",
		},
	}

	// Use a chi router so {tid} path params work.
	router := chi.NewRouter()
	// We'll set up routes after we know the server URL.

	sp := httptest.NewUnstartedServer(router)
	sp.Start()
	defer sp.Close()

	// Now configure URLs.
	cfg.SP.ACSURL = sp.URL + "/saml/acs"
	cfg.SP.SLOURL = sp.URL + "/saml/slo"
	prov.acsURL = cfg.SP.ACSURL
	prov.sloURL = cfg.SP.SLOURL

	handler := saml.NewHandler(saml.Deps{
		Provider: prov,
		Store:    store,
		Bridge:   &stubBridge{token: testToken},
		Clock:    saml.SystemClock{},
		Cfg:      cfg,
		Metrics:  saml.NewMetrics(prometheus.NewRegistry()),
		Audit:    noopEmitter{},
	})

	router.Get("/saml/login/{tid}", handler.Login)
	router.Post("/saml/acs", handler.ACS)
	router.Get("/saml/metadata", handler.Metadata)

	// Start mock IdP.
	idpSrv := httptest.NewServer(idp.handler(t, cfg.SP.ACSURL))
	defer idpSrv.Close()

	// Register the IdP in the store.
	if err := store.PutIdP(context.Background(), saml.IdPRecord{
		TenantID:    "t-001",
		EntityID:    idp.entityID,
		SSOURL:      idpSrv.URL + "/sso",
		SLOURL:      idpSrv.URL + "/slo",
		SigningCerts: [][]byte{idpCert.Raw},
	}); err != nil {
		t.Fatalf("PutIdP: %v", err)
	}

	// --- Drive the flow ---
	noFollow := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: GET /saml/login/t-001 → 302 to IdP SSO.
	loginResp, err := noFollow.Get(sp.URL + "/saml/login/t-001")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want 302", loginResp.StatusCode)
	}
	loc := loginResp.Header.Get("Location")
	if !strings.Contains(loc, idpSrv.URL+"/sso") {
		t.Fatalf("login redirect = %q, want IdP SSO", loc)
	}

	var stateCookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == "tikti_saml_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("tikti_saml_state cookie not set")
	}

	// Step 2: GET IdP SSO → HTML form with SAMLResponse.
	idpResp, err := http.Get(loc)
	if err != nil {
		t.Fatalf("idp sso: %v", err)
	}
	body, _ := io.ReadAll(idpResp.Body)
	idpResp.Body.Close()
	if idpResp.StatusCode != http.StatusOK {
		t.Fatalf("idp status = %d", idpResp.StatusCode)
	}

	samlResp := extractFormValue(string(body), "SAMLResponse")
	if samlResp == "" {
		t.Fatalf("no SAMLResponse in IdP form:\n%s", body)
	}

	// Step 3: POST SAMLResponse to SP ACS.
	form := url.Values{
		"SAMLResponse": {samlResp},
		"RelayState":   {""},
	}
	acsReq, _ := http.NewRequest(http.MethodPost, sp.URL+"/saml/acs",
		strings.NewReader(form.Encode()))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	acsReq.AddCookie(stateCookie)

	acsResp, err := noFollow.Do(acsReq)
	if err != nil {
		t.Fatalf("acs: %v", err)
	}
	defer acsResp.Body.Close()
	if acsResp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(acsResp.Body)
		t.Fatalf("acs status = %d, body = %s", acsResp.StatusCode, b)
	}

	// Step 4: Assert idToken cookie.
	var idtCookie *http.Cookie
	for _, c := range acsResp.Cookies() {
		if c.Name == "tikti_idt" {
			idtCookie = c
		}
	}
	if idtCookie == nil {
		t.Fatal("tikti_idt cookie not set after ACS")
	}
	claims := jwtClaims(t, idtCookie.Value)
	if sub, _ := claims["sub"].(string); sub != "user@example.com" {
		t.Errorf("sub = %q, want user@example.com", sub)
	}
	if tid, _ := claims["tid"].(string); tid != "t-001" {
		t.Errorf("tid = %q, want t-001", tid)
	}

	// Step 5: Verify session index was persisted.
	idx, err := store.GetIndex(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("session index not found after ACS: %v", err)
	}
	if idx.SessionIndex != "_session-e2e" {
		t.Errorf("session index = %q, want _session-e2e", idx.SessionIndex)
	}
}

// testSLOIdPInitiated tests IdP-initiated SLO via POST:
//
//	IdP sends LogoutRequest → SP deletes session → returns LogoutResponse
func testSLOIdPInitiated(t *testing.T) {
	spKey, spCert := genKeyPair(t)
	_, idpCert := genKeyPair(t)

	store := newMemStore()

	prov := &testProvider{
		entityID: "https://sp.e2e.test/metadata",
		key:      spKey,
		cert:     spCert,
	}

	router := chi.NewRouter()
	sp := httptest.NewUnstartedServer(router)
	sp.Start()
	defer sp.Close()

	prov.acsURL = sp.URL + "/saml/acs"
	prov.sloURL = sp.URL + "/saml/slo"

	handler := saml.NewHandler(saml.Deps{
		Provider: prov,
		Store:    store,
		Bridge:   &stubBridge{token: "unused"},
		Clock:    saml.SystemClock{},
		Cfg: config.SAMLConfig{
			SP: config.SPConfig{
				EntityID:       prov.entityID,
				AllowedSigAlgs: []string{"rsa-sha256"},
			},
			ACS: config.ACSConfig{CookieName: "tikti_idt"},
		},
		Metrics: saml.NewMetrics(prometheus.NewRegistry()),
		Audit:   noopEmitter{},
	})
	router.Get("/saml/slo", handler.SLO)
	router.Post("/saml/slo", handler.SLO)

	// Pre-populate.
	_ = store.PutIdP(context.Background(), saml.IdPRecord{
		TenantID:    "t-001",
		EntityID:    "https://idp.e2e.test",
		SLOURL:      "https://idp.e2e.test/slo",
		SigningCerts: [][]byte{idpCert.Raw},
	})
	_ = store.PutIndex(context.Background(), "user@example.com", saml.IndexRecord{
		TenantID:     "t-001",
		Subject:      "user-001",
		SessionIndex: "_session-e2e",
		NotOnOrAfter: time.Now().Add(time.Hour),
	})

	reqXML := fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_idp-slo-001" Version="2.0"
  Destination="%s/saml/slo">
  <saml:Issuer>https://idp.e2e.test</saml:Issuer>
  <saml:NameID>user@example.com</saml:NameID>
  <samlp:SessionIndex>_session-e2e</samlp:SessionIndex>
</samlp:LogoutRequest>`, sp.URL)

	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(reqXML))}}
	req, _ := http.NewRequest(http.MethodPost, sp.URL+"/saml/slo",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("slo post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("slo status = %d, body = %s", resp.StatusCode, b)
	}

	// Assert session index deleted.
	if _, err := store.GetIndex(context.Background(), "user@example.com"); err == nil {
		t.Error("session index should be deleted after IdP-initiated SLO")
	}
}

// testSLOSPInitiatedTail tests the SP-initiated SLO tail (GET with LogoutResponse):
//
//	IdP sends LogoutResponse via redirect → SP deletes session → redirects to /
func testSLOSPInitiatedTail(t *testing.T) {
	spKey, spCert := genKeyPair(t)

	store := newMemStore()

	prov := &testProvider{
		entityID: "https://sp.e2e.test/metadata",
		key:      spKey,
		cert:     spCert,
	}

	router := chi.NewRouter()
	sp := httptest.NewUnstartedServer(router)
	sp.Start()
	defer sp.Close()

	prov.acsURL = sp.URL + "/saml/acs"
	prov.sloURL = sp.URL + "/saml/slo"

	handler := saml.NewHandler(saml.Deps{
		Provider: prov,
		Store:    store,
		Bridge:   &stubBridge{token: "unused"},
		Clock:    saml.SystemClock{},
		Cfg: config.SAMLConfig{
			SP: config.SPConfig{
				EntityID:       prov.entityID,
				AllowedSigAlgs: []string{"rsa-sha256"},
			},
			ACS: config.ACSConfig{CookieName: "tikti_idt"},
		},
		Metrics: saml.NewMetrics(prometheus.NewRegistry()),
		Audit:   noopEmitter{},
	})
	router.Get("/saml/slo", handler.SLO)

	// Pre-populate.
	_ = store.PutIndex(context.Background(), "user2@example.com", saml.IndexRecord{
		TenantID:     "t-001",
		Subject:      "user-002",
		SessionIndex: "_session-002",
		NotOnOrAfter: time.Now().Add(time.Hour),
	})

	respXML := fmt.Sprintf(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_slo-resp-001" Version="2.0"
  Destination="%s/saml/slo"
  InResponseTo="_req-slo-001">
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
</samlp:LogoutResponse>`, sp.URL)

	encoded := base64.StdEncoding.EncodeToString([]byte(respXML))

	noFollow := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, _ := http.NewRequest(http.MethodGet,
		sp.URL+"/saml/slo?SAMLResponse="+url.QueryEscape(encoded), nil)
	req.AddCookie(&http.Cookie{Name: "tikti_saml_slo", Value: "user2@example.com"})

	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatalf("slo get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("slo get status = %d, body = %s", resp.StatusCode, b)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("slo redirect = %q, want /", loc)
	}

	// Assert session index deleted.
	if _, err := store.GetIndex(context.Background(), "user2@example.com"); err == nil {
		t.Error("session index should be deleted after SP-initiated SLO tail")
	}

	// Assert SLO cookie cleared.
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == "tikti_saml_slo" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("tikti_saml_slo cookie should be cleared")
	}
}
