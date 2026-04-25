package saml

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

// Deps bundles all external dependencies for the SAML Handler.
type Deps struct {
	Provider  Provider
	Store     Store
	Bridge    SessionBridge
	Clock     Clock
	Cfg       config.SAMLConfig
	Metrics   *Metrics
	Audit     Emitter
	JwtSecret string
}

// Handler serves the SAML HTTP endpoints.
type Handler struct {
	prov      Provider
	store     Store
	bridge    SessionBridge
	clock     Clock
	cfg       config.SAMLConfig
	metrics   *Metrics
	audit     Emitter
	jwtSecret string
}

// NewHandler returns a Handler wired with the given dependencies.
func NewHandler(d Deps) *Handler {
	return &Handler{
		prov:      d.Provider,
		store:     d.Store,
		bridge:    d.Bridge,
		clock:     d.Clock,
		cfg:       d.Cfg,
		metrics:   d.Metrics,
		audit:     d.Audit,
		jwtSecret: d.JwtSecret,
	}
}

// renderError writes a neutral error page. The bucket and HTTP status are
// derived from the Reason per HLD Appendix Q.
func (h *Handler) renderError(w http.ResponseWriter, _ *http.Request, _ Reason, status int) {
	http.Error(w, http.StatusText(status), status)
}

// subjectFromToken parses an HS256 idToken and returns the "sub" claim.
func subjectFromToken(token, secret string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("saml: empty token")
	}
	if secret == "" {
		secret = "supersecret"
	}
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("saml: unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil || !parsed.Valid {
		return "", errors.New("saml: invalid token")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("saml: invalid claims")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", errors.New("saml: no subject in token")
	}
	return sub, nil
}

// hexRandom returns n random bytes encoded as a hex string.
func hexRandom(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("saml: rand.Read failed: " + err.Error())
	}
	return hex.EncodeToString(buf)
}
