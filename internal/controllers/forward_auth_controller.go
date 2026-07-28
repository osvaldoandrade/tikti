package controllers

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

const (
	forwardAuthAudienceHeader = "X-Tikti-Expected-Audience"
	forwardAuthTenantHeader   = "X-Tikti-Expected-Tenant"
)

type forwardAuthController struct {
	svc services.UserService
	cfg *config.Config
}

type forwardAuthCredential int

const (
	forwardAuthCredentialSession forwardAuthCredential = iota
	forwardAuthCredentialAccess
)

// NewForwardAuthController creates the authentication endpoint used by edge
// proxies before forwarding a request to a protected workload.
func NewForwardAuthController(svc services.UserService, cfg *config.Config) *forwardAuthController {
	return &forwardAuthController{svc: svc, cfg: cfg}
}

func (f *forwardAuthController) Handle(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	token, credential := f.requestToken(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authentication"})
		return
	}

	var (
		claims jwt.MapClaims
		err    error
	)
	if credential == forwardAuthCredentialAccess {
		audience := strings.TrimSpace(c.GetHeader(forwardAuthAudienceHeader))
		if audience == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication policy unavailable"})
			return
		}
		claims, err = f.validateAccessToken(c.Request.Context(), token, audience)
	} else {
		claims, err = f.validateSession(c.Request.Context(), token)
	}
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authentication"})
		return
	}

	tenant := claimString(claims, "tid")
	expectedTenant := strings.TrimSpace(c.GetHeader(forwardAuthTenantHeader))
	if expectedTenant != "" && tenant != expectedTenant {
		c.JSON(http.StatusForbidden, gin.H{"error": "tenant access denied"})
		return
	}

	subject := claimString(claims, "sub")
	if subject == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authentication"})
		return
	}
	setIdentityHeader(c, "X-Tikti-Subject", subject)
	setIdentityHeader(c, "X-Tikti-Email", claimString(claims, "email"))
	setIdentityHeader(c, "X-Tikti-Tenant", tenant)
	setIdentityHeader(c, "X-Tikti-Role", claimString(claims, "role"))
	setIdentityHeader(c, "X-Tikti-Scope", claimString(claims, "scope"))
	c.Status(http.StatusNoContent)
}

func (f *forwardAuthController) requestToken(c *gin.Context) (string, forwardAuthCredential) {
	authorization := strings.TrimSpace(c.GetHeader("Authorization"))
	if authorization != "" {
		const prefix = "bearer "
		if !strings.HasPrefix(strings.ToLower(authorization), prefix) {
			return "", forwardAuthCredentialAccess
		}
		return strings.TrimSpace(authorization[len(prefix):]), forwardAuthCredentialAccess
	}

	accessCookieName := strings.TrimSpace(f.cfg.ForwardAuth.AccessCookieName)
	if accessCookieName != "" {
		if cookie, err := c.Cookie(accessCookieName); err == nil {
			if token := strings.TrimSpace(cookie); token != "" {
				return token, forwardAuthCredentialAccess
			}
		}
	}

	cookieName := strings.TrimSpace(f.cfg.SAML.ACS.CookieName)
	if cookieName == "" {
		cookieName = "tikti_idt"
	}
	cookie, err := c.Cookie(cookieName)
	if err != nil {
		return "", forwardAuthCredentialSession
	}
	return strings.TrimSpace(cookie), forwardAuthCredentialSession
}

func (f *forwardAuthController) validateAccessToken(ctx context.Context, token string, audience string) (jwt.MapClaims, error) {
	return f.svc.ValidateAccessToken(ctx, token, f.cfg.IssuerBaseURL, audience)
}

func (f *forwardAuthController) validateSession(ctx context.Context, token string) (jwt.MapClaims, error) {
	return f.svc.ValidateIDToken(ctx, token, f.cfg.IssuerBaseURL, f.cfg.DefaultAudience)
}

func claimString(claims jwt.MapClaims, key string) string {
	value, _ := claims[key].(string)
	return strings.TrimSpace(value)
}

func setIdentityHeader(c *gin.Context, name string, value string) {
	if value != "" && !strings.ContainsAny(value, "\r\n") {
		c.Header(name, value)
	}
}
