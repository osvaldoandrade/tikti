package controllers

import (
	"context"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	forwardAuthAudienceHeader  = "X-Tikti-Expected-Audience"
	forwardAuthTenantHeader    = "X-Tikti-Expected-Tenant"
	forwardAuthServicesHeader  = "X-Tikti-Allowed-Services"
	forwardAuthScopesHeader    = "X-Tikti-Required-Scopes"
	forwardAuthNamespacePrefix = "workload-"
)

var (
	forwardAuthServicePattern = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)
	forwardAuthScopePattern   = regexp.MustCompile(`^[A-Za-z0-9._:/*-]{1,128}$`)
	forwardAuthTenantPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
)

type forwardAuthController struct {
	svc         services.UserService
	workloadSvc services.WorkloadIdentityService
	cfg         *config.Config
}

type forwardAuthCredential int

const (
	forwardAuthCredentialSession forwardAuthCredential = iota
	forwardAuthCredentialAccess
)

// NewForwardAuthController creates the authentication endpoint used by edge
// proxies before forwarding a request to a protected workload.
func NewForwardAuthController(svc services.UserService, workloadSvc services.WorkloadIdentityService, cfg *config.Config) *forwardAuthController {
	return &forwardAuthController{svc: svc, workloadSvc: workloadSvc, cfg: cfg}
}

func (f *forwardAuthController) Handle(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	token, credential := f.requestToken(c)
	if token == "" {
		logForwardAuthDeny(c, credential, "missing_authentication", "")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authentication"})
		return
	}
	allowedServices, valid := forwardAuthPolicyValues(c.GetHeader(forwardAuthServicesHeader), ",", forwardAuthServicePattern)
	if !valid {
		logForwardAuthDeny(c, credential, "invalid_allowed_services_policy", "")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication policy unavailable"})
		return
	}
	requiredScopes, valid := forwardAuthPolicyValues(c.GetHeader(forwardAuthScopesHeader), " ", forwardAuthScopePattern)
	if !valid {
		logForwardAuthDeny(c, credential, "invalid_required_scopes_policy", "")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication policy unavailable"})
		return
	}

	var (
		claims            jwt.MapClaims
		err               error
		projectedWorkload bool
	)
	if credential == forwardAuthCredentialAccess {
		audience := strings.TrimSpace(c.GetHeader(forwardAuthAudienceHeader))
		if audience == "" {
			logForwardAuthDeny(c, credential, "missing_audience_policy", "")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication policy unavailable"})
			return
		}
		claims, err = f.validateAccessToken(c.Request.Context(), token, audience)
		if err != nil && len(allowedServices) > 0 && f.workloadSvc != nil {
			var subject domain.WorkloadSubject
			subject, err = f.workloadSvc.VerifyProjectedToken(c.Request.Context(), token)
			if err == nil {
				tenant, ok := workloadTenant(subject.Namespace)
				if !ok {
					c.JSON(http.StatusForbidden, gin.H{"error": "tenant access denied"})
					return
				}
				claims = jwt.MapClaims{
					"sub": subject.Subject, "tid": tenant, "service": subject.ServiceAccount,
				}
				projectedWorkload = true
			}
		}
	} else {
		claims, err = f.validateSession(c.Request.Context(), token)
	}
	if err != nil {
		logForwardAuthDeny(c, credential, "token_validation", err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authentication"})
		return
	}

	tenant := claimString(claims, "tid")
	expectedTenant := strings.TrimSpace(c.GetHeader(forwardAuthTenantHeader))
	if expectedTenant != "" && tenant != expectedTenant {
		c.JSON(http.StatusForbidden, gin.H{"error": "tenant access denied"})
		return
	}
	allowed := false
	if projectedWorkload {
		// The short-lived projected credential has no application scopes. The
		// route's explicit Service allowlist is its endpoint authorization.
		allowed = len(allowedServices) > 0 && forwardAuthServiceAllowed(claims, allowedServices)
	} else {
		allowed = forwardAuthServiceAllowed(claims, allowedServices) && forwardAuthScopesAllowed(claims, requiredScopes)
	}
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "route access denied"})
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

func logForwardAuthDeny(c *gin.Context, credential forwardAuthCredential, reason, detail string) {
	log.Printf(
		"forward auth: result=deny credential=%s reason=%s error=%q request_id=%q",
		forwardAuthCredentialName(credential),
		reason,
		detail,
		strings.TrimSpace(c.GetHeader("X-Request-Id")),
	)
}

func forwardAuthCredentialName(credential forwardAuthCredential) string {
	if credential == forwardAuthCredentialAccess {
		return "access"
	}
	return "session"
}

func workloadTenant(namespace string) (string, bool) {
	tenant := strings.TrimPrefix(strings.TrimSpace(namespace), forwardAuthNamespacePrefix)
	if tenant == namespace || !forwardAuthTenantPattern.MatchString(tenant) {
		return "", false
	}
	return tenant, true
}

func forwardAuthPolicyValues(raw, separator string, pattern *regexp.Regexp) ([]string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, true
	}
	var values []string
	if separator == " " {
		values = strings.Fields(raw)
	} else {
		values = strings.Split(raw, separator)
	}
	if len(values) == 0 || len(values) > 50 {
		return nil, false
	}
	seen := make(map[string]struct{}, len(values))
	for index := range values {
		values[index] = strings.TrimSpace(values[index])
		if !pattern.MatchString(values[index]) {
			return nil, false
		}
		if _, duplicate := seen[values[index]]; duplicate {
			return nil, false
		}
		seen[values[index]] = struct{}{}
	}
	return values, true
}

func forwardAuthServiceAllowed(claims jwt.MapClaims, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	service := claimString(claims, "service")
	if service == "" {
		parts := strings.Split(claimString(claims, "sub"), ":")
		if len(parts) == 4 && parts[0] == "system" && parts[1] == "serviceaccount" {
			service = parts[3]
		}
	}
	for _, candidate := range allowed {
		if service == candidate {
			return true
		}
	}
	return false
}

func forwardAuthScopesAllowed(claims jwt.MapClaims, required []string) bool {
	if len(required) == 0 {
		return true
	}
	granted := make(map[string]struct{})
	for _, scope := range strings.Fields(claimString(claims, "scope")) {
		granted[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, ok := granted[scope]; !ok {
			return false
		}
	}
	return true
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
