package controllers

import (
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	platformTenantAdminScope = domain.PlatformTenantAdminScope
	tenantIdentityReadScope  = "code-admin:identity:read"
	tenantIdentityWriteScope = "code-admin:identity:write"
)

func requireAdmin(c *gin.Context, cfg *config.Config) bool {
	tok := strings.TrimSpace(c.GetHeader("Authorization"))
	if tok == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authentication"})
		return false
	}
	if strings.HasPrefix(strings.ToLower(tok), "bearer ") {
		tok = strings.TrimSpace(tok[7:])
	}
	claims, err := adminClaims(tok, cfg)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return false
	}
	role, _ := claims["role"].(string)
	if role != "ADMIN" {
		c.JSON(http.StatusForbidden, gin.H{"error": "only admins can perform this action"})
		return false
	}
	return true
}

func adminClaims(token string, cfg *config.Config) (jwt.MapClaims, error) {
	claims, err := utils.ParseToken(token, cfg.JwtSecret)
	if err == nil {
		return claims, nil
	}
	key, keyErr := utils.ParseRSAPrivateKey(cfg.JwksPrivateKey)
	if keyErr != nil {
		return nil, err
	}
	return utils.ValidateRS256(token, &key.PublicKey, cfg.IssuerBaseURL, cfg.DefaultAudience)
}

func requireTenantIAMWrite(c *gin.Context, cfg *config.Config, tenantID string) (jwt.MapClaims, bool) {
	claims, ok := privilegedBearerClaims(c, cfg)
	if !ok {
		return nil, false
	}
	platform := hasClaimScope(claims, platformTenantAdminScope)
	local := hasClaimScope(claims, tenantIdentityWriteScope) && claimString(claims, "tid") == tenantID
	if claimString(claims, "sub") == "" || !platform && !local {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient tenant administration scope"})
		return nil, false
	}
	return claims, true
}

func requirePlatformTenantAdmin(c *gin.Context, cfg *config.Config) (jwt.MapClaims, bool) {
	claims, ok := privilegedBearerClaims(c, cfg)
	if !ok {
		return nil, false
	}
	if claimString(claims, "sub") == "" || !hasPlatformTenantAdminProvenance(claims) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient platform tenant administration scope"})
		return nil, false
	}
	return claims, true
}

func requireTenantIAMRead(c *gin.Context, cfg *config.Config, tenantID string) (jwt.MapClaims, bool) {
	claims, ok := privilegedBearerClaims(c, cfg)
	if !ok {
		return nil, false
	}
	platform := hasClaimScope(claims, platformTenantAdminScope)
	local := claimString(claims, "tid") == tenantID &&
		(hasClaimScope(claims, tenantIdentityReadScope) || hasClaimScope(claims, tenantIdentityWriteScope))
	if claimString(claims, "sub") == "" || !platform && !local {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient tenant administration scope"})
		return nil, false
	}
	return claims, true
}

func privilegedBearerClaims(c *gin.Context, cfg *config.Config) (jwt.MapClaims, bool) {
	parts := strings.Fields(c.GetHeader("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid bearer token"})
		return nil, false
	}
	claims, err := strictAdminClaims(parts[1], cfg)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return nil, false
	}
	return claims, true
}

func strictAdminClaims(token string, cfg *config.Config) (jwt.MapClaims, error) {
	key, err := utils.ParseRSAPrivateKey(cfg.JwksPrivateKey)
	if err != nil {
		return nil, err
	}
	return utils.ValidateRS256(token, &key.PublicKey, cfg.IssuerBaseURL, cfg.DefaultAudience)
}

func hasClaimScope(claims jwt.MapClaims, required string) bool {
	return slices.Contains(strings.Fields(claimString(claims, "scope")), required)
}

func hasPlatformTenantAdminProvenance(claims jwt.MapClaims) bool {
	return hasClaimScope(claims, platformTenantAdminScope) &&
		claimString(claims, "role") == string(domain.RoleAdmin) &&
		claimString(claims, domain.PlatformPrivilegeClaim) == domain.PlatformPrivilegeAdmin
}

func dynamicPlatformTenantTargetAllowed(cfg *config.Config, claims jwt.MapClaims) bool {
	return cfg != nil && cfg.TenantTargetDiscoveryV2 &&
		slices.Contains(cfg.TenantTargetDiscoveryV2PrincipalTenants, claimString(claims, "tid")) &&
		hasPlatformTenantAdminProvenance(claims)
}

func dynamicLocalTenantTargetAllowed(cfg *config.Config, claims jwt.MapClaims, tenantID string, scopes ...string) bool {
	if cfg == nil || !cfg.TenantTargetDiscoveryV2 || claimString(claims, "tid") != tenantID {
		return false
	}
	for _, scope := range scopes {
		if hasClaimScope(claims, scope) {
			return true
		}
	}
	return false
}
