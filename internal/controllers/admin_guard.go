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

func requireTenantIAMWrite(c *gin.Context, cfg *config.Config, tenantID string) (jwt.MapClaims, bool) {
	claims, ok := privilegedBearerClaims(c, cfg)
	if !ok {
		return nil, false
	}
	platform := hasPlatformTenantAdminProvenance(claims)
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
	platform := hasPlatformTenantAdminProvenance(claims)
	local := claimString(claims, "tid") == tenantID &&
		(hasClaimScope(claims, tenantIdentityReadScope) || hasClaimScope(claims, tenantIdentityWriteScope))
	if claimString(claims, "sub") == "" || !platform && !local {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient tenant administration scope"})
		return nil, false
	}
	return claims, true
}

// requireTenantIdentityRead authorizes compatibility reads without falling
// back to the advisory role carried by legacy identity tokens. A tenant-local
// access token is confined to its signed tid. Cross-tenant administration
// requires Tikti's provenance-bound platform privilege.
func requireTenantIdentityRead(c *gin.Context, cfg *config.Config, tenantID string) bool {
	return requireTenantIdentityAuthority(c, cfg, tenantID, false)
}

// Legacy Code Admin reads retain their established missing-authentication
// response while moving token verification and tenant authorization to the
// strict privileged path.
func requireLegacyCodeAdminTenantRead(c *gin.Context, cfg *config.Config, tenantID string) bool {
	if !legacyCodeAdminAuthenticationPresent(c) {
		return false
	}
	return requireTenantIdentityRead(c, cfg, tenantID)
}

func requireLegacyCodeAdminPlatformRead(c *gin.Context, cfg *config.Config) bool {
	if !legacyCodeAdminAuthenticationPresent(c) {
		return false
	}
	_, ok := requirePlatformTenantAdmin(c, cfg)
	return ok
}

func legacyCodeAdminAuthenticationPresent(c *gin.Context) bool {
	if strings.TrimSpace(c.GetHeader("Authorization")) != "" {
		return true
	}
	c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authentication"})
	return false
}

func requireTenantMembershipRead(c *gin.Context, cfg *config.Config, tenantID string) bool {
	return requireTenantIdentityRead(c, cfg, tenantID)
}

func requireTenantMembershipWrite(c *gin.Context, cfg *config.Config, tenantID string) bool {
	return requireTenantIdentityAuthority(c, cfg, tenantID, true)
}

func requireTenantIdentityAuthority(c *gin.Context, cfg *config.Config, tenantID string, write bool) bool {
	claims, ok := privilegedBearerClaims(c, cfg)
	if !ok {
		return false
	}
	if !canonicalMembershipTenantPath(tenantID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidArgument.Error()})
		return false
	}
	localScope := hasClaimScope(claims, tenantIdentityWriteScope)
	if !write {
		localScope = localScope || hasClaimScope(claims, tenantIdentityReadScope)
	}
	platform := hasPlatformTenantAdminProvenance(claims)
	local := localScope && claimString(claims, "tid") == tenantID
	if claimString(claims, "sub") == "" || !platform && !local {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient tenant administration scope"})
		return false
	}
	return true
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
