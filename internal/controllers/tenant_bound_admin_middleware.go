package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// RequireSAMLAdminReadAuthority binds a SAML read to an exact RS256 tenant
// authority before the controller can consult the IdP store.
func RequireSAMLAdminReadAuthority(cfg *config.Config) gin.HandlerFunc {
	return requireTenantBoundAdminAuthority(cfg, false)
}

// RequireSAMLAdminWriteAuthority binds SAML mutation to an exact RS256 tenant
// authority before metadata parsing or persistence.
func RequireSAMLAdminWriteAuthority(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID := c.Param("tenantId")
		claims, ok := privilegedBearerClaims(c, cfg)
		if !ok {
			c.Abort()
			return
		}
		if !canonicalTenantIDPath(tenantID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidArgument.Error()})
			c.Abort()
			return
		}
		platform := hasPlatformTenantAdminProvenance(claims)
		local := hasClaimScope(claims, tenantIdentityWriteScope) && claimString(claims, "tid") == tenantID
		if samlTrustHostsPlatformAdministrator(cfg, tenantID) {
			local = false
		}
		if claimString(claims, "sub") == "" || !platform && !local {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient SAML trust administration scope"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func samlTrustHostsPlatformAdministrator(cfg *config.Config, tenantID string) bool {
	if cfg == nil {
		return false
	}
	for _, administrator := range cfg.SAML.PlatformAdministrators {
		if administrator.TenantID == tenantID {
			return true
		}
	}
	return false
}

// RequireTenantOOBOrchestratorAuthority confines the code-bearing compatibility
// endpoint to a tenant-local writer or a provenance-bound platform operator.
func RequireTenantOOBOrchestratorAuthority(cfg *config.Config) gin.HandlerFunc {
	return requireTenantBoundAdminAuthority(cfg, true)
}

func requireTenantBoundAdminAuthority(cfg *config.Config, write bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireTenantIdentityAuthority(c, cfg, c.Param("tenantId"), write) {
			c.Abort()
			return
		}
		c.Next()
	}
}
