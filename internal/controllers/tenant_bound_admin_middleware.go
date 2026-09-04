package controllers

import (
	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/pkg/config"
)

// RequireSAMLAdminReadAuthority binds a SAML read to an exact RS256 tenant
// authority before the controller can consult the IdP store.
func RequireSAMLAdminReadAuthority(cfg *config.Config) gin.HandlerFunc {
	return requireTenantBoundAdminAuthority(cfg, false)
}

// RequireSAMLAdminWriteAuthority binds SAML mutation to an exact RS256 tenant
// authority before metadata parsing or persistence.
func RequireSAMLAdminWriteAuthority(cfg *config.Config) gin.HandlerFunc {
	return requireTenantBoundAdminAuthority(cfg, true)
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
