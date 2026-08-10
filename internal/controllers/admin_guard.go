package controllers

import (
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

const (
	platformTenantAdminScope = "code-admin:tenants:admin"
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
