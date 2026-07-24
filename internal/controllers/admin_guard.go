package controllers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"
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
