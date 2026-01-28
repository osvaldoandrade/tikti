package controllers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

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
	claims, err := utils.ParseToken(tok, cfg.JwtSecret)
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
