package controllers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

// CurrentAccessTokenController is the private, API-key-bound authority used by
// code-admin-api before it accepts an interactive token on its own resources.
// It returns no claims so it cannot become a directory or token-introspection
// surface.
type CurrentAccessTokenController struct {
	service services.UserService
	config  *config.Config
}

func NewCurrentAccessTokenController(service services.UserService, cfg *config.Config) *CurrentAccessTokenController {
	return &CurrentAccessTokenController{service: service, config: cfg}
}

func (c *CurrentAccessTokenController) Validate(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store, no-cache, max-age=0")
	ctx.Header("Pragma", "no-cache")
	ctx.Header("X-Content-Type-Options", "nosniff")
	if c == nil || c.service == nil || c.config == nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "token authority is unavailable"})
		return
	}
	if ctx.Request.URL.RawQuery != "" || ctx.Request.ContentLength != 0 || len(ctx.Request.TransferEncoding) != 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	values := ctx.Request.Header.Values("Authorization")
	if len(values) != 1 {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid bearer token"})
		return
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 16<<10 {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid bearer token"})
		return
	}
	if _, err := c.service.ValidateAccessToken(
		ctx.Request.Context(), parts[1], c.config.IssuerBaseURL, c.config.DefaultAudience,
	); err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	ctx.Status(http.StatusNoContent)
}
