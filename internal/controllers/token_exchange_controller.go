package controllers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// tokenExchangeController issues scoped access tokens from idTokens.
type tokenExchangeController struct {
	userSvc services.UserService
	cfg     *config.Config
}

// NewTokenExchangeController builds a controller for token exchange.
func NewTokenExchangeController(svc services.UserService, configs ...*config.Config) *tokenExchangeController {
	var cfg *config.Config
	if len(configs) > 0 {
		cfg = configs[0]
	}
	return &tokenExchangeController{userSvc: svc, cfg: cfg}
}

// Handle validates the request and returns a scoped access token.
func (ctrl *tokenExchangeController) Handle(c *gin.Context) {
	preventSensitiveResponseCaching(c)
	var req domain.TokenExchangeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	authContext := authenticationRequestContext(c, ctrl.cfg)
	ch := runCommandAsync(func(context.Context) (interface{}, error) {
		return ctrl.userSvc.TokenExchange(authContext, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch {
		case errors.Is(err, domain.ErrRateLimited):
			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, gin.H{"error": domain.ErrRateLimited.Error()})
			return
		case errors.Is(err, domain.ErrInvalidToken), errors.Is(err, domain.ErrInvalidCreds):
			c.JSON(http.StatusUnauthorized, gin.H{"error": domain.ErrInvalidToken.Error()})
			return
		case errors.Is(err, domain.ErrUnauthorizedScope):
			c.JSON(http.StatusForbidden, gin.H{"error": domain.ErrUnauthorizedScope.Error()})
			return
		case errors.Is(err, domain.ErrInvalidAudience):
			c.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidAudience.Error()})
			return
		case errors.Is(err, domain.ErrInvalidTenant):
			c.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidTenant.Error()})
			return
		case errors.Is(err, domain.ErrInvalidArgument):
			c.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidArgument.Error()})
			return
		case errors.Is(err, domain.ErrNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": domain.ErrNotFound.Error()})
			return
		case errors.Is(err, domain.ErrAuthenticationUnavailable):
			writeAuthenticationUnavailable(c, http.StatusServiceUnavailable)
			return
		default:
			writeAuthenticationUnavailable(c)
			return
		}
	}
	c.JSON(http.StatusOK, result)
}
