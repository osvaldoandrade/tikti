package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// tokenExchangeController issues scoped access tokens from idTokens.
type tokenExchangeController struct {
	userSvc services.UserService
}

// NewTokenExchangeController builds a controller for token exchange.
func NewTokenExchangeController(svc services.UserService) *tokenExchangeController {
	return &tokenExchangeController{userSvc: svc}
}

// Handle validates the request and returns a scoped access token.
func (ctrl *tokenExchangeController) Handle(c *gin.Context) {
	var req domain.TokenExchangeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return ctrl.userSvc.TokenExchange(ctx, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidToken:
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		case domain.ErrUnauthorizedScope:
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		case domain.ErrInvalidAudience, domain.ErrInvalidTenant, domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		case domain.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	c.JSON(http.StatusOK, result)
}
