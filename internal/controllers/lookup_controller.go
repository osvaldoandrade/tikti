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

// lookupController resolves idToken claims into stored user data.
type lookupController struct {
	userSvc services.UserService
	cfg     *config.Config
}

// NewLookupController returns a controller that can translate Firebase-style lookup calls.
func NewLookupController(svc services.UserService, cfg *config.Config) *lookupController {
	return &lookupController{userSvc: svc, cfg: cfg}
}

// Handle parses the lookup request, verifies tokens and responds with user metadata.
func (ctrl *lookupController) Handle(c *gin.Context) {
	var req domain.LookupReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	authContext := authenticationAPIRequestContext(c, ctrl.cfg)
	ch := runCommandAsync(func(context.Context) (interface{}, error) {
		return ctrl.userSvc.Lookup(authContext, req)
	})
	result := <-ch

	if err, ok := result.(error); ok {
		switch {
		case errors.Is(err, domain.ErrRateLimited):
			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, gin.H{"error": domain.ErrRateLimited.Error()})
		case errors.Is(err, domain.ErrPasswordChangeRequired):
			c.JSON(http.StatusPreconditionRequired, gin.H{"error": domain.ErrPasswordChangeRequired.Error(), "code": "PASSWORD_CHANGE_REQUIRED"})
		case errors.Is(err, domain.ErrInvalidToken), errors.Is(err, domain.ErrInvalidCreds), errors.Is(err, domain.ErrNotFound):
			c.JSON(http.StatusUnauthorized, gin.H{"error": domain.ErrInvalidToken.Error()})
		case errors.Is(err, domain.ErrAuthenticationUnavailable):
			writeAuthenticationUnavailable(c, http.StatusServiceUnavailable)
		default:
			writeAuthenticationUnavailable(c)
		}
		return
	}
	c.JSON(http.StatusOK, result)
}
