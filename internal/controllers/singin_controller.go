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

// SignInController authenticates users and returns Firebase-compatible tokens.
type SignInController struct {
	userSvc services.UserService
	cfg     *config.Config
}

// NewSignInController creates a controller instance that can service sign-in requests.
func NewSignInController(u services.UserService, c *config.Config) *SignInController {
	return &SignInController{userSvc: u, cfg: c}
}

// Handle binds request JSON, authenticates with the user service and returns the response.
func (ctrl *SignInController) Handle(ctx *gin.Context) {
	preventSensitiveResponseCaching(ctx)
	var req domain.SignInReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	authContext := authenticationRequestContext(ctx, ctrl.cfg)
	ch := runCommandAsync(func(context.Context) (interface{}, error) {
		return ctrl.userSvc.SignIn(authContext, req)
	})
	result := <-ch
	if e, ok := result.(error); ok {
		switch {
		case errors.Is(e, domain.ErrRateLimited):
			ctx.JSON(http.StatusTooManyRequests, gin.H{"error": domain.ErrRateLimited.Error()})
		case errors.Is(e, domain.ErrPasswordChangeRequired):
			ctx.JSON(http.StatusPreconditionRequired, gin.H{"error": domain.ErrPasswordChangeRequired.Error(), "code": "PASSWORD_CHANGE_REQUIRED"})
		case errors.Is(e, domain.ErrInvalidCreds), errors.Is(e, domain.ErrInvalidToken):
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": domain.ErrInvalidCreds.Error()})
		case errors.Is(e, domain.ErrAuthenticationUnavailable):
			writeAuthenticationUnavailable(ctx, http.StatusServiceUnavailable)
		default:
			writeAuthenticationUnavailable(ctx)
		}
		return
	}
	ctx.JSON(http.StatusOK, result)
}
