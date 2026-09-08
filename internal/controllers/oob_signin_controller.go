package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// oobSignInController authenticates users using out-of-band codes (email sign-in).
type oobSignInController struct {
	userSvc services.UserService
	cfg     *config.Config
}

// NewOobSignInController creates a controller instance for OOB sign-in requests.
func NewOobSignInController(svc services.UserService, configs ...*config.Config) *oobSignInController {
	var cfg *config.Config
	if len(configs) > 0 {
		cfg = configs[0]
	}
	return &oobSignInController{userSvc: svc, cfg: cfg}
}

// Handle validates the request, delegates sign-in to the user service and returns a SignInResp.
func (ctrl *oobSignInController) Handle(c *gin.Context) {
	preventSensitiveResponseCaching(c)
	var req domain.SignInWithOobCodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	authContext := authenticationRequestContext(c, ctrl.cfg)
	ch := runCommandAsync(func(context.Context) (interface{}, error) {
		return ctrl.userSvc.SignInWithOobCode(authContext, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrRateLimited:
			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, gin.H{"error": domain.ErrRateLimited.Error()})
		case domain.ErrPasswordChangeRequired:
			c.JSON(http.StatusPreconditionRequired, gin.H{"error": err.Error(), "code": "PASSWORD_CHANGE_REQUIRED"})
		case domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case domain.ErrInvalidOob, domain.ErrInvalidCreds, domain.ErrNotFound:
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		case domain.ErrAuthenticationUnavailable:
			c.JSON(http.StatusInternalServerError, gin.H{"error": domain.ErrAuthenticationUnavailable.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": domain.ErrAuthenticationUnavailable.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}
