package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// oobSignInController authenticates users using out-of-band codes (email sign-in).
type oobSignInController struct {
	userSvc services.UserService
}

// NewOobSignInController creates a controller instance for OOB sign-in requests.
func NewOobSignInController(svc services.UserService) *oobSignInController {
	return &oobSignInController{userSvc: svc}
}

// Handle validates the request, delegates sign-in to the user service and returns a SignInResp.
func (ctrl *oobSignInController) Handle(c *gin.Context) {
	var req domain.SignInWithOobCodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return ctrl.userSvc.SignInWithOobCode(ctx, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case domain.ErrInvalidOob, domain.ErrInvalidCreds, domain.ErrNotFound:
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}
