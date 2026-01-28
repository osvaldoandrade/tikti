package controllers

import (
	"context"
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
	var req domain.SignInReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(context.Context) (interface{}, error) {
		return ctrl.userSvc.SignIn(context.Background(), req)
	})
	result := <-ch
	if e, ok := result.(error); ok {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": e.Error()})
		return
	}
	ctx.JSON(http.StatusOK, result)
}
