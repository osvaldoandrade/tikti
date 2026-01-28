package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/internal/utils"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// signUpController guards user creation, ensuring only admins can provision accounts.
type signUpController struct {
	userService services.UserService
	cfg         *config.Config
}

// NewSignUpController initializes the sign-up endpoint with the service and config.
func NewSignUpController(svc services.UserService, cfg *config.Config) *signUpController {
	return &signUpController{
		userService: svc,
		cfg:         cfg,
	}
}

// Handle authenticates the caller, enforces admin-only access and forwards the request to the service.
func (ctrl *signUpController) Handle(c *gin.Context) {
	var req domain.SignUpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	idToken := c.GetHeader("Authorization")
	if idToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authentication"})
		return
	}
	claims, err := utils.ParseToken(idToken, ctrl.cfg.JwtSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	role, _ := claims["role"].(string)
	if role != "ADMIN" {
		c.JSON(http.StatusForbidden, gin.H{"error": "only admins can create users"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return ctrl.userService.SignUp(ctx, req)
	})
	result := <-ch
	if e, ok := result.(error); ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": e.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}
