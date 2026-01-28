package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// updateController enables authenticated users to change their email or password.
type updateController struct {
	userSvc services.UserService
	cfg     *config.Config
}

// NewUpdateController prepares the controller with a service and configuration.
func NewUpdateController(svc services.UserService, cfg *config.Config) *updateController {
	return &updateController{userSvc: svc, cfg: cfg}
}

// Handle validates the payload, triggers the update and emits either errors or the updated account info.
func (ctrl *updateController) Handle(c *gin.Context) {
	var req domain.UpdateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return ctrl.userSvc.UpdateUser(ctx, req)
	})
	result := <-ch

	if err, ok := result.(error); ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}
