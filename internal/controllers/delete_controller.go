package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// deleteController orchestrates user deletions through the user service.
type deleteController struct {
	userSvc services.UserService
	cfg     *config.Config
}

// NewDeleteController wires dependencies for user deletion endpoints.
func NewDeleteController(svc services.UserService, cfg *config.Config) *deleteController {
	return &deleteController{userSvc: svc, cfg: cfg}
}

// Handle validates the JSON payload, invokes the deletion and returns a toolkit-style response.
func (ctrl *deleteController) Handle(c *gin.Context) {
	var req domain.DeleteReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return nil, ctrl.userSvc.DeleteUser(ctx, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"kind": "identitytoolkit#DeleteAccountResponse"})
}
