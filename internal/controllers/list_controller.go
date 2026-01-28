package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

// listController returns non-sensitive snapshots of all users (mainly for debugging).
type listController struct {
	userSvc services.UserService
	cfg     *config.Config
}

// NewListController wires the list endpoint with the service and config.
func NewListController(u services.UserService, c *config.Config) *listController {
	return &listController{userSvc: u, cfg: c}
}

// Handle triggers the asynchronous fetch and relays errors or serialized users.
func (ctrl *listController) Handle(c *gin.Context) {
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return ctrl.userSvc.GetAllUsers(ctx)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}
