package controllers

import (
	"context"
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
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return ctrl.userSvc.Lookup(ctx, req)
	})
	result := <-ch

	if err, ok := result.(error); ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}
