package controllers

import (
	"crypto/subtle"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type TemporaryPasswordController struct {
	service    services.TemporaryPasswordService
	privateKey string
}

func NewTemporaryPasswordController(service services.TemporaryPasswordService, privateKey string) *TemporaryPasswordController {
	return &TemporaryPasswordController{service: service, privateKey: privateKey}
}

func (ctrl *TemporaryPasswordController) AdminSet(c *gin.Context) {
	provided := c.GetHeader("X-Password-Reset-Service-Key")
	if ctrl.privateKey == "" || len(provided) != len(ctrl.privateKey) || subtle.ConstantTimeCompare([]byte(provided), []byte(ctrl.privateKey)) != 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req domain.AdminTemporaryPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	err := ctrl.service.SetTemporaryPassword(c.Request.Context(), req)
	switch {
	case err == nil:
		c.Status(http.StatusNoContent)
	case errors.Is(err, domain.ErrInvalidArgument):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
	case errors.Is(err, domain.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
	default:
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "password service unavailable"})
	}
}

func (ctrl *TemporaryPasswordController) Change(c *gin.Context) {
	var req domain.TemporaryPasswordChangeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	err := ctrl.service.ChangeTemporaryPassword(c.Request.Context(), req)
	switch {
	case err == nil:
		c.Status(http.StatusNoContent)
	case errors.Is(err, domain.ErrInvalidArgument):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
	case errors.Is(err, domain.ErrInvalidCreds):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid temporary password"})
	default:
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "password service unavailable"})
	}
}
