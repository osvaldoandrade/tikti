package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const oobDeliveryContractHeader = "X-Tikti-OOB-Delivery"

// oobSendController issues out-of-band codes for email verification or password recovery.
type oobSendController struct {
	userSvc services.UserService
	cfg     *config.Config
}

// oobResetController consumes OOB codes to reset user passwords.
type oobResetController struct {
	userSvc services.UserService
	cfg     *config.Config
}

// NewOobSendController builds the compatibility controller that generates OOB
// codes for an external delivery orchestrator.
func NewOobSendController(svc services.UserService, cfg *config.Config) *oobSendController {
	return &oobSendController{userSvc: svc, cfg: cfg}
}

// NewOobResetController builds the controller used to reset passwords with received codes.
func NewOobResetController(svc services.UserService, cfg *config.Config) *oobResetController {
	return &oobResetController{userSvc: svc, cfg: cfg}
}

// Handle validates generation requests and returns the generated code. Tikti
// does not currently dispatch email, so the response explicitly advertises
// the external-delivery compatibility contract and must never be cached.
func (ctrl *oobSendController) Handle(c *gin.Context) {
	var req domain.SendOobReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return ctrl.userSvc.SendOob(ctx, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case domain.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	markExternalOOBDelivery(c)
	c.JSON(http.StatusOK, result)
}

func markExternalOOBDelivery(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header(oobDeliveryContractHeader, "external-required")
}

// Handle validates reset payloads, delegates the reset and emits a toolkit-compatible response.
func (ctrl *oobResetController) Handle(c *gin.Context) {
	var req domain.ResetPwdReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return nil, ctrl.userSvc.ResetPassword(ctx, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case domain.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"kind": "identitytoolkit#SetAccountPasswordResponse"})
}
