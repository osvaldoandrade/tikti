package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// oobDispatchController generates tenant-scoped OOB codes for an external
// orchestrator. Tikti has no in-process email or queue dispatcher.
type oobDispatchController struct {
	userSvc services.UserService
	cfg     *config.Config
}

func NewOobDispatchController(svc services.UserService, configs ...*config.Config) *oobDispatchController {
	var cfg *config.Config
	if len(configs) > 0 {
		cfg = configs[0]
	}
	return &oobDispatchController{userSvc: svc, cfg: cfg}
}

func (ctrl *oobDispatchController) Handle(c *gin.Context) {
	tenantID := c.Param("tenantId")
	var req domain.SendOobReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	authContext := authenticationAPIRequestContext(c, ctrl.cfg)
	ch := runCommandAsync(func(context.Context) (interface{}, error) {
		return ctrl.userSvc.SendOobForTenant(authContext, tenantID, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrRateLimited:
			c.Header("Retry-After", "3600")
			c.JSON(http.StatusTooManyRequests, gin.H{"error": domain.ErrRateLimited.Error()})
		case domain.ErrInvalidTenant, domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case domain.ErrInvalidCreds:
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		case domain.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": domain.ErrAuthenticationUnavailable.Error()})
		}
		return
	}
	markExternalOOBDelivery(c)
	c.JSON(http.StatusOK, result)
}
