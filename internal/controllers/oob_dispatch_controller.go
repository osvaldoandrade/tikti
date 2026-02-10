package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// oobDispatchController generates OOB codes and enqueues delivery jobs in codeQ.
type oobDispatchController struct {
	userSvc services.UserService
}

func NewOobDispatchController(svc services.UserService) *oobDispatchController {
	return &oobDispatchController{userSvc: svc}
}

func (ctrl *oobDispatchController) Handle(c *gin.Context) {
	tenantID := c.Param("tenantId")
	var req domain.SendOobReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return ctrl.userSvc.SendOobForTenant(ctx, tenantID, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidTenant, domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case domain.ErrInvalidCreds:
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		case domain.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}
