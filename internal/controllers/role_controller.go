package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type roleController struct {
	svc services.RoleService
	cfg *config.Config
}

func NewRoleController(svc services.RoleService, cfg *config.Config) *roleController {
	return &roleController{svc: svc, cfg: cfg}
}

func (r *roleController) Create(c *gin.Context) {
	if !requireAdmin(c, r.cfg) {
		return
	}
	tenantID := c.Param("tenantId")
	var req domain.RoleCreateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return r.svc.Create(ctx, tenantID, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidTenant, domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

func (r *roleController) List(c *gin.Context) {
	if !requireAdmin(c, r.cfg) {
		return
	}
	tenantID := c.Param("tenantId")
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return r.svc.List(ctx, tenantID)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidTenant:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}
