package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type tenantController struct {
	svc services.TenantService
	cfg *config.Config
}

func NewTenantController(svc services.TenantService, cfg *config.Config) *tenantController {
	return &tenantController{svc: svc, cfg: cfg}
}

func (t *tenantController) Create(c *gin.Context) {
	if !requireAdmin(c, t.cfg) {
		return
	}
	var req domain.TenantCreateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return t.svc.Create(ctx, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

func (t *tenantController) Get(c *gin.Context) {
	if !requireAdmin(c, t.cfg) {
		return
	}
	id := c.Param("id")
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return t.svc.Get(ctx, id)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		case domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}
