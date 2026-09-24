package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type membershipController struct {
	svc    services.MembershipService
	cfg    *config.Config
	client *redis.Client
}

func NewMembershipController(svc services.MembershipService, cfg *config.Config, client *redis.Client) *membershipController {
	return &membershipController{svc: svc, cfg: cfg, client: client}
}

func (m *membershipController) Create(c *gin.Context) {
	tenantID := c.Param("tenantId")
	var req domain.MembershipCreateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if !allowCompanyAdminMembership(c, m.cfg, m.client, tenantID, req) {
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return m.svc.Create(ctx, tenantID, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidTenant, domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case domain.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

func (m *membershipController) Remove(c *gin.Context) {
	if !requireAdmin(c, m.cfg) {
		return
	}
	tenantID := c.Param("tenantId")
	var req domain.MembershipRemoveReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return m.svc.Remove(ctx, tenantID, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidTenant, domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case domain.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}
