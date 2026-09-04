package controllers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type membershipController struct {
	svc services.MembershipService
	cfg *config.Config
}

func NewMembershipController(svc services.MembershipService, cfg *config.Config) *membershipController {
	return &membershipController{svc: svc, cfg: cfg}
}

func (m *membershipController) List(c *gin.Context) {
	tenantID := c.Param("tenantId")
	if !requireTenantMembershipRead(c, m.cfg, tenantID) {
		return
	}
	pageSize := int64(50)
	if raw := c.Query("pageSize"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 1 || parsed > 200 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pageSize"})
			return
		}
		pageSize = parsed
	}
	var cursor uint64
	if raw := c.Query("pageToken"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pageToken"})
			return
		}
		cursor = parsed
	}
	result, err := m.svc.List(c.Request.Context(), tenantID, cursor, pageSize)
	if err != nil {
		switch err {
		case domain.ErrInvalidTenant, domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not list tenant users"})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

func (m *membershipController) Create(c *gin.Context) {
	tenantID := c.Param("tenantId")
	if !requireTenantMembershipWrite(c, m.cfg, tenantID) {
		return
	}
	var req domain.MembershipCreateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
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
	tenantID := c.Param("tenantId")
	if !requireTenantMembershipWrite(c, m.cfg, tenantID) {
		return
	}
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
