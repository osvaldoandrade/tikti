package controllers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

type clientController struct {
	svc services.ClientService
	cfg *config.Config
}

func NewClientController(svc services.ClientService, cfg *config.Config) *clientController {
	return &clientController{svc: svc, cfg: cfg}
}

func (c *clientController) Create(ctx *gin.Context) {
	tenantID := ctx.Param("tenantId")
	if !requireTenantIdentityAuthority(ctx, c.cfg, tenantID, true) {
		return
	}
	var req domain.ClientCreateReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(cctx context.Context) (interface{}, error) {
		return c.svc.Create(cctx, tenantID, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch {
		case errors.Is(err, domain.ErrInvalidTenant), errors.Is(err, domain.ErrInvalidArgument):
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case errors.Is(err, domain.ErrNotFound):
			ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		case errors.Is(err, domain.ErrClientConflict), errors.Is(err, domain.ErrManagedClientConflict):
			ctx.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "could not create client"})
		}
		return
	}
	// Client secrets are returned exactly once. Prevent browsers, proxies and
	// shared gateways from persisting the successful response.
	preventSensitiveResponseCaching(ctx)
	ctx.JSON(http.StatusCreated, result)
}

func (c *clientController) Get(ctx *gin.Context) {
	tenantID := ctx.Param("tenantId")
	if _, ok := requireTenantIAMRead(ctx, c.cfg, tenantID); !ok {
		return
	}
	clientID := ctx.Param("clientId")
	ch := runCommandAsync(func(cctx context.Context) (interface{}, error) {
		return c.svc.Get(cctx, tenantID, clientID)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidTenant, domain.ErrInvalidArgument:
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case domain.ErrNotFound:
			ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		default:
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	ctx.JSON(http.StatusOK, result)
}

func (c *clientController) List(ctx *gin.Context) {
	tenantID := ctx.Param("tenantId")
	if _, ok := requireTenantIAMRead(ctx, c.cfg, tenantID); !ok {
		return
	}
	ch := runCommandAsync(func(cctx context.Context) (interface{}, error) {
		return c.svc.List(cctx, tenantID)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidTenant:
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	ctx.JSON(http.StatusOK, result)
}
