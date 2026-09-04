package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

type validateController struct {
	svc services.UserService
	cfg *config.Config
}

func NewValidateController(svc services.UserService, cfg *config.Config) *validateController {
	return &validateController{svc: svc, cfg: cfg}
}

type validateReq struct {
	Token    string `json:"token"`
	Audience string `json:"audience"`
}

func (v *validateController) Handle(c *gin.Context) {
	if _, ok := requirePlatformTenantAdmin(c, v.cfg); !ok {
		return
	}
	var req validateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return v.svc.ValidateAccessToken(ctx, req.Token, v.cfg.IssuerBaseURL, req.Audience)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}
