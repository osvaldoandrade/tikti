package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
)

type jwksController struct {
	svc services.UserService
}

func NewJWKSController(svc services.UserService) *jwksController {
	return &jwksController{svc: svc}
}

func (c *jwksController) Handle(ctx *gin.Context) {
	jwks, err := c.svc.JWKS(ctx.Request.Context())
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "jwks unavailable"})
		return
	}
	ctx.Header("Cache-Control", "public, max-age=300")
	ctx.JSON(http.StatusOK, jwks)
}
