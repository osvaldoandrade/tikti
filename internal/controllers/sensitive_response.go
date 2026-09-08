package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// preventSensitiveResponseCaching applies to both success and error responses
// on credential/token endpoints so intermediaries cannot retain artifacts.
func preventSensitiveResponseCaching(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
}

func writeAuthenticationUnavailable(ctx *gin.Context, status ...int) {
	preventSensitiveResponseCaching(ctx)
	code := http.StatusInternalServerError
	if len(status) == 1 {
		code = status[0]
	}
	ctx.JSON(code, gin.H{"error": domain.ErrAuthenticationUnavailable.Error()})
}
