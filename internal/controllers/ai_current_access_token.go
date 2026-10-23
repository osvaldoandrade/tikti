package controllers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// AICurrentAccessTokenController is machine-only, behind the existing API-key
// middleware. It returns no claims and never treats a request body as identity.
type AICurrentAccessTokenController struct{ validator services.AIUserTokenValidator }

func NewAICurrentAccessTokenController(validator services.AIUserTokenValidator) *AICurrentAccessTokenController {
	return &AICurrentAccessTokenController{validator: validator}
}

func (c *AICurrentAccessTokenController) Validate(ctx *gin.Context) {
	preventSensitiveResponseCaching(ctx)
	ctx.Header("X-Content-Type-Options", "nosniff")
	r := ctx.Request
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || r.Body != nil && r.Body != http.NoBody || len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Cookie")) != 0 {
		ctx.Status(http.StatusBadRequest)
		return
	}
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		ctx.Status(http.StatusUnauthorized)
		return
	}
	parts := strings.Split(headers[0], " ")
	if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" || len(parts[1]) > 16384 || strings.ContainsAny(parts[1], "\t\r\n") {
		ctx.Status(http.StatusUnauthorized)
		return
	}
	if c == nil || c.validator == nil {
		ctx.Status(http.StatusServiceUnavailable)
		return
	}
	if _, err := c.validator.ValidateAIAccessToken(r.Context(), parts[1]); err != nil {
		if errors.Is(err, domain.ErrAuthenticationUnavailable) {
			ctx.Status(http.StatusServiceUnavailable)
		} else {
			ctx.Status(http.StatusUnauthorized)
		}
		return
	}
	ctx.Status(http.StatusNoContent)
}
