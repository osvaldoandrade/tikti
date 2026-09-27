package app

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const codeQTopicAuthorityPath = "/v1/internal/codeq/topic-authority"

type codeQTopicValidator interface {
	ValidateCodeQTopicToken(context.Context, string) (services.CodeQTopicAuthority, error)
}

func setupCodeQTopicAuthority(engine *gin.Engine, service services.WorkloadIdentityService) {
	engine.Any(codeQTopicAuthorityPath, func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		r := c.Request
		raw, ok := singletonRuntimeHeader(r.Header, "Authorization")
		if r.Method != http.MethodGet || r.URL.Path != codeQTopicAuthorityPath || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) > 0 || (r.Body != nil && r.Body != http.NoBody) || hasRuntimeHeader(r.Header, "Origin") || hasRuntimeHeader(r.Header, "Cookie") || !ok || !strings.HasPrefix(raw, "Bearer ") || strings.ContainsAny(strings.TrimPrefix(raw, "Bearer "), " \r\n\t") {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		validator, ok := service.(codeQTopicValidator)
		if !ok {
			c.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		authority, err := validator.ValidateCodeQTopicToken(r.Context(), strings.TrimPrefix(raw, "Bearer "))
		if err != nil {
			status := http.StatusForbidden
			if errors.Is(err, domain.ErrWorkloadIdentityUnavailable) {
				status = http.StatusServiceUnavailable
			}
			c.AbortWithStatus(status)
			return
		}
		c.JSON(http.StatusOK, authority)
	})
}
