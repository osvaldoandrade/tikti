package controllers

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const managedAudienceClientBodyLimit = 128 << 10

type managedAudienceClientController struct {
	service services.ClientService
	config  *config.Config
}

func NewManagedAudienceClientController(
	service services.ClientService,
	config *config.Config,
) *managedAudienceClientController {
	return &managedAudienceClientController{service: service, config: config}
}

func (c *managedAudienceClientController) Ensure(ctx *gin.Context) {
	claims, authorized := requirePlatformTenantAdmin(ctx, c.config)
	if !authorized {
		return
	}
	tenantID, outcome := ctx.Param("tenantId"), "failure"
	defer func() {
		log.Printf("audit event=managed_audience_client_ensure actor=%.128q tenant=%.128q client=%q request_id=%.128q result=%s",
			claimString(claims, "sub"), tenantID, domain.CodeAdminAudienceClientID,
			ctx.GetHeader("X-Request-Id"), outcome)
	}()
	mediaType, _, err := mime.ParseMediaType(ctx.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		ctx.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "content type must be application/json"})
		return
	}
	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, managedAudienceClientBodyLimit)
	request, err := decodeManagedAudienceClientEnsure(ctx.Request.Body)
	if err != nil {
		status := http.StatusBadRequest
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			status = http.StatusRequestEntityTooLarge
		}
		ctx.JSON(status, gin.H{"error": "invalid request"})
		return
	}
	response, created, err := c.service.EnsureCodeAdminAudience(ctx.Request.Context(), tenantID, request)
	if err != nil {
		writeManagedAudienceClientError(ctx, err)
		if errors.Is(err, domain.ErrManagedClientConflict) {
			outcome = "conflict"
		}
		return
	}
	status := http.StatusOK
	outcome = "replay"
	if created {
		status, outcome = http.StatusCreated, "create"
	}
	ctx.JSON(status, response)
}

func decodeManagedAudienceClientEnsure(body io.Reader) (domain.ManagedAudienceClientEnsureReq, error) {
	var request domain.ManagedAudienceClientEnsureReq
	decoder := json.NewDecoder(body)
	if err := expectJSONDelimiter(decoder, '{'); err != nil {
		return request, err
	}
	seen := false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return request, err
		}
		key, ok := token.(string)
		if !ok || key != "defaultScopes" || seen {
			return request, domain.ErrInvalidArgument
		}
		var scopes *[]string
		if err := decoder.Decode(&scopes); err != nil {
			return request, err
		}
		if scopes == nil {
			return request, domain.ErrInvalidArgument
		}
		request.DefaultScopes, seen = *scopes, true
	}
	if !seen {
		return request, domain.ErrInvalidArgument
	}
	if err := expectJSONDelimiter(decoder, '}'); err != nil {
		return request, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return request, domain.ErrInvalidArgument
	}
	return request, nil
}

func writeManagedAudienceClientError(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidTenant), errors.Is(err, domain.ErrInvalidArgument):
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, domain.ErrManagedClientConflict):
		ctx.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "could not ensure managed audience client"})
	}
}
