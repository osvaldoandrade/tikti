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

const aiGatewayIdentityBodyLimit = 4 << 10

type aiGatewayIdentityController struct {
	service services.AIGatewayIdentityService
	config  *config.Config
}

func NewAIGatewayIdentityController(service services.AIGatewayIdentityService, cfg *config.Config) *aiGatewayIdentityController {
	return &aiGatewayIdentityController{service: service, config: cfg}
}

// Ensure installs the closed AI identity of exactly one tenant. Authority is
// the same as tenant role/client administration: a tenant-local
// code-admin:identity:write token for its own tid, or platform administration.
func (c *aiGatewayIdentityController) Ensure(ctx *gin.Context) {
	tenantID, outcome, actor := ctx.Param("tenantId"), "failure", ""
	defer func() {
		log.Printf("audit event=ai_gateway_identity_ensure actor=%.128q tenant=%.128q client=%q request_id=%.128q result=%s",
			actor, tenantID, domain.AIGatewayAudienceClientID, ctx.GetHeader("X-Request-Id"), outcome)
	}()
	if c == nil || c.service == nil || c.config == nil || !c.config.AIGateway.Enabled {
		outcome = "unavailable"
		ctx.JSON(http.StatusNotFound, gin.H{"error": "resource not found"})
		return
	}
	if !canonicalTenantIDPath(tenantID) {
		outcome = "invalid"
		ctx.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidArgument.Error()})
		return
	}
	claims, authorized := requireTenantIAMWrite(ctx, c.config, tenantID)
	if !authorized {
		outcome = "denied"
		return
	}
	actor = claimString(claims, "sub")
	mediaType, _, err := mime.ParseMediaType(ctx.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		ctx.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "content type must be application/json"})
		return
	}
	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, aiGatewayIdentityBodyLimit)
	if err := decodeEmptyJSONObject(ctx.Request.Body); err != nil {
		status := http.StatusBadRequest
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			status = http.StatusRequestEntityTooLarge
		}
		ctx.JSON(status, gin.H{"error": "invalid request"})
		return
	}
	response, created, err := c.service.Ensure(ctx.Request.Context(), tenantID)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidTenant), errors.Is(err, domain.ErrInvalidArgument):
			outcome = "invalid"
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case errors.Is(err, domain.ErrRoleConflict), errors.Is(err, domain.ErrManagedClientConflict):
			outcome = "conflict"
			ctx.JSON(http.StatusConflict, gin.H{"error": "AI identity conflicts with an existing tenant role or client"})
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "could not ensure AI identity"})
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

// decodeEmptyJSONObject accepts exactly `{}`: definitions are server-owned.
func decodeEmptyJSONObject(body io.Reader) error {
	decoder := json.NewDecoder(body)
	if err := expectJSONDelimiter(decoder, '{'); err != nil {
		return err
	}
	if decoder.More() {
		return domain.ErrInvalidArgument
	}
	if err := expectJSONDelimiter(decoder, '}'); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			return err
		}
		return domain.ErrInvalidArgument
	}
	return nil
}
