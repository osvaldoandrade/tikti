package controllers

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

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

// Ensure activates the closed AI identity of exactly one tenant. Authority is
// the same as tenant role/client administration, and the caller's token must
// also be issued for that tenant: activation assigns <tenant>-ai-admin to the
// caller's own user there (ADR-0024 Amendment 2, decision 3), so a platform
// administrator acting on another tenant has no identity to assign and fails.
func (c *aiGatewayIdentityController) Ensure(ctx *gin.Context) {
	tenantID, outcome, actor := ctx.Param("tenantId"), "failure", ""
	defer func() {
		log.Printf("audit event=ai_gateway_identity_ensure actor=%.128q tenant=%.128q client=%q assigned_role=%.160q request_id=%.128q result=%s",
			actor, tenantID, domain.AIGatewayAudienceClientID, services.AIGatewayAdminRole(tenantID), ctx.GetHeader("X-Request-Id"), outcome)
	}()
	claims, ok := c.authorize(ctx, tenantID, &outcome)
	if !ok {
		return
	}
	actor = claimString(claims, "sub")
	if claimString(claims, "tid") != tenantID {
		outcome = "denied"
		ctx.JSON(http.StatusForbidden, gin.H{"error": domain.ErrAIGatewayAdministrator.Error()})
		return
	}
	response, created, err := c.service.Ensure(ctx.Request.Context(), tenantID, actor)
	if err != nil {
		outcome = c.writeError(ctx, err, "could not ensure AI identity")
		return
	}
	status := http.StatusOK
	outcome = "replay"
	if created {
		status, outcome = http.StatusCreated, "create"
	}
	ctx.JSON(status, response)
}

// Deactivate marks exactly one tenant's managed AI audience INACTIVE
// (ADR-0024 Amendment 2, decision 4). Roles, assignments and the record are
// retained; a tenant without the audience is an idempotent no-op.
func (c *aiGatewayIdentityController) Deactivate(ctx *gin.Context) {
	tenantID, outcome, actor := ctx.Param("tenantId"), "failure", ""
	defer func() {
		log.Printf("audit event=ai_gateway_identity_deactivate actor=%.128q tenant=%.128q client=%q request_id=%.128q result=%s",
			actor, tenantID, domain.AIGatewayAudienceClientID, ctx.GetHeader("X-Request-Id"), outcome)
	}()
	claims, ok := c.authorize(ctx, tenantID, &outcome)
	if !ok {
		return
	}
	actor = claimString(claims, "sub")
	response, changed, err := c.service.Deactivate(ctx.Request.Context(), tenantID)
	if err != nil {
		outcome = c.writeError(ctx, err, "could not deactivate AI identity")
		return
	}
	outcome = "replay"
	if changed {
		outcome = "deactivate"
	}
	ctx.JSON(http.StatusOK, response)
}

// authorize applies the shared route gate: AI enabled, canonical tenant,
// tenant identity administration, and an exact empty JSON object body.
func (c *aiGatewayIdentityController) authorize(ctx *gin.Context, tenantID string, outcome *string) (jwt.MapClaims, bool) {
	if c == nil || c.service == nil || c.config == nil || !c.config.AIGateway.Enabled {
		*outcome = "unavailable"
		ctx.JSON(http.StatusNotFound, gin.H{"error": "resource not found"})
		return nil, false
	}
	if !canonicalTenantIDPath(tenantID) {
		*outcome = "invalid"
		ctx.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidArgument.Error()})
		return nil, false
	}
	claims, authorized := requireTenantIAMWrite(ctx, c.config, tenantID)
	if !authorized {
		*outcome = "denied"
		return nil, false
	}
	mediaType, _, err := mime.ParseMediaType(ctx.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		ctx.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "content type must be application/json"})
		return nil, false
	}
	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, aiGatewayIdentityBodyLimit)
	if err := decodeEmptyJSONObject(ctx.Request.Body); err != nil {
		status := http.StatusBadRequest
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			status = http.StatusRequestEntityTooLarge
		}
		ctx.JSON(status, gin.H{"error": "invalid request"})
		return nil, false
	}
	return claims, true
}

func (c *aiGatewayIdentityController) writeError(ctx *gin.Context, err error, fallback string) string {
	switch {
	case errors.Is(err, domain.ErrAIGatewayAdministrator):
		ctx.JSON(http.StatusForbidden, gin.H{"error": domain.ErrAIGatewayAdministrator.Error()})
		return "denied"
	case errors.Is(err, domain.ErrInvalidTenant), errors.Is(err, domain.ErrInvalidArgument):
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return "invalid"
	case errors.Is(err, domain.ErrRoleConflict), errors.Is(err, domain.ErrManagedClientConflict), errors.Is(err, domain.ErrVersionConflict):
		ctx.JSON(http.StatusConflict, gin.H{"error": "AI identity conflicts with an existing tenant role, assignment or client"})
		return "conflict"
	default:
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fallback})
		return "failure"
	}
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
