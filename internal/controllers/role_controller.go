package controllers

import (
	"context"
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

const rolePutBodyLimit = 16 << 10

type roleController struct {
	svc services.RoleService
	cfg *config.Config
}

func NewRoleController(svc services.RoleService, cfg *config.Config) *roleController {
	return &roleController{svc: svc, cfg: cfg}
}

func (r *roleController) Create(c *gin.Context) {
	tenantID := c.Param("tenantId")
	if !requireTenantIdentityAuthority(c, r.cfg, tenantID, true) {
		return
	}
	var req domain.RoleCreateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return r.svc.Create(ctx, tenantID, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidTenant, domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

func (r *roleController) Put(c *gin.Context) {
	tenantID := c.Param("tenantId")
	claims, ok := requireTenantIAMWrite(c, r.cfg, tenantID)
	if !ok {
		return
	}
	actor, roleName := claimString(claims, "sub"), c.Param("roleName")
	outcome := "failure"
	defer func() { logRolePut(c, actor, tenantID, roleName, outcome) }()
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "content type must be application/json"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, rolePutBodyLimit)
	req, err := decodeRolePut(c.Request.Body)
	if err != nil {
		status := http.StatusBadRequest
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			status = http.StatusRequestEntityTooLarge
		}
		c.JSON(status, gin.H{"error": "invalid request"})
		return
	}
	result, created, err := r.svc.CreateWithName(c.Request.Context(), tenantID, roleName, req)
	if err != nil {
		if errors.Is(err, domain.ErrRoleConflict) {
			outcome = "conflict"
		}
		writeRolePutError(c, err)
		return
	}
	status := http.StatusOK
	outcome = "replay"
	if created {
		status, outcome = http.StatusCreated, "create"
	}
	c.JSON(status, result)
}

func (r *roleController) Get(c *gin.Context) {
	tenantID, roleName := c.Param("tenantId"), c.Param("roleName")
	claims, ok := requireTenantIAMRead(c, r.cfg, tenantID)
	if !ok {
		return
	}
	outcome := "failure"
	defer func() { logRoleRead(c, "tenant_role_get", claimString(claims, "sub"), tenantID, roleName, outcome) }()
	result, err := r.svc.GetByName(c.Request.Context(), tenantID, roleName)
	if err != nil {
		outcome = roleReadOutcome(err)
		writeRoleReadError(c, err, "could not read role")
		return
	}
	outcome = "success"
	c.JSON(http.StatusOK, result)
}

func (r *roleController) ListAdmin(c *gin.Context) {
	tenantID := c.Param("tenantId")
	claims, ok := requireTenantIAMRead(c, r.cfg, tenantID)
	if !ok {
		return
	}
	outcome := "failure"
	defer func() { logRoleRead(c, "tenant_role_list", claimString(claims, "sub"), tenantID, "*", outcome) }()
	result, err := r.svc.ListCanonical(c.Request.Context(), tenantID)
	if err != nil {
		outcome = roleReadOutcome(err)
		writeRoleReadError(c, err, "could not list roles")
		return
	}
	outcome = "success"
	c.JSON(http.StatusOK, result)
}

func roleReadOutcome(err error) string {
	if errors.Is(err, domain.ErrInvalidTenant) || errors.Is(err, domain.ErrInvalidArgument) {
		return "invalid"
	}
	if errors.Is(err, domain.ErrRoleNotFound) {
		return "not_found"
	}
	return "failure"
}

func logRoleRead(c *gin.Context, event, actor, tenantID, roleName, outcome string) {
	log.Printf("audit event=%s actor=%.128q tenant=%.128q role=%.128q request_id=%.128q result=%s",
		event, actor, tenantID, roleName, c.GetHeader("X-Request-Id"), outcome)
}

func writeRoleReadError(c *gin.Context, err error, internalMessage string) {
	switch {
	case errors.Is(err, domain.ErrInvalidTenant), errors.Is(err, domain.ErrInvalidArgument):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, domain.ErrRoleNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": domain.ErrRoleNotFound.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": internalMessage})
	}
}

func logRolePut(c *gin.Context, actor, tenantID, roleName, result string) {
	log.Printf("audit event=tenant_role_put actor=%.128q tenant=%.128q role=%.128q request_id=%.128q result=%s",
		actor, tenantID, roleName, c.GetHeader("X-Request-Id"), result)
}

func decodeRolePut(body io.Reader) (domain.RolePutReq, error) {
	decoder := json.NewDecoder(body)
	if err := expectJSONDelimiter(decoder, '{'); err != nil {
		return domain.RolePutReq{}, err
	}
	req, seen, err := decodeRolePutFields(decoder)
	if err != nil {
		return req, err
	}
	if !seen {
		return req, domain.ErrInvalidArgument
	}
	if err := expectJSONDelimiter(decoder, '}'); err != nil {
		return req, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err != nil {
			return req, err
		}
		return req, domain.ErrInvalidArgument
	}
	return req, nil
}

func decodeRolePutFields(decoder *json.Decoder) (domain.RolePutReq, bool, error) {
	var req domain.RolePutReq
	seen := false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return req, seen, err
		}
		key, ok := token.(string)
		if !ok || key != "permissions" || seen {
			return req, seen, domain.ErrInvalidArgument
		}
		var permissions *[]string
		if err := decoder.Decode(&permissions); err != nil {
			return req, seen, err
		}
		if permissions == nil {
			return req, seen, domain.ErrInvalidArgument
		}
		req.Permissions, seen = *permissions, true
	}
	return req, seen, nil
}

func expectJSONDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if token == expected {
		return nil
	}
	if err != nil {
		return err
	}
	return domain.ErrInvalidArgument
}

func writeRolePutError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidTenant), errors.Is(err, domain.ErrInvalidArgument):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, domain.ErrRoleConflict):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create role"})
	}
}

func (r *roleController) List(c *gin.Context) {
	tenantID := c.Param("tenantId")
	if !requireLegacyCodeAdminTenantRead(c, r.cfg, tenantID) {
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return r.svc.List(ctx, tenantID)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidTenant:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}
