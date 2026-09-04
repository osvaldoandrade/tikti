package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const tenantCreateBodyLimit = 4 << 10

type tenantController struct {
	svc services.TenantService
	cfg *config.Config
}

func NewTenantController(svc services.TenantService, cfg *config.Config) *tenantController {
	return &tenantController{svc: svc, cfg: cfg}
}

func (t *tenantController) Create(c *gin.Context) {
	if !requireAdmin(c, t.cfg) {
		return
	}
	var req domain.TenantCreateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return t.svc.Create(ctx, req)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

func (t *tenantController) CreateWithID(c *gin.Context) {
	claims, ok := requirePlatformTenantAdmin(c, t.cfg)
	if !ok {
		return
	}
	actor, tenantID, outcome := claimString(claims, "sub"), c.Param("tenantId"), "failure"
	defer func() {
		log.Printf("audit event=tenant_create actor=%.128q tenant=%.128q request_id=%.128q result=%s",
			actor, tenantID, c.GetHeader("X-Request-Id"), outcome)
	}()
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "content type must be application/json"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, tenantCreateBodyLimit)
	req, err := decodeTenantCreate(c.Request.Body)
	if err != nil {
		status := http.StatusBadRequest
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			status = http.StatusRequestEntityTooLarge
		}
		c.JSON(status, gin.H{"error": "invalid request"})
		return
	}
	result, created, err := t.svc.CreateWithID(c.Request.Context(), tenantID, req)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidArgument):
			outcome = "invalid"
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case errors.Is(err, domain.ErrTenantConflict):
			outcome = "conflict"
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create tenant"})
		}
		return
	}
	status := http.StatusOK
	outcome = "replay"
	if created {
		status = http.StatusCreated
		outcome = "create"
	}
	c.JSON(status, result)
}

func decodeTenantCreate(body io.Reader) (domain.TenantCreateReq, error) {
	var req domain.TenantCreateReq
	decoder := json.NewDecoder(body)
	token, err := decoder.Token()
	if err != nil {
		return req, err
	}
	if token != json.Delim('{') {
		return req, domain.ErrInvalidArgument
	}
	fields := map[string]*string{"name": &req.Name, "slug": &req.Slug}
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return req, err
		}
		key, ok := token.(string)
		target, exists := fields[key]
		if !ok || !exists {
			return req, domain.ErrInvalidArgument
		}
		delete(fields, key)
		var value *string
		if err = decoder.Decode(&value); err != nil {
			return req, err
		}
		if value == nil {
			return req, domain.ErrInvalidArgument
		}
		*target = *value
	}
	if token, err = decoder.Token(); err != nil {
		return req, err
	}
	if token != json.Delim('}') || len(fields) != 0 {
		return req, domain.ErrInvalidArgument
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err != nil {
			return req, err
		}
		return req, domain.ErrInvalidArgument
	}
	return req, nil
}

func (t *tenantController) Get(c *gin.Context) {
	id := c.Param("id")
	if !requireLegacyCodeAdminTenantRead(c, t.cfg, id) {
		return
	}
	ch := runCommandAsync(func(ctx context.Context) (interface{}, error) {
		return t.svc.Get(ctx, id)
	})
	result := <-ch
	if err, ok := result.(error); ok {
		switch err {
		case domain.ErrNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		case domain.ErrInvalidArgument:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}
	c.JSON(http.StatusOK, result)
}

func (t *tenantController) List(c *gin.Context) {
	if !requireLegacyCodeAdminPlatformRead(c, t.cfg) {
		return
	}
	pageSize := int64(50)
	if raw := c.Query("pageSize"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 1 || parsed > 200 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pageSize"})
			return
		}
		pageSize = parsed
	}
	var offset uint64
	if raw := c.Query("pageToken"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid pageToken"})
			return
		}
		offset = parsed
	}
	result, err := t.svc.List(c.Request.Context(), offset, pageSize)
	if err != nil {
		if err == domain.ErrInvalidArgument {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not list tenants"})
		return
	}
	c.JSON(http.StatusOK, result)
}
