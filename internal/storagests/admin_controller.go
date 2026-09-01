package storagests

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const maxAdminBrowserBodyBytes = 4 << 10

type AdminBroker interface {
	List(context.Context, AdminListRequest, string, string) (AdminObjectList, *Error)
	CreateUploadURL(context.Context, AdminUploadRequest, string, string) (AdminSignedURL, *Error)
	CreateDownloadURL(context.Context, AdminDownloadRequest, string, string) (AdminSignedURL, *Error)
}

type AdminDeleteBroker interface {
	Delete(context.Context, AdminDeleteRequest, string, string) *Error
}

type AdminController struct {
	broker  AdminBroker
	deleter AdminDeleteBroker
	metrics *Metrics
}

func NewAdminController(broker AdminBroker) *AdminController {
	return NewAdminControllerWithMetrics(broker, nil)
}

func NewAdminControllerWithMetrics(broker AdminBroker, metrics *Metrics) *AdminController {
	deleter, _ := broker.(AdminDeleteBroker)
	return &AdminController{broker: broker, deleter: deleter, metrics: metrics}
}

func (h *AdminController) List(c *gin.Context) {
	adminResponseHeaders(c)
	token, ok := adminBearer(c)
	if !ok {
		return
	}
	pageSize := 100
	if raw := c.Query("pageSize"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			writeAdminError(c, adminPublicError(http.StatusBadRequest, CodeInvalidParameterValue, "invalid_request", "The object list request is invalid."))
			return
		}
		pageSize = parsed
	}
	includeDelete := false
	if values, present := c.Request.URL.Query()["include"]; present {
		if len(values) != 1 || values[0] != "object-delete-v1" {
			writeAdminError(c, adminPublicError(http.StatusBadRequest, CodeInvalidParameterValue, "invalid_request", "The object list request is invalid."))
			return
		}
		includeDelete = true
	}
	result, publicErr := h.broker.List(c.Request.Context(), AdminListRequest{
		TenantID: c.Param("tenantId"), BucketID: c.Param("bucketId"), Prefix: c.Query("prefix"),
		PageSize: pageSize, PageToken: c.Query("pageToken"), IncludeDeleteMetadata: includeDelete,
	}, token, c.GetHeader("X-Request-Id"))
	if publicErr != nil {
		writeAdminError(c, publicErr)
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *AdminController) Delete(c *gin.Context) {
	started := time.Now()
	result, reason := "error", "internal"
	var metrics *Metrics
	if h != nil {
		metrics = h.metrics
	}
	defer func() { metrics.observeAdmin("delete", result, reason, started) }()
	adminResponseHeaders(c)
	token, ok := adminBearer(c)
	if !ok {
		reason = "invalid_token"
		return
	}
	if h == nil || h.deleter == nil {
		reason = "provider_unavailable"
		writeAdminError(c, adminPublicError(http.StatusServiceUnavailable, CodeServiceUnavailable, "provider_unavailable", "Object storage is temporarily unavailable."))
		return
	}
	var input struct {
		Key  string `json:"key"`
		ETag string `json:"etag"`
	}
	if !decodeAdminBrowserJSON(c, &input) {
		reason = "invalid_request"
		return
	}
	publicErr := h.deleter.Delete(c.Request.Context(), AdminDeleteRequest{
		TenantID: c.Param("tenantId"), BucketID: c.Param("bucketId"), Key: input.Key, ETag: input.ETag,
	}, token, c.GetHeader("X-Request-Id"))
	if publicErr != nil {
		reason = publicErr.Reason
		writeAdminError(c, publicErr)
		return
	}
	result, reason = "success", "allowed"
	c.Status(http.StatusNoContent)
}

func (h *AdminController) UploadURL(c *gin.Context) {
	adminResponseHeaders(c)
	token, ok := adminBearer(c)
	if !ok {
		return
	}
	var input struct {
		Key         string `json:"key"`
		Size        int64  `json:"size"`
		ContentType string `json:"contentType"`
	}
	if !decodeAdminBrowserJSON(c, &input) {
		return
	}
	result, publicErr := h.broker.CreateUploadURL(c.Request.Context(), AdminUploadRequest{
		TenantID: c.Param("tenantId"), BucketID: c.Param("bucketId"),
		Key: input.Key, Size: input.Size, ContentType: input.ContentType,
	}, token, c.GetHeader("X-Request-Id"))
	if publicErr != nil {
		writeAdminError(c, publicErr)
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *AdminController) DownloadURL(c *gin.Context) {
	adminResponseHeaders(c)
	token, ok := adminBearer(c)
	if !ok {
		return
	}
	var input struct {
		Key string `json:"key"`
	}
	if !decodeAdminBrowserJSON(c, &input) {
		return
	}
	result, publicErr := h.broker.CreateDownloadURL(c.Request.Context(), AdminDownloadRequest{
		TenantID: c.Param("tenantId"), BucketID: c.Param("bucketId"), Key: input.Key,
	}, token, c.GetHeader("X-Request-Id"))
	if publicErr != nil {
		writeAdminError(c, publicErr)
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *AdminController) Reject(c *gin.Context) {
	adminResponseHeaders(c)
	writeAdminError(c, adminPublicError(http.StatusBadRequest, CodeInvalidParameterValue, "invalid_request", "The object storage route is invalid."))
}

func adminBearer(c *gin.Context) (string, bool) {
	parts := strings.Fields(c.GetHeader("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) < 16 || len(parts[1]) > 16<<10 {
		writeAdminError(c, adminPublicError(http.StatusUnauthorized, CodeInvalidIdentityToken, "invalid_token", "The access token is invalid."))
		return "", false
	}
	return parts[1], true
}

func decodeAdminBrowserJSON(c *gin.Context, target any) bool {
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAdminError(c, adminPublicError(http.StatusBadRequest, CodeInvalidParameterValue, "invalid_request", "The request body must be JSON."))
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAdminBrowserBodyBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeAdminError(c, adminPublicError(http.StatusBadRequest, CodeInvalidParameterValue, "invalid_request", "The request body is invalid."))
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeAdminError(c, adminPublicError(http.StatusBadRequest, CodeInvalidParameterValue, "invalid_request", "The request body is invalid."))
		return false
	}
	return true
}

func adminResponseHeaders(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("X-Tikti-Contract", AdminObjectStorageVersion)
}

func writeAdminError(c *gin.Context, publicErr *Error) {
	if publicErr == nil {
		publicErr = adminPublicError(http.StatusInternalServerError, CodeInternalFailure, "internal", "The request could not be completed.")
	}
	c.AbortWithStatusJSON(publicErr.HTTPStatus, gin.H{
		"error": publicErr.Message, "code": publicErr.Code, "reason": publicErr.Reason,
	})
}
