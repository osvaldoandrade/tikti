package controllers

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/osvaldoandrade/tikti/internal/saml"
)

type SAMLAdminController struct {
	service *saml.AdminService
}

func NewSAMLAdminController(service *saml.AdminService) *SAMLAdminController {
	return &SAMLAdminController{service: service}
}

func (h *SAMLAdminController) Get(c *gin.Context) {
	tenantID := strings.TrimSpace(c.Param("tenantId"))
	result, err := h.service.Get(c.Request.Context(), tenantID)
	if err != nil {
		writeSAMLAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *SAMLAdminController) Put(c *gin.Context) {
	tenantID := strings.TrimSpace(c.Param("tenantId"))
	var input saml.PutIdPConfiguration
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, saml.MaxMetadataBytes+(32<<10)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid SAML configuration request"})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request must contain one JSON object"})
		return
	}
	result, err := h.service.Put(c.Request.Context(), tenantID, input)
	if err != nil {
		log.Printf("saml admin: action=upsert result=failure tenant=%s request_id=%s", tenantID, c.GetHeader("X-Request-Id"))
		writeSAMLAdminError(c, err)
		return
	}
	log.Printf("saml admin: action=upsert result=success tenant=%s entity=%q request_id=%s", tenantID, result.EntityID, c.GetHeader("X-Request-Id"))
	c.JSON(http.StatusOK, result)
}

func (h *SAMLAdminController) Delete(c *gin.Context) {
	tenantID := strings.TrimSpace(c.Param("tenantId"))
	if err := h.service.Delete(c.Request.Context(), tenantID); err != nil {
		log.Printf("saml admin: action=delete result=failure tenant=%s request_id=%s", tenantID, c.GetHeader("X-Request-Id"))
		writeSAMLAdminError(c, err)
		return
	}
	log.Printf("saml admin: action=delete result=success tenant=%s request_id=%s", tenantID, c.GetHeader("X-Request-Id"))
	c.Status(http.StatusNoContent)
}

func writeSAMLAdminError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, saml.ErrAdminInvalidInput):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "SAML administration is temporarily unavailable"})
	}
}
