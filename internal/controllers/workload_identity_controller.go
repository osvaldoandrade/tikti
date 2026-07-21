package controllers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const maxWorkloadIdentityRequestBytes = 96 << 10

type workloadIdentityController struct {
	service services.WorkloadIdentityService
}

func NewWorkloadIdentityController(service services.WorkloadIdentityService) *workloadIdentityController {
	return &workloadIdentityController{service: service}
}

func (c *workloadIdentityController) Exchange(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
	var req domain.WorkloadTokenExchangeReq
	if err := decodeWorkloadIdentityJSON(ctx, &req); err != nil {
		writeInvalidWorkloadIdentityRequest(ctx, err)
		return
	}
	response, err := c.service.Exchange(ctx.Request.Context(), req)
	if err != nil {
		writeWorkloadIdentityError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, response)
}

func (c *workloadIdentityController) UpsertBinding(ctx *gin.Context) {
	var req domain.WorkloadBindingUpsertReq
	if err := decodeWorkloadIdentityJSON(ctx, &req); err != nil {
		writeInvalidWorkloadIdentityRequest(ctx, err)
		return
	}
	binding, err := c.service.UpsertBinding(ctx.Request.Context(), req)
	if err != nil {
		writeWorkloadIdentityError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, binding)
}

func (c *workloadIdentityController) RevokeBinding(ctx *gin.Context) {
	var req domain.WorkloadBindingRevokeReq
	if err := decodeWorkloadIdentityJSON(ctx, &req); err != nil {
		writeInvalidWorkloadIdentityRequest(ctx, err)
		return
	}
	binding, err := c.service.RevokeBinding(ctx.Request.Context(), req)
	if err != nil {
		writeWorkloadIdentityError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, binding)
}

func decodeWorkloadIdentityJSON(ctx *gin.Context, destination interface{}) error {
	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxWorkloadIdentityRequestBytes)
	decoder := json.NewDecoder(ctx.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func writeInvalidWorkloadIdentityRequest(ctx *gin.Context, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		ctx.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request too large"})
		return
	}
	ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
}

func writeWorkloadIdentityError(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidArgument):
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid workload identity request"})
	case errors.Is(err, domain.ErrWorkloadTokenInvalid):
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid workload token"})
	case errors.Is(err, domain.ErrWorkloadBindingDenied), errors.Is(err, domain.ErrUnauthorizedScope):
		ctx.JSON(http.StatusForbidden, gin.H{"error": "workload binding denied"})
	case errors.Is(err, domain.ErrNotFound):
		ctx.JSON(http.StatusNotFound, gin.H{"error": "workload binding not found"})
	default:
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "workload identity unavailable"})
	}
}
