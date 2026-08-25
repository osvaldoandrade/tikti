package controllers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	maxWorkloadAccountRequestBytes = 8 << 10
	maxProjectedWorkloadTokenBytes = 16 << 10
	workloadAccountContract        = "workload-account-bff-v1"
)

type workloadAccountBFFController struct {
	service services.WorkloadAccountBFFService
}

func NewWorkloadAccountBFFController(service services.WorkloadAccountBFFService) *workloadAccountBFFController {
	return &workloadAccountBFFController{service: service}
}

func (c *workloadAccountBFFController) Register(ctx *gin.Context) {
	prepareWorkloadAccountResponse(ctx)
	token, credentials, ok := workloadAccountRequest(ctx)
	if !ok {
		return
	}
	result, created, err := c.service.Register(ctx.Request.Context(), token, credentials)
	if err != nil {
		writeWorkloadAccountError(ctx, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	ctx.JSON(status, result)
}

func (c *workloadAccountBFFController) Session(ctx *gin.Context) {
	prepareWorkloadAccountResponse(ctx)
	token, credentials, ok := workloadAccountRequest(ctx)
	if !ok {
		return
	}
	result, err := c.service.Session(ctx.Request.Context(), token, credentials)
	if err != nil {
		writeWorkloadAccountError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, result)
}

func prepareWorkloadAccountResponse(ctx *gin.Context) {
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
	ctx.Header("X-Tikti-Contract", workloadAccountContract)
}

func workloadAccountRequest(ctx *gin.Context) (string, domain.WorkloadAccountCredentials, bool) {
	token, valid := workloadAccountBearer(ctx.Request.Header.Values("Authorization"))
	if !valid {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid workload authentication"})
		return "", domain.WorkloadAccountCredentials{}, false
	}
	var credentials domain.WorkloadAccountCredentials
	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxWorkloadAccountRequestBytes)
	decoder := json.NewDecoder(ctx.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil {
		writeWorkloadAccountDecodeError(ctx, err)
		return "", domain.WorkloadAccountCredentials{}, false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return "", domain.WorkloadAccountCredentials{}, false
	}
	return token, credentials, true
}

func workloadAccountBearer(values []string) (string, bool) {
	if len(values) != 1 || len(values[0]) < 8 || !strings.EqualFold(values[0][:7], "Bearer ") {
		return "", false
	}
	token := values[0][7:]
	if token == "" || len(token) > maxProjectedWorkloadTokenBytes || strings.TrimSpace(token) != token ||
		strings.ContainsAny(token, " \r\n\t;,") {
		return "", false
	}
	return token, true
}

func writeWorkloadAccountDecodeError(ctx *gin.Context, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		ctx.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request too large"})
		return
	}
	ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
}

func writeWorkloadAccountError(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidArgument):
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid account request"})
	case errors.Is(err, domain.ErrWorkloadTokenInvalid), errors.Is(err, domain.ErrInvalidCreds):
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
	case errors.Is(err, domain.ErrWorkloadBindingDenied), errors.Is(err, domain.ErrUnauthorizedScope),
		errors.Is(err, domain.ErrInvalidTenant):
		ctx.JSON(http.StatusForbidden, gin.H{"error": "workload account access denied"})
	case errors.Is(err, domain.ErrWorkloadAccountConflict), errors.Is(err, domain.ErrMembershipConflict),
		errors.Is(err, domain.ErrEmailExists):
		ctx.JSON(http.StatusConflict, gin.H{"error": "account registration conflict"})
	default:
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "workload account service unavailable"})
	}
}
