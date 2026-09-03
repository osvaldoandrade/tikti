package controllers

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const (
	exactMembershipPageDefault = 50
	exactMembershipPageMax     = 200
	exactMembershipTokenMax    = 512
)

type exactMembershipReadController struct {
	svc     services.ExactMembershipReadService
	cfg     *config.Config
	allowed []string
}

func NewExactMembershipReadController(svc services.ExactMembershipReadService, cfg *config.Config) *exactMembershipReadController {
	allowed := append([]string(nil), cfg.ExactMembershipReadRoutesV1Tenants...)
	return &exactMembershipReadController{svc: svc, cfg: cfg, allowed: allowed}
}

func (r *exactMembershipReadController) Get(c *gin.Context) {
	tenantID, userID := c.Param("tenantId"), c.Param("userId")
	claims, ok := r.authorize(c, tenantID, userID)
	actor, outcome := claimString(claims, "sub"), "denied"
	defer func() { logExactMembershipRead(c, "membership_get", actor, tenantID, userID, outcome) }()
	if !ok {
		return
	}
	outcome = "failure"
	if c.Request.URL.RawQuery != "" {
		outcome = "invalid"
		c.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidArgument.Error()})
		return
	}
	if r.svc == nil {
		writeExactMembershipReadError(c, errors.New("unavailable"), "could not read membership")
		return
	}
	result, err := r.svc.Get(c.Request.Context(), tenantID, userID)
	if err != nil {
		outcome = exactMembershipReadOutcome(err)
		writeExactMembershipReadError(c, err, "could not read membership")
		return
	}
	outcome = "success"
	c.JSON(http.StatusOK, result)
}

func (r *exactMembershipReadController) List(c *gin.Context) {
	tenantID := c.Param("tenantId")
	claims, ok := r.authorize(c, tenantID, "*")
	actor, outcome := claimString(claims, "sub"), "denied"
	defer func() { logExactMembershipRead(c, "membership_list", actor, tenantID, "*", outcome) }()
	if !ok {
		return
	}
	pageToken, pageSize, err := exactMembershipListInput(c)
	if err != nil {
		outcome = "invalid"
		c.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidArgument.Error()})
		return
	}
	outcome = "failure"
	if r.svc == nil {
		writeExactMembershipReadError(c, errors.New("unavailable"), "could not list memberships")
		return
	}
	result, err := r.svc.List(c.Request.Context(), tenantID, pageToken, pageSize)
	if err != nil {
		outcome = exactMembershipReadOutcome(err)
		writeExactMembershipReadError(c, err, "could not list memberships")
		return
	}
	outcome = "success"
	c.JSON(http.StatusOK, result)
}

// Authorization deliberately precedes canary lookup so unauthorized callers
// cannot enumerate the allowlist from response differences.
func (r *exactMembershipReadController) authorize(c *gin.Context, tenantID, userID string) (jwt.MapClaims, bool) {
	claims, ok := privilegedBearerClaims(c, r.cfg)
	if !ok {
		return nil, false
	}
	if !canonicalMembershipTenantPath(tenantID) || userID != "*" && !canonicalMembershipUserPath(userID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidArgument.Error()})
		return claims, false
	}
	platform := hasClaimScope(claims, platformTenantAdminScope)
	local := claimString(claims, "tid") == tenantID &&
		(hasClaimScope(claims, tenantIdentityReadScope) || hasClaimScope(claims, tenantIdentityWriteScope))
	if claimString(claims, "sub") == "" || !platform && !local {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient tenant administration scope"})
		return claims, false
	}
	dynamicLocal := local && dynamicLocalTenantTargetAllowed(
		r.cfg, claims, tenantID, tenantIdentityReadScope, tenantIdentityWriteScope,
	)
	if !slices.Contains(r.allowed, tenantID) && !(platform && dynamicPlatformTenantTargetAllowed(r.cfg, claims)) && !dynamicLocal {
		c.Status(http.StatusNotFound)
		return claims, false
	}
	return claims, true
}

func exactMembershipListInput(c *gin.Context) (string, int, error) {
	headers := c.Request.Header.Values("X-Page-Token")
	if len(headers) > 1 || len(headers) == 1 && (len(headers[0]) < 1 || len(headers[0]) > exactMembershipTokenMax) {
		return "", 0, domain.ErrInvalidArgument
	}
	token := ""
	if len(headers) == 1 {
		token = headers[0]
	}
	values, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil || len(values) > 1 {
		return "", 0, domain.ErrInvalidArgument
	}
	if len(values) == 0 {
		return token, exactMembershipPageDefault, nil
	}
	pageValues, exists := values["pageSize"]
	if !exists || len(pageValues) != 1 || pageValues[0] == "" {
		return "", 0, domain.ErrInvalidArgument
	}
	for _, character := range []byte(pageValues[0]) {
		if character < '0' || character > '9' {
			return "", 0, domain.ErrInvalidArgument
		}
	}
	pageSize, err := strconv.Atoi(pageValues[0])
	if err != nil || pageSize < 1 || pageSize > exactMembershipPageMax {
		return "", 0, domain.ErrInvalidArgument
	}
	return token, pageSize, nil
}

func canonicalMembershipTenantPath(value string) bool {
	if len(value) < 1 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range []byte(value) {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func canonicalMembershipUserPath(value string) bool {
	if value == "." || value == ".." || len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-", rune(character)) {
			return false
		}
	}
	return true
}

func exactMembershipReadOutcome(err error) string {
	switch {
	case errors.Is(err, domain.ErrInvalidTenant), errors.Is(err, domain.ErrInvalidArgument):
		return "invalid"
	case errors.Is(err, domain.ErrMembershipNotFound):
		return "not_found"
	case errors.Is(err, domain.ErrMembershipPageStale):
		return "stale"
	default:
		return "failure"
	}
}

func writeExactMembershipReadError(c *gin.Context, err error, unavailable string) {
	switch {
	case errors.Is(err, domain.ErrInvalidTenant), errors.Is(err, domain.ErrInvalidArgument):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, domain.ErrMembershipNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": domain.ErrMembershipNotFound.Error()})
	case errors.Is(err, domain.ErrMembershipPageStale):
		c.JSON(http.StatusConflict, gin.H{"error": domain.ErrMembershipPageStale.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": unavailable})
	}
}

func logExactMembershipRead(c *gin.Context, action, actor, tenantID, userID, result string) {
	log.Printf("audit action=%s actor=%q tenant=%q user=%q request_id=%q result=%s",
		action, safeMembershipAuditValue(actor), safeMembershipAuditValue(tenantID),
		safeMembershipAuditValue(userID), safeMembershipAuditValue(c.GetHeader("X-Request-Id")), result)
}

func safeMembershipAuditValue(value string) string {
	if value == "*" {
		return value
	}
	if len(value) < 1 || len(value) > 128 {
		return ""
	}
	for _, character := range []byte(value) {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:@-", rune(character)) {
			return ""
		}
	}
	return value
}
