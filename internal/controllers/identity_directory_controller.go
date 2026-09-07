package controllers

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const identityDirectoryBodyLimit = 16 << 10

type IdentityDirectoryController struct {
	service services.IdentityDirectoryService
	config  *config.Config
}

func NewIdentityDirectoryController(service services.IdentityDirectoryService, cfg *config.Config) *IdentityDirectoryController {
	return &IdentityDirectoryController{service: service, config: cfg}
}

func (r *IdentityDirectoryController) CreateUser(c *gin.Context) {
	if _, ok := requirePlatformTenantAdmin(c, r.config); !ok {
		return
	}
	var request domain.DirectoryUserCreateReq
	if !decodeIdentityDirectoryJSON(c, &request) {
		return
	}
	result, err := r.service.CreateUser(c.Request.Context(), request)
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.JSON(http.StatusCreated, result)
}

func (r *IdentityDirectoryController) ChangeTemporaryPassword(c *gin.Context) {
	var request domain.TemporaryPasswordChangeReq
	if !decodeIdentityDirectoryJSON(c, &request) {
		return
	}
	if r.service == nil {
		writeIdentityDirectoryError(c, domain.ErrDirectoryInvariant)
		return
	}
	if err := r.service.ChangeTemporaryPassword(c.Request.Context(), request); err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.Status(http.StatusNoContent)
}

func (r *IdentityDirectoryController) ListUsers(c *gin.Context) {
	claims, platform, ok := r.authorizeDirectoryRead(c)
	if !ok {
		return
	}
	query, token, size, err := identityDirectoryQuery(c, true)
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	var page *domain.DirectoryUserPage
	if platform {
		page, err = r.service.ListUsers(c.Request.Context(), query, token, size)
	} else {
		normalized := strings.ToLower(strings.TrimSpace(query))
		if exactIdentityDirectoryEmail(normalized) {
			// Exact email is the sole external-user resolver available to a
			// workload administrator. It does not expose fuzzy matches.
			if token != "" {
				writeIdentityDirectoryError(c, domain.ErrInvalidArgument)
				return
			}
			page = &domain.DirectoryUserPage{Users: []domain.DirectoryUser{}}
			user, findErr := r.service.FindUserByEmail(c.Request.Context(), normalized)
			if findErr == nil && user != nil {
				page.Users = append(page.Users, *user)
			} else if findErr != nil && !errors.Is(findErr, domain.ErrNotFound) {
				writeIdentityDirectoryError(c, findErr)
				return
			}
		} else {
			// Empty and prefix searches are filtered to effective membership in
			// the signed tenant. The opaque cursor remains bounded by the global
			// page but never exposes another user's projection.
			page, err = r.service.ListUsers(c.Request.Context(), normalized, token, size)
			if err == nil {
				visible := page.Users[:0]
				for _, user := range page.Users {
					roles, _, accessErr := r.service.GetEffectiveTenantRoles(c.Request.Context(), user.ID, claimString(claims, "tid"))
					if accessErr != nil {
						err = accessErr
						break
					}
					if len(roles) > 0 {
						visible = append(visible, user)
					}
				}
				page.Users = visible
			}
		}
	}
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.JSON(http.StatusOK, page)
}

func exactIdentityDirectoryEmail(value string) bool {
	if len(value) < 3 || len(value) > 254 || strings.Count(value, "@") != 1 || strings.HasPrefix(value, "@") || strings.HasSuffix(value, "@") {
		return false
	}
	for _, character := range []byte(value) {
		if character < '!' || character > '~' {
			return false
		}
	}
	return true
}

func (r *IdentityDirectoryController) GetUser(c *gin.Context) {
	claims, platform, ok := r.authorizeDirectoryRead(c)
	if !ok || !identityDirectoryNoQuery(c) {
		return
	}
	userID := c.Param("userId")
	if !canonicalDirectoryIDPath(userID) {
		writeIdentityDirectoryError(c, domain.ErrInvalidArgument)
		return
	}
	if !platform && !r.localUserVisible(c, claims, userID) {
		return
	}
	result, err := r.service.GetUser(c.Request.Context(), userID)
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.JSON(http.StatusOK, result)
}

func (r *IdentityDirectoryController) GetUserAccess(c *gin.Context) {
	claims, platform, ok := r.authorizeDirectoryRead(c)
	if !ok || !identityDirectoryNoQuery(c) {
		return
	}
	userID := c.Param("userId")
	if !canonicalDirectoryIDPath(userID) {
		writeIdentityDirectoryError(c, domain.ErrInvalidArgument)
		return
	}
	if !platform && !r.localUserVisible(c, claims, userID) {
		return
	}
	result, err := r.service.GetUserAccess(c.Request.Context(), userID)
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	if !platform {
		tenantID := claimString(claims, "tid")
		filtered := result.Tenants[:0]
		for _, tenant := range result.Tenants {
			if tenant.TenantID == tenantID {
				filtered = append(filtered, tenant)
			}
		}
		result.Tenants = filtered
	}
	identityDirectoryResponseHeaders(c)
	c.JSON(http.StatusOK, result)
}

func (r *IdentityDirectoryController) CreateGroup(c *gin.Context) {
	if _, ok := requirePlatformTenantAdmin(c, r.config); !ok {
		return
	}
	var request domain.IdentityGroupCreateReq
	if !decodeIdentityDirectoryJSON(c, &request) {
		return
	}
	result, err := r.service.CreateGroup(c.Request.Context(), request)
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.Header("ETag", repository.IdentityETag(result.Version))
	c.JSON(http.StatusCreated, result)
}

func (r *IdentityDirectoryController) ListGroups(c *gin.Context) {
	if _, ok := requirePlatformTenantAdmin(c, r.config); !ok {
		return
	}
	query, token, size, err := identityDirectoryQuery(c, true)
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	result, err := r.service.ListGroups(c.Request.Context(), query, token, size)
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.JSON(http.StatusOK, result)
}

func (r *IdentityDirectoryController) GetGroup(c *gin.Context) {
	if _, ok := requirePlatformTenantAdmin(c, r.config); !ok || !identityDirectoryNoQuery(c) {
		return
	}
	result, err := r.service.GetGroup(c.Request.Context(), c.Param("groupId"))
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.Header("ETag", repository.IdentityETag(result.Version))
	c.JSON(http.StatusOK, result)
}

func (r *IdentityDirectoryController) PatchGroup(c *gin.Context) {
	if _, ok := requirePlatformTenantAdmin(c, r.config); !ok || !identityDirectoryNoQuery(c) {
		return
	}
	ifMatch, ok := identityDirectoryIfMatch(c)
	if !ok {
		return
	}
	var request domain.IdentityGroupPatchReq
	if !decodeIdentityDirectoryJSON(c, &request) {
		return
	}
	result, err := r.service.PatchGroup(c.Request.Context(), c.Param("groupId"), request, ifMatch)
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.Header("ETag", repository.IdentityETag(result.Version))
	c.JSON(http.StatusOK, result)
}

func (r *IdentityDirectoryController) DeleteGroup(c *gin.Context) {
	if _, ok := requirePlatformTenantAdmin(c, r.config); !ok || !identityDirectoryNoQuery(c) {
		return
	}
	ifMatch, ok := identityDirectoryIfMatch(c)
	if !ok {
		return
	}
	_, err := r.service.DeleteGroup(c.Request.Context(), c.Param("groupId"), ifMatch)
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.Status(http.StatusNoContent)
}

func (r *IdentityDirectoryController) PutGroupMember(c *gin.Context) { r.changeGroupMember(c, true) }
func (r *IdentityDirectoryController) DeleteGroupMember(c *gin.Context) {
	r.changeGroupMember(c, false)
}
func (r *IdentityDirectoryController) changeGroupMember(c *gin.Context, add bool) {
	if _, ok := requirePlatformTenantAdmin(c, r.config); !ok || !identityDirectoryNoQuery(c) {
		return
	}
	if !identityDirectoryNoBody(c) {
		return
	}
	ifMatch, ok := identityDirectoryIfMatch(c)
	if !ok {
		return
	}
	var result *domain.IdentityGroup
	var err error
	if add {
		result, _, err = r.service.PutGroupMember(c.Request.Context(), c.Param("groupId"), c.Param("userId"), ifMatch)
	} else {
		result, _, err = r.service.DeleteGroupMember(c.Request.Context(), c.Param("groupId"), c.Param("userId"), ifMatch)
	}
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.Header("ETag", repository.IdentityETag(result.Version))
	c.JSON(http.StatusOK, result)
}

func (r *IdentityDirectoryController) ListAssignments(c *gin.Context) {
	tenantID := c.Param("tenantId")
	if _, ok := requireTenantIAMRead(c, r.config, tenantID); !ok {
		return
	}
	query, token, size, err := identityDirectoryQuery(c, false)
	if err != nil || query != "" {
		writeIdentityDirectoryError(c, domain.ErrInvalidArgument)
		return
	}
	result, err := r.service.ListAssignments(c.Request.Context(), tenantID, token, size)
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.JSON(http.StatusOK, result)
}

func (r *IdentityDirectoryController) GetUserAssignment(c *gin.Context) {
	tenantID := c.Param("tenantId")
	if _, ok := requireTenantIAMRead(c, r.config, tenantID); !ok || !identityDirectoryNoQuery(c) {
		return
	}
	result, err := r.service.GetAssignment(c.Request.Context(), tenantID, domain.AccessPrincipalUser, c.Param("userId"))
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.Header("ETag", repository.IdentityETag(result.Version))
	c.JSON(http.StatusOK, result)
}

func (r *IdentityDirectoryController) PutUserAssignment(c *gin.Context) {
	r.putAssignment(c, domain.AccessPrincipalUser)
}
func (r *IdentityDirectoryController) PutGroupAssignment(c *gin.Context) {
	r.putAssignment(c, domain.AccessPrincipalGroup)
}
func (r *IdentityDirectoryController) putAssignment(c *gin.Context, kind domain.AccessPrincipalType) {
	tenantID := c.Param("tenantId")
	if _, ok := requireTenantIAMWrite(c, r.config, tenantID); !ok || !identityDirectoryNoQuery(c) {
		return
	}
	ifMatch, ok := identityDirectoryIfMatch(c)
	if !ok {
		return
	}
	var request domain.AccessAssignmentPutReq
	if !decodeIdentityDirectoryJSON(c, &request) {
		return
	}
	principalID := c.Param("userId")
	if kind == domain.AccessPrincipalGroup {
		principalID = c.Param("groupId")
	}
	result, created, err := r.service.PutAssignment(c.Request.Context(), tenantID, kind, principalID, request.Roles, ifMatch)
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.Header("ETag", repository.IdentityETag(result.Version))
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	c.JSON(status, result)
}

func (r *IdentityDirectoryController) DeleteUserAssignment(c *gin.Context) {
	r.deleteAssignment(c, domain.AccessPrincipalUser)
}
func (r *IdentityDirectoryController) DeleteGroupAssignment(c *gin.Context) {
	r.deleteAssignment(c, domain.AccessPrincipalGroup)
}
func (r *IdentityDirectoryController) deleteAssignment(c *gin.Context, kind domain.AccessPrincipalType) {
	tenantID := c.Param("tenantId")
	if _, ok := requireTenantIAMWrite(c, r.config, tenantID); !ok || !identityDirectoryNoQuery(c) {
		return
	}
	if !identityDirectoryNoBody(c) {
		return
	}
	ifMatch, ok := identityDirectoryIfMatch(c)
	if !ok {
		return
	}
	principalID := c.Param("userId")
	if kind == domain.AccessPrincipalGroup {
		principalID = c.Param("groupId")
	}
	_, err := r.service.DeleteAssignment(c.Request.Context(), tenantID, kind, principalID, ifMatch)
	if err != nil {
		writeIdentityDirectoryError(c, err)
		return
	}
	identityDirectoryResponseHeaders(c)
	c.Status(http.StatusNoContent)
}

func (r *IdentityDirectoryController) authorizeDirectoryRead(c *gin.Context) (jwt.MapClaims, bool, bool) {
	claims, ok := privilegedBearerClaims(c, r.config)
	if !ok {
		return nil, false, false
	}
	platform := hasPlatformTenantAdminProvenance(claims)
	local := claimString(claims, "sub") != "" && claimString(claims, "tid") != "" && (hasClaimScope(claims, tenantIdentityReadScope) || hasClaimScope(claims, tenantIdentityWriteScope))
	if !platform && !local {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient identity directory scope"})
		return nil, false, false
	}
	return claims, platform, true
}

func (r *IdentityDirectoryController) localUserVisible(c *gin.Context, claims jwt.MapClaims, userID string) bool {
	roles, _, err := r.service.GetEffectiveTenantRoles(c.Request.Context(), userID, claimString(claims, "tid"))
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		writeIdentityDirectoryError(c, err)
		return false
	}
	if len(roles) == 0 {
		c.Status(http.StatusNotFound)
		return false
	}
	return true
}

func identityDirectoryQuery(c *gin.Context, allowQuery bool) (string, string, int, error) {
	values, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil || len(values) > 3 {
		return "", "", 0, domain.ErrInvalidArgument
	}
	allowed := map[string]bool{"pageSize": true, "pageToken": true}
	if allowQuery {
		allowed["query"] = true
	}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return "", "", 0, domain.ErrInvalidArgument
		}
	}
	size := 50
	if raw := values.Get("pageSize"); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 1 || parsed > 200 {
			return "", "", 0, domain.ErrInvalidArgument
		}
		size = parsed
	}
	token := values.Get("pageToken")
	if len(token) > 1024 {
		return "", "", 0, domain.ErrInvalidArgument
	}
	return values.Get("query"), token, size, nil
}

func identityDirectoryNoQuery(c *gin.Context) bool {
	if c.Request.URL.RawQuery != "" || c.Request.URL.ForceQuery {
		writeIdentityDirectoryError(c, domain.ErrInvalidArgument)
		return false
	}
	return true
}

func decodeIdentityDirectoryJSON(c *gin.Context, target any) bool {
	mediaValues := c.Request.Header.Values("Content-Type")
	media, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if len(mediaValues) != 1 || err != nil || media != "application/json" {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "content type must be application/json"})
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, identityDirectoryBodyLimit)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return false
	}
	return true
}

func identityDirectoryIfMatch(c *gin.Context) (string, bool) {
	values := c.Request.Header.Values("If-Match")
	if len(values) == 0 {
		return "", true
	}
	if len(values) != 1 || values[0] == "" || len(values[0]) > 64 || strings.Contains(values[0], ",") {
		writeIdentityDirectoryError(c, domain.ErrInvalidArgument)
		return "", false
	}
	value := values[0]
	if value == "*" {
		return value, true
	}
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		writeIdentityDirectoryError(c, domain.ErrInvalidArgument)
		return "", false
	}
	version, err := strconv.ParseInt(value[1:len(value)-1], 10, 64)
	if err != nil || version < 1 || strconv.FormatInt(version, 10) != value[1:len(value)-1] {
		writeIdentityDirectoryError(c, domain.ErrInvalidArgument)
		return "", false
	}
	return value, true
}

func identityDirectoryNoBody(c *gin.Context) bool {
	if c.Request.Body != nil && (c.Request.ContentLength != 0 || len(c.Request.TransferEncoding) != 0) {
		writeIdentityDirectoryError(c, domain.ErrInvalidArgument)
		return false
	}
	return true
}

func identityDirectoryResponseHeaders(c *gin.Context) {
	c.Header("X-Tikti-Contract", "identity-directory-v2")
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Vary", "Authorization, Cookie, Origin, X-Tenant-Id")
}

func writeIdentityDirectoryError(c *gin.Context, err error) {
	identityDirectoryResponseHeaders(c)
	switch {
	case errors.Is(err, domain.ErrInvalidArgument):
		c.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidArgument.Error()})
	case errors.Is(err, domain.ErrInvalidCreds):
		c.JSON(http.StatusUnauthorized, gin.H{"error": domain.ErrInvalidCreds.Error()})
	case errors.Is(err, domain.ErrPasswordChangeRequired):
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": err.Error(), "code": "PASSWORD_CHANGE_REQUIRED"})
	case errors.Is(err, domain.ErrNotFound), errors.Is(err, domain.ErrMembershipDependencyNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	case errors.Is(err, domain.ErrEmailExists), errors.Is(err, domain.ErrGroupExists):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, domain.ErrVersionConflict):
		c.JSON(http.StatusPreconditionFailed, gin.H{"error": domain.ErrVersionConflict.Error()})
	case errors.Is(err, domain.ErrMembershipDependencyInactive):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, domain.ErrGroupMutationsDisabled):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": domain.ErrGroupMutationsDisabled.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "identity directory is unavailable"})
	}
}
