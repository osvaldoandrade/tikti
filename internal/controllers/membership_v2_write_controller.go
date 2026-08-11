package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"slices"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const membershipV2WriteBodyLimit = 16 << 10

type membershipV2WriteAudit interface {
	Emit(ctx context.Context, phase, actor, tenantID, userID, requestID, result string) error
}

type membershipV2LogAudit struct {
	mu     sync.Mutex
	writer io.Writer
}

type membershipV2WriteController struct {
	svc     services.MembershipV2WriteService
	cfg     *config.Config
	allowed []string
	audit   membershipV2WriteAudit
}

func NewMembershipV2WriteController(svc services.MembershipV2WriteService, cfg *config.Config) *membershipV2WriteController {
	return newMembershipV2WriteController(svc, cfg, &membershipV2LogAudit{writer: log.Writer()})
}

func newMembershipV2WriteController(svc services.MembershipV2WriteService, cfg *config.Config, audit membershipV2WriteAudit) *membershipV2WriteController {
	return &membershipV2WriteController{
		svc: svc, cfg: cfg, audit: audit,
		allowed: append([]string(nil), cfg.MembershipV2WriteRoutesV1Tenants...),
	}
}

func (r *membershipV2WriteController) Put(c *gin.Context) {
	tenantID, userID := c.Param("tenantId"), c.Param("userId")
	claims, ok := r.authorize(c, tenantID, userID)
	if !ok {
		return
	}
	if c.Request.URL.ForceQuery || c.Request.URL.RawQuery != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidArgument.Error()})
		return
	}
	mediaTypes := c.Request.Header.Values("Content-Type")
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if len(mediaTypes) != 1 || err != nil || mediaType != "application/json" {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "content type must be application/json"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, membershipV2WriteBodyLimit)
	roles, err := decodeMembershipV2Write(c.Request.Body)
	if err != nil {
		status := http.StatusBadRequest
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			status = http.StatusRequestEntityTooLarge
		}
		c.JSON(status, gin.H{"error": "invalid request"})
		return
	}
	actor, requestID := claimString(claims, "sub"), c.GetHeader("X-Request-Id")
	if r.audit == nil || r.audit.Emit(c.Request.Context(), "intent", actor, tenantID, userID, requestID, "attempt") != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not ensure membership"})
		return
	}
	var result *domain.Membership
	var created bool
	serviceErr := errors.New("unavailable")
	if r.svc != nil {
		result, created, serviceErr = r.svc.Ensure(c.Request.Context(), tenantID, userID, roles)
	}
	outcome := membershipV2WriteOutcome(serviceErr, created)
	if r.audit.Emit(context.WithoutCancel(c.Request.Context()), "completion", actor, tenantID, userID, requestID, outcome) != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not ensure membership"})
		return
	}
	if serviceErr != nil {
		writeMembershipV2Error(c, serviceErr)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	c.JSON(status, result)
}

// Authentication precedes canonical and canary checks to hide the rollout boundary.
func (r *membershipV2WriteController) authorize(c *gin.Context, tenantID, userID string) (jwt.MapClaims, bool) {
	claims, ok := privilegedBearerClaims(c, r.cfg)
	if !ok {
		return nil, false
	}
	expectedPath := "/v1/admin/tenants/" + tenantID + "/memberships/" + userID
	if !canonicalMembershipTenantPath(tenantID) || userID == "." || userID == ".." ||
		!canonicalMembershipUserPath(userID) || c.Request.URL.EscapedPath() != expectedPath {
		c.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidArgument.Error()})
		return nil, false
	}
	if claimString(claims, "sub") == "" || !hasClaimScope(claims, platformTenantAdminScope) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient tenant administration scope"})
		return nil, false
	}
	if !slices.Contains(r.allowed, tenantID) {
		c.Status(http.StatusNotFound)
		return nil, false
	}
	return claims, true
}

func decodeMembershipV2Write(body io.Reader) ([]string, error) {
	decoder := json.NewDecoder(body)
	if err := expectJSONDelimiter(decoder, '{'); err != nil {
		return nil, err
	}
	seen := false
	var roles []string
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || key != "roles" || seen {
			return nil, domain.ErrInvalidArgument
		}
		var values *[]string
		if err := decoder.Decode(&values); err != nil || values == nil {
			return nil, domain.ErrInvalidArgument
		}
		roles, seen = *values, true
	}
	if !seen {
		return nil, domain.ErrInvalidArgument
	}
	if err := expectJSONDelimiter(decoder, '}'); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, domain.ErrInvalidArgument
	}
	return roles, nil
}

func membershipV2WriteOutcome(err error, created bool) string {
	switch {
	case err == nil && created:
		return "create"
	case err == nil:
		return "replay"
	case errors.Is(err, domain.ErrMembershipConflict), errors.Is(err, domain.ErrMembershipDependencyInactive):
		return "conflict"
	case errors.Is(err, domain.ErrMembershipDependencyNotFound):
		return "not_found"
	default:
		return "failure"
	}
}

func writeMembershipV2Error(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidTenant), errors.Is(err, domain.ErrInvalidArgument):
		c.JSON(http.StatusBadRequest, gin.H{"error": domain.ErrInvalidArgument.Error()})
	case errors.Is(err, domain.ErrMembershipDependencyNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": domain.ErrMembershipDependencyNotFound.Error()})
	case errors.Is(err, domain.ErrMembershipConflict):
		c.JSON(http.StatusConflict, gin.H{"error": domain.ErrMembershipConflict.Error()})
	case errors.Is(err, domain.ErrMembershipDependencyInactive):
		c.JSON(http.StatusConflict, gin.H{"error": domain.ErrMembershipDependencyInactive.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not ensure membership"})
	}
}

func (a *membershipV2LogAudit) Emit(_ context.Context, phase, actor, tenantID, userID, requestID, result string) error {
	line := fmt.Sprintf("audit action=membership_v2_put phase=%s actor=%q tenant=%q user=%q request_id=%q result=%s\n",
		phase, safeMembershipAuditValue(actor), safeMembershipAuditValue(tenantID), safeMembershipAuditValue(userID),
		safeMembershipAuditValue(requestID), result)
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := io.WriteString(a.writer, line)
	return err
}
