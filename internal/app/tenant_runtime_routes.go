package app

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/osvaldoandrade/tikti/internal/repository"
	"github.com/osvaldoandrade/tikti/pkg/config"
	"github.com/osvaldoandrade/tikti/pkg/domain"
)

const tenantRuntimePrefix = "/v1/internal/tenants"
const tenantRuntimeVersion = "tenant-runtime/v1"

type tenantRuntimeResponse struct {
	SchemaVersion string `json:"schemaVersion"`
	TenantID      string `json:"tenantId"`
	TenantEpoch   string `json:"tenantEpoch"`
	State         string `json:"state"`
	ObservedAt    string `json:"observedAt"`
	Nonce         string `json:"nonce"`
}

func setupTenantRuntimeMappings(engine *gin.Engine, cfg *config.Config, reader repository.RetainedTenantRepository) {
	// This middleware also protects unmatched encoded/normalized/case aliases
	// from browser CORS, whose middleware is installed after NewApplication.
	engine.Use(func(c *gin.Context) {
		if isTenantRuntimePath(c.Request.URL.Path) && (!cfg.TenantRuntimeAuthorityV1 || c.FullPath() == "") {
			tenantRuntimeError(c, http.StatusNotFound, "TenantRuntimeUnsupported")
			return
		}
		c.Next()
	})
	if !cfg.TenantRuntimeAuthorityV1 {
		return
	}
	configuredKey := sha256.Sum256([]byte(cfg.ApiKey))
	handler := func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Header("X-Content-Type-Options", "nosniff")
		defer func() {
			if recover() != nil {
				// Keep dependency panics inside the same bounded machine error
				// contract; the normal access logger records the failure status.
				tenantRuntimeError(c, http.StatusServiceUnavailable, "TenantRuntimeUnavailable")
			}
		}()
		request := c.Request
		tenantID, validPath := canonicalRuntimePath(request)
		if !validPath || request.Method != http.MethodGet || request.URL.RawQuery != "" || request.URL.ForceQuery ||
			request.ContentLength != 0 || len(request.TransferEncoding) != 0 || len(request.Trailer) != 0 ||
			(request.Body != nil && request.Body != http.NoBody) ||
			hasRuntimeHeader(request.Header, "Origin") || hasRuntimeHeader(request.Header, "Cookie") ||
			hasRuntimeHeader(request.Header, "Authorization") || hasRuntimeHeader(request.Header, "Transfer-Encoding") {
			tenantRuntimeError(c, http.StatusBadRequest, "TenantRuntimeInvalidRequest")
			return
		}
		key, keyOK := singletonRuntimeHeader(request.Header, "X-API-Key")
		providedKey := sha256.Sum256([]byte(key))
		if !keyOK || subtle.ConstantTimeCompare(configuredKey[:], providedKey[:]) != 1 {
			tenantRuntimeError(c, http.StatusUnauthorized, "TenantRuntimeUnauthorized")
			return
		}
		version, versionOK := singletonRuntimeHeader(request.Header, "X-Code-Foundry-Tenant-Runtime")
		nonce, nonceOK := singletonRuntimeHeader(request.Header, "X-Code-Foundry-Tenant-Runtime-Nonce")
		if !versionOK || version != tenantRuntimeVersion || !nonceOK || !runtimeNonce(nonce) {
			tenantRuntimeError(c, http.StatusBadRequest, "TenantRuntimeInvalidRequest")
			return
		}
		// This observation begins before the sole HGET, so storage latency cannot
		// manufacture a fresh lease or validate a birth in the future.
		observedAt := time.Now().UTC()
		if reader == nil {
			tenantRuntimeError(c, http.StatusServiceUnavailable, "TenantRuntimeUnavailable")
			return
		}
		tenant, err := reader.GetRetained(request.Context(), tenantID, observedAt)
		if err != nil {
			tenantRuntimeError(c, http.StatusServiceUnavailable, "TenantRuntimeUnavailable")
			return
		}
		response := tenantRuntimeResponse{SchemaVersion: tenantRuntimeVersion, TenantID: tenantID, State: "ABSENT", ObservedAt: observedAt.Format(time.RFC3339Nano), Nonce: nonce}
		if tenant != nil {
			epoch := sha256.Sum256([]byte("codefoundry/tenant-lifetime/v1\x00" + tenantID + "\x00" + tenant.CreatedAt.UTC().Format(time.RFC3339Nano)))
			response.TenantEpoch = hex.EncodeToString(epoch[:])
			response.State = string(tenant.Status)
			if tenant.RetiredAt != nil {
				response.State = "RETIRED"
			}
		}
		// Every field is bounded and contains no tenant-supplied display text;
		// the encoded response is below 512 bytes (contract maximum: 4 KiB).
		c.JSON(http.StatusOK, response)
	}
	// Catch the complete private namespace with every method before browser
	// middleware. The handler admits only the one canonical GET. The explicit
	// base prevents Gin's automatic slash redirect for its catch-all route.
	engine.Any(tenantRuntimePrefix, handler)
	engine.Any(tenantRuntimePrefix+"/*runtimePath", handler)
}

func tenantRuntimeError(c *gin.Context, status int, code string) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("X-Content-Type-Options", "nosniff")
	c.AbortWithStatusJSON(status, struct {
		Code string `json:"code"`
	}{Code: code})
}

func canonicalRuntimePath(request *http.Request) (string, bool) {
	if request.URL == nil || request.URL.RawPath != "" || request.URL.Opaque != "" || request.URL.Fragment != "" {
		return "", false
	}
	value := request.URL.Path
	if !strings.HasPrefix(value, tenantRuntimePrefix+"/") || !strings.HasSuffix(value, "/runtime-state") {
		return "", false
	}
	tenantID := strings.TrimSuffix(strings.TrimPrefix(value, tenantRuntimePrefix+"/"), "/runtime-state")
	if len(tenantID) < 1 || len(tenantID) > 63 || tenantID == domain.RetiredDefaultTenantID || tenantID[0] == '-' || tenantID[len(tenantID)-1] == '-' {
		return "", false
	}
	for _, character := range []byte(tenantID) {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return "", false
		}
	}
	// The wire path, not Gin's decoded parameter, is the authority target.
	if request.RequestURI != "" && request.RequestURI != value {
		return "", false
	}
	return tenantID, true
}

func isTenantRuntimePath(value string) bool {
	for range 4 {
		normalized := strings.ToLower(path.Clean(strings.ReplaceAll(value, "\\", "/")))
		if normalized == tenantRuntimePrefix || strings.HasPrefix(normalized, tenantRuntimePrefix+"/") {
			return true
		}
		decoded, err := url.PathUnescape(value)
		if err != nil || decoded == value {
			break
		}
		value = decoded
	}
	return false
}

func hasRuntimeHeader(headers http.Header, name string) bool {
	for key := range headers {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func singletonRuntimeHeader(headers http.Header, name string) (string, bool) {
	var value string
	count := 0
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		if len(values) != 1 {
			return "", false
		}
		count++
		value = values[0]
	}
	return value, count == 1 && len(value) > 0 && len(value) <= 4096 && strings.TrimSpace(value) == value && !strings.Contains(value, ",")
}

func runtimeNonce(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range []byte(value) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
