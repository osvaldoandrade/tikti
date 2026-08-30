package storagests

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	MachineOIDCDiscoveryPath = "/internal/v1/storage/.well-known/openid-configuration"
	MachineOIDCJWKSPath      = "/internal/v1/storage/jwks.json"
)

var storageOIDCClaims = []string{
	"iss", "aud", "client_id", "sub", "tid", "cluster_ref", "namespace",
	"service_account", "binding_uid", "binding_generation", "bucket_uid",
	"bucket_generation", "preferred_username", "policy", "jti", "iat", "nbf", "exp",
}

// JWKSProvider is deliberately narrower than the user service. The machine
// endpoint can only read the existing signing keys and cannot access users.
type JWKSProvider interface {
	JWKS(context.Context) (map[string]any, error)
}

// OIDCController serves only the metadata needed by MinIO's claim provider.
// It intentionally does not advertise browser authorization or token flows.
type OIDCController struct {
	issuer   string
	jwksURL  string
	provider JWKSProvider
}

func NewOIDCController(issuer, jwksURL string, provider JWKSProvider) *OIDCController {
	return &OIDCController{
		issuer:   strings.TrimSuffix(strings.TrimSpace(issuer), "/"),
		jwksURL:  strings.TrimSpace(jwksURL),
		provider: provider,
	}
}

func (c *OIDCController) Discovery(ctx *gin.Context) {
	prepareMachineMetadataResponse(ctx)
	ctx.JSON(http.StatusOK, gin.H{
		"issuer":                                c.issuer,
		"jwks_uri":                              c.jwksURL,
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"claims_supported":                      storageOIDCClaims,
	})
}

func (c *OIDCController) JWKS(ctx *gin.Context) {
	prepareMachineMetadataResponse(ctx)
	if c == nil || c.provider == nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "jwks unavailable"})
		return
	}
	jwks, err := c.provider.JWKS(ctx.Request.Context())
	if err != nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "jwks unavailable"})
		return
	}
	ctx.JSON(http.StatusOK, jwks)
}

func (c *OIDCController) Reject(ctx *gin.Context) {
	removeCORSHeaders(ctx)
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("X-Content-Type-Options", "nosniff")
	ctx.Status(http.StatusNotFound)
}

func prepareMachineMetadataResponse(ctx *gin.Context) {
	removeCORSHeaders(ctx)
	ctx.Header("Cache-Control", "public, max-age=300")
	ctx.Header("X-Content-Type-Options", "nosniff")
}
