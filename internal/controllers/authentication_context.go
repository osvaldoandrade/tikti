package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/gin-gonic/gin"

	"github.com/osvaldoandrade/tikti/internal/httpidentity"
	"github.com/osvaldoandrade/tikti/internal/services"
	"github.com/osvaldoandrade/tikti/pkg/config"
)

func authenticationRequestContext(c *gin.Context, cfg *config.Config) context.Context {
	ctx := c.Request.Context()
	trusted := []string(nil)
	if cfg != nil {
		trusted = cfg.HTTP.TrustedProxyCIDRs
	}
	resolver, err := httpidentity.NewClientIPResolver(trusted)
	if err != nil {
		resolver, _ = httpidentity.NewClientIPResolver(nil)
	}
	return services.WithAuthenticationClientIP(ctx, resolver.Resolve(c.Request))
}

func authenticationAPIRequestContext(c *gin.Context, cfg *config.Config) context.Context {
	ctx := authenticationRequestContext(c, cfg)
	if cfg == nil || cfg.ApiKey == "" {
		return ctx
	}
	digest := sha256.Sum256([]byte(cfg.ApiKey))
	return services.WithAuthenticationAPIKeyID(ctx, hex.EncodeToString(digest[:]))
}
