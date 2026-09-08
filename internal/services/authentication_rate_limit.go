package services

import (
	"context"
	"strings"
	"time"

	"github.com/osvaldoandrade/tikti/pkg/config"
)

const (
	authenticationBucketPasswordIP             = "password:ip"
	authenticationBucketPasswordEmail          = "password:email"
	authenticationBucketTemporaryPasswordIP    = "temporary-password:ip"
	authenticationBucketTemporaryPasswordEmail = "temporary-password:email"
	authenticationBucketOOBSignInIP            = "oob-signin:ip"
	authenticationBucketOOBSignInEmail         = "oob-signin:email"
	authenticationBucketTokenExchangeUser      = "token-exchange:user"
	authenticationBucketLookupAPIKey           = "lookup:api-key" // #nosec G101 -- rate-limit bucket label, not an API key.
	authenticationBucketOOBEmail               = "oob-send:email"
)

type authenticationContextKey uint8

const (
	authenticationClientIPKey authenticationContextKey = iota
	authenticationAPIKeyIDKey
)

// WithAuthenticationClientIP records a canonical address resolved at the
// trusted HTTP boundary. Services never inspect forwarding headers directly.
func WithAuthenticationClientIP(ctx context.Context, clientIP string) context.Context {
	return context.WithValue(ctx, authenticationClientIPKey, strings.TrimSpace(clientIP))
}

// WithAuthenticationAPIKeyID records a non-secret identifier for the API key
// that passed boundary authentication. The Redis repository hashes it again.
func WithAuthenticationAPIKeyID(ctx context.Context, keyID string) context.Context {
	return context.WithValue(ctx, authenticationAPIKeyIDKey, strings.TrimSpace(keyID))
}

func authenticationClientIP(ctx context.Context) string {
	value, _ := ctx.Value(authenticationClientIPKey).(string)
	return strings.TrimSpace(value)
}

func authenticationAPIKeyID(ctx context.Context) string {
	value, _ := ctx.Value(authenticationAPIKeyIDKey).(string)
	return strings.TrimSpace(value)
}

func (s *userService) allowAuthenticationAttempt(ctx context.Context, bucket, subject string, limit int, window time.Duration) (bool, error) {
	// Direct service calls outside HTTP have no boundary identity. They retain
	// deterministic behavior for internal workflows; every public route sets
	// the appropriate identity before invoking the service.
	if strings.TrimSpace(subject) == "" || s.authenticationAttempts == nil {
		return true, nil
	}
	return s.authenticationAttempts.AllowAuthenticationAttempt(ctx, bucket, subject, limit, window)
}

func effectiveAuthenticationRateLimits(limits config.AuthenticationRateLimitsConfig) config.AuthenticationRateLimitsConfig {
	defaults := config.DefaultAuthenticationRateLimits()
	if limits.Login.Requests < 1 || limits.Login.WindowSeconds < 1 {
		limits.Login = defaults.Login
	}
	if limits.OOBSignIn.Requests < 1 || limits.OOBSignIn.WindowSeconds < 1 {
		limits.OOBSignIn = defaults.OOBSignIn
	}
	if limits.TokenExchange.Requests < 1 || limits.TokenExchange.WindowSeconds < 1 {
		limits.TokenExchange = defaults.TokenExchange
	}
	if limits.Lookup.Requests < 1 || limits.Lookup.WindowSeconds < 1 {
		limits.Lookup = defaults.Lookup
	}
	if limits.OOB.Requests < 1 || limits.OOB.WindowSeconds < 1 {
		limits.OOB = defaults.OOB
	}
	if limits.SAML.Requests < 1 || limits.SAML.WindowSeconds < 1 {
		limits.SAML = defaults.SAML
	}
	return limits
}
