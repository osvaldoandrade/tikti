package utils

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// ApiKey returns a Gin middleware that enforces the ?key= query parameter.
func ApiKey(expected string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if expected == "" {
			// No API Key needed
			c.Next()
			return
		}
		key := c.Query("key")
		if !constantTimeEqual(key, expected) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing API key"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequiredApiKeyHeader protects high-privilege routes without placing the key
// in URLs, access logs, browser history, or proxy query-string telemetry. An
// empty configured key fails closed.
func RequiredApiKeyHeader(expected string) gin.HandlerFunc {
	expected = strings.TrimSpace(expected)
	return func(c *gin.Context) {
		provided := strings.TrimSpace(c.GetHeader("X-API-Key"))
		if expected == "" || !constantTimeEqual(provided, expected) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing API key"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func constantTimeEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
