package utils

import (
	"net/http"

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
		if key != expected {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing API key"})
			c.Abort()
			return
		}
		c.Next()
	}
}
