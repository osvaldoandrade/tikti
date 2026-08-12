package app

import (
	"io"
	"log"
	"net"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
)

const safeLogValueLimit = 128

func newSafeEngine() *gin.Engine {
	return newSafeEngineWithWriters(gin.DefaultWriter, gin.DefaultErrorWriter)
}

func newSafeEngineWithWriters(accessWriter, recoveryWriter io.Writer) *gin.Engine {
	engine := gin.New()
	engine.Use(safeAccessLogger(accessWriter), safeRecovery(recoveryWriter))
	return engine
}

func safeAccessLogger(writer io.Writer) gin.HandlerFunc {
	logger := log.New(writer, "", 0)
	return func(c *gin.Context) {
		started := time.Now()
		c.Next()
		logger.Printf(
			"access method=%q path=%q status=%d latency_ms=%d remote_ip=%q request_id=%q",
			safeLogValue(c.Request.Method), safeRoutePath(c),
			c.Writer.Status(), time.Since(started).Milliseconds(), remoteIP(c.Request.RemoteAddr),
			safeRequestID(c.GetHeader("X-Request-Id")),
		)
	}
}

func safeRecovery(writer io.Writer) gin.HandlerFunc {
	logger := log.New(writer, "", 0)
	return func(c *gin.Context) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.Printf(
					"recovery method=%q path=%q request_id=%q panic_type=%T\n%s",
					safeLogValue(c.Request.Method), safeRoutePath(c),
					safeRequestID(c.GetHeader("X-Request-Id")), recovered, debug.Stack(),
				)
				c.AbortWithStatus(500)
			}
		}()
		c.Next()
	}
}

func safeRoutePath(c *gin.Context) string {
	if c == nil || c.FullPath() == "" {
		return "<unmatched>"
	}
	return safeLogValue(c.FullPath())
}

func safeRequestID(value string) string {
	if len(value) < 1 || len(value) > safeLogValueLimit {
		return ""
	}
	for _, character := range []byte(value) {
		if character != '-' && character != '_' && character != '.' && character != ':' &&
			(character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') {
			return ""
		}
	}
	return value
}

func safeLogValue(value string) string {
	if len(value) > safeLogValueLimit {
		return value[:safeLogValueLimit]
	}
	return value
}

func remoteIP(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return safeLogValue(address)
	}
	return safeLogValue(host)
}
