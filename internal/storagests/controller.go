package storagests

import (
	"encoding/xml"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Controller struct {
	accountID string
	broker    Broker
	metrics   *Metrics
}

func NewController(accountID string, broker Broker, metrics *Metrics) *Controller {
	return &Controller{accountID: accountID, broker: broker, metrics: metrics}
}

func (c *Controller) Handle(ctx *gin.Context) {
	started := time.Now()
	removeCORSHeaders(ctx)
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
	ctx.Header("X-Content-Type-Options", "nosniff")
	requestID := boundedRequestID(ctx.GetHeader("X-Request-Id"))
	request, parseErr := ParseRequest(ctx.Request, c.accountID)
	if parseErr != nil {
		c.metrics.observeRequest("error", "invalid_request", started)
		writeErrorXML(ctx, parseErr.Code, requestID)
		return
	}
	if c.broker == nil {
		c.metrics.observeRequest("error", "internal", started)
		writeErrorXML(ctx, CodeServiceUnavailable, requestID)
		return
	}
	result, stsErr := c.broker.Exchange(ctx.Request.Context(), request, requestID)
	if stsErr != nil {
		c.metrics.observeRequest("error", stsErr.Reason, started)
		writeErrorXML(ctx, stsErr.Code, requestID)
		return
	}
	response := assumeRoleResponseXML{
		XMLNS: AWSQueryXMLNamespace,
		Result: assumeRoleResultXML{
			Audience:        result.Audience,
			AssumedRoleUser: assumedRoleUserXML{ARN: result.AssumedRoleARN, ID: result.AssumedRoleID},
			Credentials: credentialsXML{
				AccessKeyID: result.Credentials.AccessKeyID, SecretAccessKey: result.Credentials.SecretAccessKey,
				SessionToken: result.Credentials.SessionToken, Expiration: result.Credentials.Expiration.UTC().Format(time.RFC3339),
			},
			PackedPolicySize: 0, Provider: result.Provider, SubjectFromWebIdentityToken: result.Subject,
		},
		Metadata: responseMetadataXML{RequestID: requestID},
	}
	raw, err := xml.Marshal(response)
	if err != nil {
		c.metrics.observeRequest("error", "internal", started)
		writeErrorXML(ctx, CodeInternalFailure, requestID)
		return
	}
	c.metrics.observeRequest("success", "allowed", started)
	removeCORSHeaders(ctx)
	ctx.Data(http.StatusOK, "application/xml; charset=utf-8", append([]byte(xml.Header), raw...))
}

// RejectAlias prevents Gin from redirecting a secret-bearing POST sent with a
// trailing slash. The public contract has one exact path.
func (c *Controller) RejectAlias(ctx *gin.Context) {
	removeCORSHeaders(ctx)
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("Pragma", "no-cache")
	ctx.Header("X-Content-Type-Options", "nosniff")
	writeErrorXML(ctx, CodeInvalidParameterValue, boundedRequestID(ctx.GetHeader("X-Request-Id")))
}

func writeErrorXML(ctx *gin.Context, code Code, requestID string) {
	response := errorResponseXML{
		XMLNS:     AWSQueryXMLNamespace,
		Error:     errorDetailXML{Type: errorType(code), Code: string(code), Message: messageForCode(code)},
		RequestID: requestID,
	}
	raw, err := xml.Marshal(response)
	if err != nil {
		ctx.Status(http.StatusInternalServerError)
		return
	}
	removeCORSHeaders(ctx)
	ctx.Data(statusForCode(code), "application/xml; charset=utf-8", append([]byte(xml.Header), raw...))
}

func errorType(code Code) string {
	switch code {
	case CodeInvalidParameterValue, CodeInvalidIdentityToken, CodeAccessDenied, CodeThrottling:
		return "Sender"
	default:
		return "Receiver"
	}
}

func boundedRequestID(raw string) string {
	raw = strings.TrimSpace(raw)
	if opaqueIDPattern.MatchString(raw) {
		return raw
	}
	return uuid.NewString()
}

func removeCORSHeaders(ctx *gin.Context) {
	if ctx == nil {
		return
	}
	for key := range ctx.Writer.Header() {
		if strings.HasPrefix(strings.ToLower(key), "access-control-") {
			ctx.Writer.Header().Del(key)
		}
	}
}
