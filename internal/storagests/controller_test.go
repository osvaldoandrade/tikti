package storagests

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type fakeBroker struct {
	result Result
	err    *Error
}

func (f fakeBroker) Exchange(context.Context, Request, string) (Result, *Error) {
	return f.result, f.err
}

func TestControllerReturnsAWSXMLWithoutCacheOrCORS(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	broker := fakeBroker{result: Result{
		Credentials:    Credentials{AccessKeyID: "MINIOACCESSKEY123456", SecretAccessKey: "secret<&key", SessionToken: "session-token", Expiration: now.Add(15 * time.Minute)},
		AssumedRoleARN: "arn:aws:sts::000000000000:assumed-role/codefoundry-payments-api-invoices/session",
		AssumedRoleID:  "1234567890abcdef:session", Audience: "tikti-workload-exchange",
		Provider: "https://cluster.example.com", Subject: "system:serviceaccount:workload-payments:payments-api",
	}}
	controller := NewController(testAccountID, broker, nil)
	engine := gin.New()
	engine.POST("/v1/storage/sts", controller.Handle)
	form := url.Values{"Action": {AWSQueryAction}, "Version": {AWSQueryVersion}, "RoleArn": {testRoleARN}, "WebIdentityToken": {testJWT}}
	request := httptest.NewRequest(http.MethodPost, "/v1/storage/sts", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-Request-Id", "request-storage-1")
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Pragma") != "no-cache" || response.Header().Get("Access-Control-Allow-Origin") != "" ||
		!strings.Contains(response.Header().Get("Content-Type"), "application/xml") {
		t.Fatalf("response=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var parsed assumeRoleResponseXML
	if err := xml.Unmarshal(response.Body.Bytes(), &parsed); err != nil || parsed.XMLNS != AWSQueryXMLNamespace ||
		parsed.Result.Credentials.SecretAccessKey != "secret<&key" || parsed.Metadata.RequestID != "request-storage-1" {
		t.Fatalf("XML=%#v error=%v body=%s", parsed, err, response.Body.String())
	}
}

func TestControllerErrorsNeverEchoIdentityOrCredentials(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		body   string
		broker fakeBroker
		status int
		code   Code
	}{
		{name: "parser", body: "WebIdentityToken=projected-secret-sentinel&RoleArn=secret-role", status: 400, code: CodeInvalidParameterValue},
		{name: "denied", body: validStorageForm(), broker: fakeBroker{err: &Error{Code: CodeAccessDenied, HTTPStatus: 403, Reason: "denied", Message: "Access is denied."}}, status: 403, code: CodeAccessDenied},
		{name: "provider", body: validStorageForm(), broker: fakeBroker{err: &Error{Code: CodeInternalFailure, HTTPStatus: 500, Reason: "provider_invalid", Message: "The request could not be completed."}}, status: 500, code: CodeInternalFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller := NewController(testAccountID, test.broker, nil)
			engine := gin.New()
			engine.POST("/v1/storage/sts", controller.Handle)
			request := httptest.NewRequest(http.MethodPost, "/v1/storage/sts", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, request)
			body := response.Body.String()
			if response.Code != test.status || !strings.Contains(body, "<Code>"+string(test.code)+"</Code>") ||
				strings.Contains(body, "projected-secret-sentinel") || strings.Contains(body, "secret-role") || strings.Contains(body, "credential") {
				t.Fatalf("response=%d %s", response.Code, body)
			}
		})
	}
}

func validStorageForm() string {
	return url.Values{"Action": {AWSQueryAction}, "Version": {AWSQueryVersion}, "RoleArn": {testRoleARN}, "WebIdentityToken": {testJWT}}.Encode()
}
