package storagests

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	testAccountID = "000000000000"
	testRoleARN   = "arn:aws:iam::000000000000:role/codefoundry/payments/workload-payments/payments-api-invoices"
	testJWT       = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6d29ya2xvYWQtcGF5bWVudHM6cGF5bWVudHMtYXBpIn0.c2lnbmF0dXJl" // gitleaks:allow -- deliberately invalid public test fixture
)

func TestParseRequestAcceptsOnlyTheBoundedAWSQueryContract(t *testing.T) {
	t.Parallel()
	values := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {testRoleARN},
		"RoleSessionName":  {"payments-api-1"},
		"WebIdentityToken": {testJWT},
		"DurationSeconds":  {"900"},
	}
	request := formRequest(t, values.Encode())

	parsed, stsErr := ParseRequest(request, testAccountID)
	if stsErr != nil {
		t.Fatalf("ParseRequest() error = %#v", stsErr)
	}
	if parsed.RoleARN != testRoleARN || parsed.Role.TenantID != "payments" ||
		parsed.Role.Namespace != "workload-payments" || parsed.Role.BindingName != "payments-api-invoices" ||
		parsed.RoleSessionName != "payments-api-1" || parsed.WebIdentityToken != testJWT || parsed.DurationSeconds != 900 {
		t.Fatalf("ParseRequest() = %#v", parsed)
	}
}

func TestParseRequestUsesDeterministicSafeSessionDefault(t *testing.T) {
	t.Parallel()
	values := url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"},
		"RoleArn": {testRoleARN}, "WebIdentityToken": {testJWT},
	}
	first, firstErr := ParseRequest(formRequest(t, values.Encode()), testAccountID)
	second, secondErr := ParseRequest(formRequest(t, values.Encode()), testAccountID)
	if firstErr != nil || secondErr != nil || first.RoleSessionName != second.RoleSessionName ||
		len(first.RoleSessionName) < 2 || len(first.RoleSessionName) > 64 {
		t.Fatalf("defaults = %#v %#v errors=%v/%v", first, second, firstErr, secondErr)
	}
}

func TestParseRequestRejectsEverythingOutsideTheExactContract(t *testing.T) {
	t.Parallel()
	base := url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"},
		"RoleArn": {testRoleARN}, "WebIdentityToken": {testJWT},
	}
	for _, test := range []struct {
		name        string
		method      string
		body        string
		contentType string
		target      string
		chunked     bool
	}{
		{name: "method", method: http.MethodGet, body: base.Encode()},
		{name: "query", body: base.Encode(), target: "/v1/storage/sts?Action=AssumeRoleWithWebIdentity"},
		{name: "content type", body: base.Encode(), contentType: "application/json"},
		{name: "duplicate", body: base.Encode() + "&RoleArn=" + url.QueryEscape(testRoleARN)},
		{name: "unknown", body: base.Encode() + "&Policy=%7B%7D"},
		{name: "provider id", body: base.Encode() + "&ProviderId=example"},
		{name: "alternate action", body: strings.Replace(base.Encode(), "AssumeRoleWithWebIdentity", "AssumeRole", 1)},
		{name: "alternate version", body: strings.Replace(base.Encode(), "2011-06-15", "2010-05-08", 1)},
		{name: "foreign account", body: strings.Replace(base.Encode(), testAccountID, "111111111111", 1)},
		{name: "uppercase tenant", body: strings.Replace(base.Encode(), "payments%2F", "Payments%2F", 1)},
		{name: "foreign namespace", body: strings.Replace(base.Encode(), "workload-payments", "workload-other", 1)},
		{name: "invalid jwt", body: strings.Replace(base.Encode(), url.QueryEscape(testJWT), "not-a-jwt", 1)},
		{name: "oversized token", body: "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn=" + url.QueryEscape(testRoleARN) + "&WebIdentityToken=" + strings.Repeat("a", maxWebIdentityTokenBytes+1)},
		{name: "unreviewed duration", body: base.Encode() + "&DurationSeconds=901"},
		{name: "invalid session", body: base.Encode() + "&RoleSessionName=a%2Fb"},
		{name: "too many parameters", body: base.Encode() + "&a=1&b=2&c=3&d=4&e=5"},
		{name: "oversized chunked body", body: strings.Repeat("x", maxRequestBodyBytes+1), chunked: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			method := test.method
			if method == "" {
				method = http.MethodPost
			}
			target := test.target
			if target == "" {
				target = "/v1/storage/sts"
			}
			request := httptest.NewRequest(method, target, strings.NewReader(test.body))
			contentType := test.contentType
			if contentType == "" {
				contentType = "application/x-www-form-urlencoded"
			}
			request.Header.Set("Content-Type", contentType)
			if test.chunked {
				request.ContentLength = -1
				request.TransferEncoding = []string{"chunked"}
			}
			if _, stsErr := ParseRequest(request, testAccountID); stsErr == nil || stsErr.Code != CodeInvalidParameterValue {
				t.Fatalf("ParseRequest() error = %#v", stsErr)
			}
		})
	}
}

func FuzzParseRequestNeverPanics(f *testing.F) {
	f.Add("Action=AssumeRoleWithWebIdentity&Version=2011-06-15")
	f.Add("%")
	f.Fuzz(func(t *testing.T, body string) {
		request := httptest.NewRequest(http.MethodPost, "/v1/storage/sts", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = ParseRequest(request, testAccountID)
	})
}

func formRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/storage/sts", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}
