package storagests

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const maxQueryParameters = 8

var (
	accountIDPattern  = regexp.MustCompile(`^[0-9]{12}$`)
	tenantIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	dnsLabelPattern   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	sessionPattern    = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{2,64}$`)
	jwtSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

var allowedQueryParameters = map[string]struct{}{
	"Action": {}, "Version": {}, "RoleArn": {}, "RoleSessionName": {},
	"WebIdentityToken": {}, "DurationSeconds": {},
}

// ParseRequest accepts only the reviewed AWS Query subset. The role is parsed
// as a lookup key and must still be authorized against current platform state.
func ParseRequest(request *http.Request, syntheticAccountID string) (Request, *Error) {
	if request == nil || request.Method != http.MethodPost || request.URL == nil ||
		request.URL.RawQuery != "" || !accountIDPattern.MatchString(syntheticAccountID) {
		return Request{}, invalidParameterError()
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || !validContentTypeParameters(parameters) {
		return Request{}, invalidParameterError()
	}
	if request.ContentLength > maxRequestBodyBytes {
		return Request{}, invalidParameterError()
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBodyBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxRequestBodyBytes {
		zeroBytes(raw)
		return Request{}, invalidParameterError()
	}
	defer zeroBytes(raw)
	values, err := url.ParseQuery(string(raw))
	if err != nil || len(values) == 0 {
		return Request{}, invalidParameterError()
	}
	parameterCount := 0
	for key, items := range values {
		parameterCount += len(items)
		if _, allowed := allowedQueryParameters[key]; !allowed || len(items) != 1 {
			return Request{}, invalidParameterError()
		}
	}
	if parameterCount > maxQueryParameters || one(values, "Action") != AWSQueryAction ||
		one(values, "Version") != AWSQueryVersion {
		return Request{}, invalidParameterError()
	}

	roleARN := one(values, "RoleArn")
	role, valid := parseRole(roleARN, syntheticAccountID)
	if !valid {
		return Request{}, invalidParameterError()
	}
	token := one(values, "WebIdentityToken")
	if !validCompactJWT(token) {
		return Request{}, invalidParameterError()
	}
	sessionName := one(values, "RoleSessionName")
	if sessionName == "" {
		digest := sha256.Sum256([]byte(token))
		sessionName = "cf-" + hex.EncodeToString(digest[:10])
	}
	if !sessionPattern.MatchString(sessionName) {
		return Request{}, invalidParameterError()
	}
	duration := one(values, "DurationSeconds")
	if duration != "" && duration != "900" {
		return Request{}, invalidParameterError()
	}
	return Request{
		RoleARN: roleARN, Role: role, RoleSessionName: sessionName,
		WebIdentityToken: token, DurationSeconds: defaultCredentialTTL,
	}, nil
}

func validContentTypeParameters(parameters map[string]string) bool {
	if len(parameters) == 0 {
		return true
	}
	return len(parameters) == 1 && strings.EqualFold(parameters["charset"], "utf-8")
}

func one(values url.Values, key string) string {
	items := values[key]
	if len(items) != 1 {
		return ""
	}
	return items[0]
}

func parseRole(roleARN, accountID string) (Role, bool) {
	if len(roleARN) < 1 || len(roleARN) > 512 || !ascii(roleARN) {
		return Role{}, false
	}
	prefix := "arn:aws:iam::" + accountID + ":role/codefoundry/"
	if !strings.HasPrefix(roleARN, prefix) {
		return Role{}, false
	}
	parts := strings.Split(strings.TrimPrefix(roleARN, prefix), "/")
	if len(parts) != 3 || !tenantIDPattern.MatchString(parts[0]) ||
		!validDNSLabel(parts[1]) || !validDNSLabel(parts[2]) || parts[1] != "workload-"+parts[0] {
		return Role{}, false
	}
	return Role{AccountID: accountID, TenantID: parts[0], Namespace: parts[1], BindingName: parts[2]}, true
}

func validDNSLabel(value string) bool {
	return len(value) >= 1 && len(value) <= 63 && dnsLabelPattern.MatchString(value)
}

func validCompactJWT(value string) bool {
	if len(value) < 5 || len(value) > maxWebIdentityTokenBytes || strings.TrimSpace(value) != value {
		return false
	}
	parts := strings.Split(value, ".")
	return len(parts) == 3 && jwtSegmentPattern.MatchString(parts[0]) &&
		jwtSegmentPattern.MatchString(parts[1]) && jwtSegmentPattern.MatchString(parts[2])
}

func ascii(value string) bool {
	for index := range []byte(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
