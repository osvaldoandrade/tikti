package storagests

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxMinIOResponseBytes = 64 << 10

type MinIOClient struct {
	endpoint string
	http     *http.Client
	timeout  time.Duration
	now      func() time.Time
}

func NewMinIOClient(rawEndpoint string, client *http.Client, timeout time.Duration) (*MinIOClient, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawEndpoint))
	if err != nil || client == nil || timeout <= 0 || timeout > 10*time.Second || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.EscapedPath() != "" && parsed.EscapedPath() != "/") || !trustedDependencyScheme(parsed) {
		return nil, ErrInvalidDependencyResponse
	}
	httpClient := *client
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &MinIOClient{endpoint: parsed.String(), http: &httpClient, timeout: timeout, now: time.Now}, nil
}

func (c *MinIOClient) Exchange(ctx context.Context, assertion string, duration int) (Credentials, error) {
	if c == nil || c.http == nil || assertion == "" || len(assertion) > 16<<10 || duration != defaultCredentialTTL {
		return Credentials{}, ErrInvalidDependencyResponse
	}
	form := url.Values{
		"Action": {AWSQueryAction}, "Version": {AWSQueryVersion},
		"WebIdentityToken": {assertion}, "DurationSeconds": {strconv.Itoa(duration)},
	}.Encode()
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.endpoint, strings.NewReader(form))
	if err != nil {
		return Credentials{}, ErrDependencyUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/xml, text/xml")
	response, err := c.http.Do(request)
	if err != nil {
		return Credentials{}, ErrDependencyUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return Credentials{}, ErrDependencyUnavailable
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/xml" && mediaType != "text/xml") {
		return Credentials{}, ErrInvalidDependencyResponse
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxMinIOResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxMinIOResponseBytes {
		zeroBytes(raw)
		return Credentials{}, ErrInvalidDependencyResponse
	}
	defer zeroBytes(raw)
	if !validMinIOXMLShape(raw) {
		return Credentials{}, ErrInvalidDependencyResponse
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.Strict = true
	var responseXML assumeRoleResponseXML
	if err := decoder.Decode(&responseXML); err != nil || responseXML.XMLName.Space != AWSQueryXMLNamespace {
		return Credentials{}, ErrInvalidDependencyResponse
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return Credentials{}, ErrInvalidDependencyResponse
	}
	expiration, err := time.Parse(time.RFC3339, responseXML.Result.Credentials.Expiration)
	if err != nil {
		return Credentials{}, ErrInvalidDependencyResponse
	}
	now := c.now().UTC()
	credentials := Credentials{
		AccessKeyID: responseXML.Result.Credentials.AccessKeyID, SecretAccessKey: responseXML.Result.Credentials.SecretAccessKey,
		SessionToken: responseXML.Result.Credentials.SessionToken, Expiration: expiration.UTC(),
	}
	if !validCredential(credentials.AccessKeyID, 16, 128) || !validCredential(credentials.SecretAccessKey, 16, 256) ||
		!validCredential(credentials.SessionToken, 16, 16<<10) || !credentials.Expiration.After(now) ||
		credentials.Expiration.After(now.Add(time.Duration(duration)*time.Second+5*time.Second)) {
		return Credentials{}, ErrInvalidDependencyResponse
	}
	return credentials, nil
}

func validMinIOXMLShape(raw []byte) bool {
	const root = "AssumeRoleWithWebIdentityResponse"
	const result = root + "/AssumeRoleWithWebIdentityResult"
	const credentials = result + "/Credentials"
	allowed := map[string]struct{}{
		root: {}, result: {}, credentials: {},
		credentials + "/AccessKeyId": {}, credentials + "/SecretAccessKey": {},
		credentials + "/SessionToken": {}, credentials + "/Expiration": {},
		result + "/AssumedRoleUser": {}, result + "/AssumedRoleUser/Arn": {},
		result + "/AssumedRoleUser/AssumedRoleId": {}, result + "/AssumedRoleUser/AssumeRoleId": {},
		result + "/Audience": {}, result + "/Provider": {}, result + "/SubjectFromWebIdentityToken": {},
		result + "/PackedPolicySize": {}, root + "/ResponseMetadata": {}, root + "/ResponseMetadata/RequestId": {},
	}
	required := []string{
		root, result, credentials, credentials + "/AccessKeyId", credentials + "/SecretAccessKey",
		credentials + "/SessionToken", credentials + "/Expiration",
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.Strict = true
	stack := make([]string, 0, 5)
	counts := make(map[string]int, len(allowed))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if len(stack) != 0 {
				return false
			}
			for _, path := range required {
				if counts[path] != 1 {
					return false
				}
			}
			return true
		}
		if err != nil {
			return false
		}
		switch value := token.(type) {
		case xml.StartElement:
			if value.Name.Space != AWSQueryXMLNamespace {
				return false
			}
			stack = append(stack, value.Name.Local)
			path := strings.Join(stack, "/")
			if _, ok := allowed[path]; !ok {
				return false
			}
			counts[path]++
			if counts[path] != 1 {
				return false
			}
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != value.Name.Local {
				return false
			}
			stack = stack[:len(stack)-1]
		case xml.Directive, xml.Comment:
			return false
		case xml.ProcInst:
			if value.Target != "xml" || counts[root] != 0 {
				return false
			}
		}
	}
}

func validCredential(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
