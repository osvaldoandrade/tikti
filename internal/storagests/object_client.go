package storagests

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	awsSigV4Algorithm           = "AWS4-HMAC-SHA256"
	awsS3XMLNamespace           = "http://s3.amazonaws.com/doc/2006-03-01/"
	maxMinIOObjectResponseBytes = 1 << 20
)

type listBucketResultXML struct {
	XMLName               xml.Name           `xml:"ListBucketResult"`
	Name                  string             `xml:"Name"`
	Prefix                string             `xml:"Prefix"`
	MaxKeys               int                `xml:"MaxKeys"`
	IsTruncated           bool               `xml:"IsTruncated"`
	NextContinuationToken string             `xml:"NextContinuationToken"`
	CommonPrefixes        []commonPrefixXML  `xml:"CommonPrefixes"`
	Contents              []objectContentXML `xml:"Contents"`
}

type commonPrefixXML struct {
	Prefix string `xml:"Prefix"`
}

type objectContentXML struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

func (c *MinIOClient) ListObjects(
	ctx context.Context,
	bucket, prefix string,
	pageSize int,
	pageToken, region string,
	credentials Credentials,
) (AdminObjectList, error) {
	if c == nil || c.http == nil || !physicalNamePattern.MatchString(bucket) || !validAdminPrefix(prefix) ||
		pageSize < 1 || pageSize > 200 || len(pageToken) > 2048 || !regionPattern.MatchString(region) ||
		!validAdminCredentials(credentials, c.now()) {
		return AdminObjectList{}, ErrInvalidDependencyResponse
	}
	base, err := url.Parse(c.endpoint)
	if err != nil {
		return AdminObjectList{}, ErrInvalidDependencyResponse
	}
	query := map[string][]string{
		"delimiter": {"/"}, "list-type": {"2"}, "max-keys": {strconv.Itoa(pageSize)},
	}
	if prefix != "" {
		query["prefix"] = []string{prefix}
	}
	if pageToken != "" {
		query["continuation-token"] = []string{pageToken}
	}
	canonicalQuery := awsCanonicalQuery(query)
	canonicalURI := "/" + awsURIEncode(bucket, true)
	now := c.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	payloadHash := awsSHA256Hex(nil)
	canonicalHeaders := "host:" + strings.ToLower(base.Host) + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n" +
		"x-amz-security-token:" + strings.TrimSpace(credentials.SessionToken) + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
	authorization := awsAuthorization(
		http.MethodGet, canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash,
		base.Host, region, now, credentials,
	)
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, strings.TrimRight(c.endpoint, "/")+canonicalURI+"?"+canonicalQuery, nil)
	if err != nil {
		return AdminObjectList{}, ErrDependencyUnavailable
	}
	request.Header.Set("Accept", "application/xml, text/xml")
	request.Header.Set("X-Amz-Date", amzDate)
	request.Header.Set("X-Amz-Content-Sha256", payloadHash)
	request.Header.Set("X-Amz-Security-Token", credentials.SessionToken)
	request.Header.Set("Authorization", authorization)
	response, err := c.http.Do(request)
	if err != nil {
		return AdminObjectList{}, ErrDependencyUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return AdminObjectList{}, ErrDependencyUnavailable
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/xml" && mediaType != "text/xml") {
		return AdminObjectList{}, ErrInvalidDependencyResponse
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxMinIOObjectResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxMinIOObjectResponseBytes || !validListObjectsXMLShape(raw) {
		return AdminObjectList{}, ErrInvalidDependencyResponse
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.Strict = true
	var resultXML listBucketResultXML
	if err := decoder.Decode(&resultXML); err != nil || resultXML.XMLName.Space != awsS3XMLNamespace ||
		resultXML.Name != bucket || resultXML.Prefix != prefix || resultXML.MaxKeys != pageSize ||
		len(resultXML.NextContinuationToken) > 2048 || len(resultXML.CommonPrefixes)+len(resultXML.Contents) > pageSize {
		return AdminObjectList{}, ErrInvalidDependencyResponse
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return AdminObjectList{}, ErrInvalidDependencyResponse
	}
	items := make([]AdminObject, 0, len(resultXML.CommonPrefixes)+len(resultXML.Contents))
	seenKeys := make(map[string]struct{}, cap(items))
	for _, folder := range resultXML.CommonPrefixes {
		if !strings.HasPrefix(folder.Prefix, prefix) || !strings.HasSuffix(folder.Prefix, "/") || !validAdminPrefix(folder.Prefix) {
			return AdminObjectList{}, ErrInvalidDependencyResponse
		}
		if _, duplicate := seenKeys[folder.Prefix]; duplicate {
			return AdminObjectList{}, ErrInvalidDependencyResponse
		}
		seenKeys[folder.Prefix] = struct{}{}
		items = append(items, AdminObject{Key: folder.Prefix, Kind: "prefix"})
	}
	for _, object := range resultXML.Contents {
		modified, parseErr := time.Parse(time.RFC3339Nano, object.LastModified)
		if !strings.HasPrefix(object.Key, prefix) || !validAdminObjectKey(object.Key) || object.Size < 0 || parseErr != nil || !validAdminStrongETag(object.ETag) {
			return AdminObjectList{}, ErrInvalidDependencyResponse
		}
		if _, duplicate := seenKeys[object.Key]; duplicate {
			return AdminObjectList{}, ErrInvalidDependencyResponse
		}
		seenKeys[object.Key] = struct{}{}
		items = append(items, AdminObject{
			Key: object.Key, Kind: "object", Size: object.Size, LastModified: modified.UTC().Format(time.RFC3339Nano), ETag: object.ETag,
		})
	}
	if resultXML.IsTruncated && resultXML.NextContinuationToken == "" || !resultXML.IsTruncated && resultXML.NextContinuationToken != "" {
		return AdminObjectList{}, ErrInvalidDependencyResponse
	}
	return AdminObjectList{
		SchemaVersion: AdminObjectStorageVersion, Prefix: prefix, Items: items,
		NextPageToken: resultXML.NextContinuationToken,
	}, nil
}

// DeleteObject performs ordinary S3 DeleteObject for the current view only.
// The strong If-Match condition prevents deleting a replacement object and a
// one object HEAD plus a bucket-existence probe resolves an ambiguous replay
// without addressing any version ID. Every unclassified 404 fails closed.
func (c *MinIOClient) DeleteObject(
	ctx context.Context,
	bucket, key, etag, region string,
	credentials Credentials,
) error {
	if c == nil || c.http == nil || !physicalNamePattern.MatchString(bucket) || !validAdminObjectKey(key) ||
		!validAdminStrongETag(etag) || !regionPattern.MatchString(region) || !validAdminCredentials(credentials, c.now()) {
		return ErrInvalidDependencyResponse
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	response, err := c.signedObjectRequest(requestCtx, http.MethodDelete, bucket, key, etag, region, credentials)
	if err != nil {
		return err
	}
	status := response.StatusCode
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxMinIOObjectResponseBytes))
	_ = response.Body.Close()
	switch status {
	case http.StatusNoContent:
		return nil
	case http.StatusPreconditionFailed:
		return c.resolveConditionalDelete(requestCtx, bucket, key, etag, region, credentials)
	default:
		return ErrDependencyUnavailable
	}
}

func (c *MinIOClient) resolveConditionalDelete(
	ctx context.Context,
	bucket, key, listedETag, region string,
	credentials Credentials,
) error {
	response, err := c.signedObjectRequest(ctx, http.MethodHead, bucket, key, "", region, credentials)
	if err != nil {
		return err
	}
	status := response.StatusCode
	errorCode := strings.TrimSpace(response.Header.Get("X-Minio-Error-Code"))
	currentETag := strings.TrimSpace(response.Header.Get("ETag"))
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxMinIOObjectResponseBytes))
	_ = response.Body.Close()
	switch status {
	case http.StatusNotFound:
		if errorCode != "NoSuchKey" {
			return ErrDependencyUnavailable
		}
		return c.requireBucketExists(ctx, bucket, region, credentials)
	case http.StatusOK:
		if validAdminStrongETag(currentETag) && currentETag != listedETag {
			return ErrAdminObjectChanged
		}
	}
	return ErrDependencyUnavailable
}

func (c *MinIOClient) requireBucketExists(
	ctx context.Context,
	bucket, region string,
	credentials Credentials,
) error {
	response, err := c.signedS3Request(ctx, http.MethodHead, bucket, "", "", region, credentials)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxMinIOObjectResponseBytes))
	if response.StatusCode != http.StatusOK {
		return ErrDependencyUnavailable
	}
	return nil
}

func (c *MinIOClient) signedObjectRequest(
	ctx context.Context,
	method, bucket, key, etag, region string,
	credentials Credentials,
) (*http.Response, error) {
	return c.signedS3Request(ctx, method, bucket, key, etag, region, credentials)
}

func (c *MinIOClient) signedS3Request(
	ctx context.Context,
	method, bucket, key, etag, region string,
	credentials Credentials,
) (*http.Response, error) {
	base, err := url.Parse(c.endpoint)
	if err != nil {
		return nil, ErrInvalidDependencyResponse
	}
	now := c.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	payloadHash := awsSHA256Hex(nil)
	canonicalURI := "/" + awsURIEncode(bucket, true)
	if key != "" {
		canonicalURI += "/" + awsURIEncode(key, false)
	}
	canonicalHeaders := "host:" + strings.ToLower(base.Host) + "\n"
	signedHeaders := "host"
	if etag != "" {
		canonicalHeaders += "if-match:" + etag + "\n"
		signedHeaders += ";if-match"
	}
	canonicalHeaders += "x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n" +
		"x-amz-security-token:" + strings.TrimSpace(credentials.SessionToken) + "\n"
	signedHeaders += ";x-amz-content-sha256;x-amz-date;x-amz-security-token"
	authorization := awsAuthorization(
		method, canonicalURI, "", canonicalHeaders, signedHeaders, payloadHash,
		base.Host, region, now, credentials,
	)
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.endpoint, "/")+canonicalURI, nil)
	if err != nil {
		return nil, ErrDependencyUnavailable
	}
	request.Header.Set("X-Amz-Date", amzDate)
	request.Header.Set("X-Amz-Content-Sha256", payloadHash)
	request.Header.Set("X-Amz-Security-Token", credentials.SessionToken)
	request.Header.Set("Authorization", authorization)
	if etag != "" {
		request.Header.Set("If-Match", etag)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, ErrDependencyUnavailable
	}
	return response, nil
}

func (c *MinIOClient) Presign(
	now time.Time,
	endpoint, bucket, key, contentType, method, region string,
	ttl int,
	credentials Credentials,
) (AdminSignedURL, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" ||
		!physicalNamePattern.MatchString(bucket) || !validAdminObjectKey(key) || !regionPattern.MatchString(region) ||
		(method != http.MethodGet && method != http.MethodPut) || ttl != adminPresignTTL ||
		(method == http.MethodPut && !validAdminContentType(contentType)) || method == http.MethodGet && contentType != "" ||
		!validAdminCredentials(credentials, now) || !credentials.Expiration.After(now.UTC().Add(time.Duration(ttl)*time.Second)) {
		return AdminSignedURL{}, ErrInvalidDependencyResponse
	}
	now = now.UTC().Truncate(time.Second)
	date := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")
	scope := date + "/" + region + "/s3/aws4_request"
	signedHeaders := "host"
	canonicalHeaders := "host:" + strings.ToLower(parsed.Host) + "\n"
	if method == http.MethodPut {
		signedHeaders = "content-type;host"
		canonicalHeaders = "content-type:" + strings.TrimSpace(contentType) + "\n" + canonicalHeaders
	}
	query := map[string][]string{
		"X-Amz-Algorithm":      {awsSigV4Algorithm},
		"X-Amz-Credential":     {credentials.AccessKeyID + "/" + scope},
		"X-Amz-Date":           {amzDate},
		"X-Amz-Expires":        {strconv.Itoa(ttl)},
		"X-Amz-Security-Token": {credentials.SessionToken},
		"X-Amz-SignedHeaders":  {signedHeaders},
	}
	if method == http.MethodGet {
		filename := key
		if separator := strings.LastIndex(filename, "/"); separator >= 0 {
			filename = filename[separator+1:]
		}
		query["response-content-disposition"] = []string{mime.FormatMediaType("attachment", map[string]string{"filename": filename})}
	}
	canonicalQuery := awsCanonicalQuery(query)
	canonicalURI := "/" + awsURIEncode(bucket, true) + "/" + awsURIEncode(key, false)
	canonicalRequest := strings.Join([]string{
		method, canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, "UNSIGNED-PAYLOAD",
	}, "\n")
	stringToSign := awsSigV4Algorithm + "\n" + amzDate + "\n" + scope + "\n" + awsSHA256Hex([]byte(canonicalRequest))
	signature := hex.EncodeToString(hmacSHA256(awsSigningKey(credentials.SecretAccessKey, date, region, "s3"), []byte(stringToSign)))
	result := AdminSignedURL{
		URL:    "https://" + parsed.Host + canonicalURI + "?" + canonicalQuery + "&X-Amz-Signature=" + signature,
		Method: method, ExpiresIn: ttl,
	}
	if method == http.MethodPut {
		result.Headers = map[string]string{"Content-Type": contentType}
	}
	return result, nil
}

func awsAuthorization(method, uri, query, headers, signedHeaders, payloadHash, host, region string, now time.Time, credentials Credentials) string {
	date := now.UTC().Format("20060102")
	amzDate := now.UTC().Format("20060102T150405Z")
	scope := date + "/" + region + "/s3/aws4_request"
	canonicalRequest := strings.Join([]string{method, uri, query, headers, signedHeaders, payloadHash}, "\n")
	stringToSign := awsSigV4Algorithm + "\n" + amzDate + "\n" + scope + "\n" + awsSHA256Hex([]byte(canonicalRequest))
	signature := hex.EncodeToString(hmacSHA256(awsSigningKey(credentials.SecretAccessKey, date, region, "s3"), []byte(stringToSign)))
	return awsSigV4Algorithm + " Credential=" + credentials.AccessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

func awsSigningKey(secret, date, region, service string) []byte {
	dateKey := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	regionKey := hmacSHA256(dateKey, []byte(region))
	serviceKey := hmacSHA256(regionKey, []byte(service))
	return hmacSHA256(serviceKey, []byte("aws4_request"))
}

func hmacSHA256(key, value []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(value)
	return mac.Sum(nil)
}

func awsSHA256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func awsCanonicalQuery(values map[string][]string) string {
	type pair struct{ key, value string }
	pairs := make([]pair, 0, len(values))
	for key, entries := range values {
		for _, value := range entries {
			pairs = append(pairs, pair{key: awsURIEncode(key, true), value: awsURIEncode(value, true)})
		}
	}
	sort.Slice(pairs, func(left, right int) bool {
		return pairs[left].key < pairs[right].key || pairs[left].key == pairs[right].key && pairs[left].value < pairs[right].value
	})
	encoded := make([]string, len(pairs))
	for index, item := range pairs {
		encoded[index] = item.key + "=" + item.value
	}
	return strings.Join(encoded, "&")
}

// awsURIEncode follows the SigV4 percent-encoding rules. slashSafe controls
// whether slash is encoded; object keys preserve separators while all query
// values encode them.
func awsURIEncode(value string, encodeSlash bool) string {
	var builder strings.Builder
	for _, character := range []byte(value) {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' || character == '~' ||
			character == '/' && !encodeSlash {
			builder.WriteByte(character)
			continue
		}
		builder.WriteString(fmt.Sprintf("%%%02X", character))
	}
	return builder.String()
}

func validAdminCredentials(credentials Credentials, now time.Time) bool {
	return validCredential(credentials.AccessKeyID, 16, 128) && validCredential(credentials.SecretAccessKey, 16, 256) &&
		validCredential(credentials.SessionToken, 16, 16<<10) && credentials.Expiration.After(now.UTC())
}

func validListObjectsXMLShape(raw []byte) bool {
	const root = "ListBucketResult"
	allowed := map[string]struct{}{
		root: {}, root + "/Name": {}, root + "/Prefix": {}, root + "/KeyCount": {}, root + "/MaxKeys": {},
		root + "/Delimiter": {}, root + "/IsTruncated": {}, root + "/ContinuationToken": {},
		root + "/NextContinuationToken": {}, root + "/StartAfter": {}, root + "/EncodingType": {},
		root + "/CommonPrefixes": {}, root + "/CommonPrefixes/Prefix": {},
		root + "/Contents": {}, root + "/Contents/Key": {}, root + "/Contents/LastModified": {},
		root + "/Contents/ETag": {}, root + "/Contents/Size": {}, root + "/Contents/StorageClass": {},
		root + "/Contents/Owner": {}, root + "/Contents/Owner/ID": {}, root + "/Contents/Owner/DisplayName": {},
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	decoder.Strict = true
	stack := make([]string, 0, 4)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return len(stack) == 0
		}
		if err != nil {
			return false
		}
		switch value := token.(type) {
		case xml.StartElement:
			if value.Name.Space != awsS3XMLNamespace {
				return false
			}
			stack = append(stack, value.Name.Local)
			if _, ok := allowed[strings.Join(stack, "/")]; !ok {
				return false
			}
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != value.Name.Local {
				return false
			}
			stack = stack[:len(stack)-1]
		case xml.Comment, xml.Directive:
			return false
		case xml.ProcInst:
			if value.Target != "xml" || len(stack) != 0 {
				return false
			}
		}
	}
}
