package storagests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type administrativeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f administrativeRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestMinIOClientListsObjectsWithSessionSigV4AndBoundedXML(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/cf-payments-invoices-47e89ff7e282" ||
			r.URL.Query().Get("list-type") != "2" || r.URL.Query().Get("delimiter") != "/" ||
			r.URL.Query().Get("prefix") != "reports/" || r.URL.Query().Get("max-keys") != "25" ||
			r.URL.Query().Get("continuation-token") != "opaque-page" {
			t.Fatalf("request=%s %s", r.Method, r.URL.String())
		}
		if r.Header.Get("X-Amz-Security-Token") != "session-token-value-1234567890" ||
			r.Header.Get("X-Amz-Content-Sha256") != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ||
			!strings.Contains(r.Header.Get("Authorization"), "Credential=ABCDEFGHIJKLMNOPQRST/") ||
			!strings.Contains(r.Header.Get("Authorization"), "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token") {
			t.Fatalf("signature headers=%v", r.Header)
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>cf-payments-invoices-47e89ff7e282</Name><Prefix>reports/</Prefix><KeyCount>2</KeyCount><MaxKeys>25</MaxKeys><Delimiter>/</Delimiter><IsTruncated>true</IsTruncated><NextContinuationToken>next-page</NextContinuationToken><CommonPrefixes><Prefix>reports/2026/</Prefix></CommonPrefixes><Contents><Key>reports/a.txt</Key><LastModified>2026-08-31T12:00:00.000Z</LastModified><ETag>&quot;etag&quot;</ETag><Size>12</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>`))
	}))
	defer server.Close()
	client, err := NewMinIOClient(server.URL, server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC) }
	result, err := client.ListObjects(context.Background(), "cf-payments-invoices-47e89ff7e282", "reports/", 25, "opaque-page", "us-central1", adminTestCredentialsAt(client.now()))
	if err != nil || result.SchemaVersion != AdminObjectStorageVersion || result.Prefix != "reports/" || result.NextPageToken != "next-page" || len(result.Items) != 2 ||
		result.Items[0].Kind != "prefix" || result.Items[0].Key != "reports/2026/" || result.Items[1].Key != "reports/a.txt" || result.Items[1].Size != 12 || result.Items[1].ETag != `"etag"` {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestMinIOClientConditionallyDeletesCurrentObjectWithSignedETag(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/cf-payments-invoices-47e89ff7e282/reports/a.txt" || r.URL.RawQuery != "" {
			t.Fatalf("request=%s %s", r.Method, r.URL.String())
		}
		if r.Header.Get("If-Match") != `"etag"` || r.Header.Get("X-Amz-Security-Token") != "session-token-value-1234567890" ||
			!strings.Contains(r.Header.Get("Authorization"), "SignedHeaders=host;if-match;x-amz-content-sha256;x-amz-date;x-amz-security-token") {
			t.Fatalf("headers=%v", r.Header)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := NewMinIOClient(server.URL, server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC) }
	if err := client.DeleteObject(
		context.Background(), "cf-payments-invoices-47e89ff7e282", "reports/a.txt", `"etag"`,
		"us-central1", adminTestCredentialsAt(client.now()),
	); err != nil {
		t.Fatal(err)
	}
}

func TestMinIOClientResolvesConditionalDeleteReplayWithoutDeletingAVersion(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name          string
		headStatus    int
		headETag      string
		headErrorCode string
		bucketStatus  int
		want          error
		wantCalls     int
	}{
		{name: "already absent", headStatus: http.StatusNotFound, headErrorCode: "NoSuchKey", bucketStatus: http.StatusOK, wantCalls: 3},
		{name: "bucket absent is ambiguous", headStatus: http.StatusNotFound, headErrorCode: "NoSuchKey", bucketStatus: http.StatusNotFound, want: ErrDependencyUnavailable, wantCalls: 3},
		{name: "provider says bucket absent", headStatus: http.StatusNotFound, headErrorCode: "NoSuchBucket", want: ErrDependencyUnavailable, wantCalls: 2},
		{name: "unclassified not found is ambiguous", headStatus: http.StatusNotFound, want: ErrDependencyUnavailable, wantCalls: 2},
		{name: "changed", headStatus: http.StatusOK, headETag: `"new-etag"`, want: ErrAdminObjectChanged, wantCalls: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls == 1 {
					if r.Method != http.MethodDelete || r.Header.Get("If-Match") != `"etag"` {
						t.Fatalf("delete request=%s headers=%v", r.Method, r.Header)
					}
					w.WriteHeader(http.StatusPreconditionFailed)
					return
				}
				if r.Method != http.MethodHead || r.Header.Get("If-Match") != "" {
					t.Fatalf("resolution request=%s headers=%v", r.Method, r.Header)
				}
				if calls == 3 {
					if r.URL.Path != "/cf-payments-invoices-47e89ff7e282" {
						t.Fatalf("bucket probe path=%s", r.URL.Path)
					}
					w.WriteHeader(test.bucketStatus)
					return
				}
				if test.headETag != "" {
					w.Header().Set("ETag", test.headETag)
				}
				if test.headErrorCode != "" {
					w.Header().Set("X-Minio-Error-Code", test.headErrorCode)
				}
				w.WriteHeader(test.headStatus)
			}))
			defer server.Close()
			client, err := NewMinIOClient(server.URL, server.Client(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			client.now = func() time.Time { return time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC) }
			err = client.DeleteObject(
				context.Background(), "cf-payments-invoices-47e89ff7e282", "reports/a.txt", `"etag"`,
				"us-central1", adminTestCredentialsAt(client.now()),
			)
			if !errors.Is(err, test.want) || calls != test.wantCalls {
				t.Fatalf("error=%v want=%v calls=%d wantCalls=%d", err, test.want, calls, test.wantCalls)
			}
		})
	}
}

func TestMinIOClientRejectsEveryDirectDeleteNotFoundAsAmbiguous(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, body string
		want       error
	}{
		{name: "object not found remains ambiguous", body: `<Error><Code>NoSuchKey</Code><Message>absent</Message></Error>`, want: ErrDependencyUnavailable},
		{name: "bucket absent", body: `<Error><Code>NoSuchBucket</Code><Message>absent</Message></Error>`, want: ErrDependencyUnavailable},
		{name: "malformed error", body: `<Error><Code>NoSuchKey`, want: ErrDependencyUnavailable},
		{name: "unknown provider code", body: `<Error><Code>UnknownNotFound</Code></Error>`, want: ErrDependencyUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			client, err := NewMinIOClient(server.URL, server.Client(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			client.now = func() time.Time { return time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC) }
			err = client.DeleteObject(
				context.Background(), "cf-payments-invoices-47e89ff7e282", "reports/a.txt", `"etag"`,
				"us-central1", adminTestCredentialsAt(client.now()),
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestMinIOClientDoesNotRetryAfterDeleteTransmissionFailure(t *testing.T) {
	t.Parallel()
	calls := 0
	httpClient := &http.Client{Transport: administrativeRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodDelete || request.Header.Get("If-Match") != `"etag"` {
			t.Fatalf("request=%s headers=%v", request.Method, request.Header)
		}
		return nil, context.DeadlineExceeded
	})}
	client, err := NewMinIOClient("http://minio.code-admin.svc:9000", httpClient, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC) }
	err = client.DeleteObject(
		context.Background(), "cf-payments-invoices-47e89ff7e282", "reports/a.txt", `"etag"`,
		"us-central1", adminTestCredentialsAt(client.now()),
	)
	if !errors.Is(err, ErrDependencyUnavailable) || calls != 1 {
		t.Fatalf("error=%v calls=%d", err, calls)
	}
}

func TestMinIOClientPresignsExactKeyMethodContentTypeAndSixtySeconds(t *testing.T) {
	t.Parallel()
	client, err := NewMinIOClient("http://minio.code-admin.svc:9000", &http.Client{Timeout: time.Second}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC)
	for _, test := range []struct {
		method, contentType, signedHeaders, signature string
	}{
		{method: http.MethodGet, signedHeaders: "host", signature: "acda9b012f0e4e70023a50c5296dbb16b5311871681dbfb8c3ecb82253d7eccf"},
		{method: http.MethodPut, contentType: "text/plain", signedHeaders: "content-type;host", signature: "394e86f4ae726f7354d801aaf4a73369a0ab3746a4974f7bcbdb756325c165f0"},
	} {
		result, err := client.Presign(
			now, "https://s3.example.com", "cf-payments-invoices-47e89ff7e282",
			"reports/olá world.txt", test.contentType, test.method, "us-central1", 60, adminTestCredentialsAt(now),
		)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := url.Parse(result.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host != "s3.example.com" ||
			parsed.EscapedPath() != "/cf-payments-invoices-47e89ff7e282/reports/ol%C3%A1%20world.txt" ||
			parsed.Query().Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" ||
			parsed.Query().Get("X-Amz-Expires") != "60" || parsed.Query().Get("X-Amz-SignedHeaders") != test.signedHeaders ||
			parsed.Query().Get("X-Amz-Security-Token") != "session-token-value-1234567890" ||
			parsed.Query().Get("X-Amz-Signature") != test.signature || strings.Contains(result.URL, strings.Repeat("s", 40)) ||
			result.Method != test.method || result.ExpiresIn != 60 {
			t.Fatalf("result=%#v parsed=%#v err=%v", result, parsed, err)
		}
		if test.method == http.MethodPut && result.Headers["Content-Type"] != test.contentType {
			t.Fatalf("upload headers=%v", result.Headers)
		}
		if test.method == http.MethodGet && len(result.Headers) != 0 {
			t.Fatalf("download headers=%v", result.Headers)
		}
		if test.method == http.MethodGet && !strings.Contains(parsed.Query().Get("response-content-disposition"), "attachment") {
			t.Fatalf("download disposition=%q", parsed.Query().Get("response-content-disposition"))
		}
		if test.method == http.MethodPut && parsed.Query().Has("response-content-disposition") {
			t.Fatalf("upload unexpectedly overrides response disposition")
		}
	}
}

func TestMinIOClientRejectsDuplicateListItems(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>cf-payments-invoices-47e89ff7e282</Name><Prefix>reports/</Prefix><KeyCount>2</KeyCount><MaxKeys>25</MaxKeys><Delimiter>/</Delimiter><IsTruncated>false</IsTruncated><Contents><Key>reports/a.txt</Key><LastModified>2026-08-31T12:00:00Z</LastModified><Size>12</Size></Contents><Contents><Key>reports/a.txt</Key><LastModified>2026-08-31T12:00:00Z</LastModified><Size>12</Size></Contents></ListBucketResult>`))
	}))
	defer server.Close()
	client, err := NewMinIOClient(server.URL, server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC) }
	_, err = client.ListObjects(
		context.Background(), "cf-payments-invoices-47e89ff7e282", "reports/", 25, "", "us-central1", adminTestCredentialsAt(client.now()),
	)
	if err == nil {
		t.Fatal("expected duplicate provider keys to fail closed")
	}
}

func TestMinIOClientPresignRejectsNonSixtySecondExpiry(t *testing.T) {
	t.Parallel()
	client, err := NewMinIOClient("http://minio.code-admin.svc:9000", &http.Client{Timeout: time.Second}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC)
	credentials := adminTestCredentialsAt(now)
	for _, ttl := range []int{59, 61} {
		if _, err := client.Presign(
			now, "https://s3.example.com", "cf-payments-invoices-47e89ff7e282",
			"reports/a.txt", "text/plain", http.MethodPut, "us-central1", ttl, credentials,
		); err == nil {
			t.Fatalf("ttl %d was accepted", ttl)
		}
	}
}

func FuzzAdministrativeListXMLShapeNeverPanics(f *testing.F) {
	f.Add([]byte(`<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>bucket</Name></ListBucketResult>`))
	f.Add([]byte(`<ListBucketResult><Contents><Key>../escape</Key></Contents></ListBucketResult>`))
	f.Add([]byte{0, '<', 'x', 'm', 'l', '>'})
	f.Fuzz(func(_ *testing.T, raw []byte) {
		_ = validListObjectsXMLShape(raw)
	})
}

func FuzzAdministrativeSigV4PresignRemainsKeyBound(f *testing.F) {
	f.Add("reports/a.txt", "text/plain")
	f.Add("unicode/olá mundo.txt", "application/octet-stream")
	f.Add("../escape", "text/plain")
	f.Fuzz(func(t *testing.T, key, contentType string) {
		client, err := NewMinIOClient("http://minio.code-admin.svc:9000", &http.Client{Timeout: time.Second}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Date(2026, 8, 31, 12, 30, 0, 0, time.UTC)
		result, err := client.Presign(
			now, "https://s3.example.com", "cf-payments-invoices-47e89ff7e282",
			key, contentType, http.MethodPut, "us-central1", 60, adminTestCredentialsAt(now),
		)
		if err != nil {
			return
		}
		parsed, parseErr := url.Parse(result.URL)
		if parseErr != nil || parsed.EscapedPath() != "/cf-payments-invoices-47e89ff7e282/"+awsURIEncode(key, false) ||
			parsed.Query().Get("X-Amz-Expires") != "60" || parsed.Query().Get("X-Amz-SignedHeaders") != "content-type;host" ||
			result.Headers["Content-Type"] != contentType || strings.Contains(result.URL, strings.Repeat("s", 40)) {
			t.Fatalf("unbound presign result=%#v parsed=%#v error=%v", result, parsed, parseErr)
		}
	})
}

func FuzzAdministrativeDeleteKeyAndETagValidation(f *testing.F) {
	f.Add("reports/a.txt", `"etag"`)
	f.Add("../escape", `W/"weak"`)
	f.Add("unicode/olá.txt", `"strong-visible"`)
	f.Fuzz(func(t *testing.T, key, etag string) {
		keyValid := validAdminObjectKey(key)
		etagValid := validAdminStrongETag(etag)
		if keyValid && (len(key) == 0 || len(key) > 1024 || !utf8.ValidString(key) || strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") || strings.Contains(key, "\\")) {
			t.Fatalf("invalid canonical key accepted: length=%d", len(key))
		}
		if etagValid && (len(etag) < 3 || len(etag) > 128 || etag[0] != '"' || etag[len(etag)-1] != '"') {
			t.Fatalf("invalid strong ETag accepted: length=%d", len(etag))
		}
	})
}

func adminTestCredentialsAt(now time.Time) Credentials {
	return Credentials{
		AccessKeyID: "ABCDEFGHIJKLMNOPQRST", SecretAccessKey: strings.Repeat("s", 40),
		SessionToken: "session-token-value-1234567890", Expiration: now.Add(15 * time.Minute),
	}
}
