package storagests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

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
		result.Items[0].Kind != "prefix" || result.Items[0].Key != "reports/2026/" || result.Items[1].Key != "reports/a.txt" || result.Items[1].Size != 12 {
		t.Fatalf("result=%#v err=%v", result, err)
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

func adminTestCredentialsAt(now time.Time) Credentials {
	return Credentials{
		AccessKeyID: "ABCDEFGHIJKLMNOPQRST", SecretAccessKey: strings.Repeat("s", 40),
		SessionToken: "session-token-value-1234567890", Expiration: now.Add(15 * time.Minute),
	}
}
