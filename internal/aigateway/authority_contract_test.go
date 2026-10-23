package aigateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIdentityAuthorityDestinationBoundary(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, base string
		timeout    time.Duration
		allow      bool
	}{
		{"public tls", "https://api.example.test", time.Second, true},
		{"explicit tls port", "https://api.example.test:8443", 10 * time.Second, true},
		{"lowest port", "https://api.example.test:1", time.Second, true},
		{"highest port", "https://api.example.test:65535", time.Second, true},
		{"cluster service", "http://code-admin-api.code-admin.svc.cluster.local:8080", time.Second, true},
		{"malformed url", "https://%xx", time.Second, false},
		{"missing host", "https://", time.Second, false},
		{"public cleartext", "http://api.example.test", time.Second, false},
		{"cluster without port", "http://api.ns.svc.cluster.local", time.Second, false},
		{"foreign service suffix", "http://api.ns.svc.cluster.local.attacker.test:8080", time.Second, false},
		{"zero port", "https://api.example.test:0", time.Second, false},
		{"overflow port", "https://api.example.test:65536", time.Second, false},
		{"noninteger port", "https://api.example.test:not-a-port", time.Second, false},
		{"userinfo", "https://user@api.example.test", time.Second, false},
		{"zero timeout", "https://api.example.test", 0, false},
		{"negative timeout", "https://api.example.test", -1, false},
		{"excess timeout", "https://api.example.test", 10*time.Second + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(tc.base+AuthorityPath, tc.timeout)
			if (err == nil) != tc.allow || (c != nil) != tc.allow {
				t.Fatalf("destination admission = %v, allowed %v", err, tc.allow)
			}
		})
	}
	for _, suffix := range []string{"?", "?x=1", "#fragment", "/", "%2f", " "} {
		if _, err := NewClient("https://api.example.test"+AuthorityPath+suffix, time.Second); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("noncanonical destination suffix %q accepted", suffix)
		}
	}
}

func TestIdentityAuthorityResponseRefusal(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, media, body string
		status            int
		want              error
	}{
		{"unauthenticated", "application/json", "{}", 401, ErrDenied},
		{"unauthorized", "application/json", "{}", 403, ErrDenied},
		{"absent identity", "application/json", "{}", 404, ErrDenied},
		{"rate limited", "application/json", "{}", 429, ErrUnavailable},
		{"server failure", "application/json", "{}", 503, ErrUnavailable},
		{"redirect", "application/json", "{}", 307, ErrUnavailable},
		{"wrong media", "text/html", "{}", 200, ErrUnavailable},
		{"missing media", "", "{}", 200, ErrUnavailable},
		{"invalid media", "application/json; broken", "{}", 200, ErrUnavailable},
		{"invalid json", "application/json", "{", 200, ErrUnavailable},
		{"oversized", "application/json", strings.Repeat(" ", 16385), 200, ErrUnavailable},
		{"duplicate identity", "application/json", `{"subject":"a","subject":"b"}`, 200, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.media)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(srv.Close)
			c := &Client{url: srv.URL, http: srv.Client()}
			got, err := c.Authorize(t.Context(), "synthetic-assertion")
			if !errors.Is(err, tc.want) || got != (Principal{}) {
				t.Fatalf("failed response produced principal or wrong error: %v", err)
			}
		})
	}
}

type aiAuthorityTransport func(*http.Request) (*http.Response, error)

func (f aiAuthorityTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type aiBrokenBody struct{}

func (aiBrokenBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (aiBrokenBody) Close() error             { return nil }

func TestIdentityAuthorityExactAssertionLimit(t *testing.T) {
	t.Parallel()
	c := &Client{url: "https://api.example.test" + AuthorityPath, http: &http.Client{Transport: aiAuthorityTransport(func(r *http.Request) (*http.Response, error) {
		if len(r.Header.Get("Authorization")) != len("Bearer ")+16384 {
			t.Fatal("assertion changed at transport boundary")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"subject":"verified"}`))}, nil
	})}}
	if p, err := c.Authorize(t.Context(), strings.Repeat("a", 16384)); err != nil || p.Subject != "verified" {
		t.Fatalf("exact assertion bound rejected: %v", err)
	}
	if scopes, ok := Scopes([]string{InvokeScope}); !ok || len(scopes) != 1 || scopes[0] != InvokeScope {
		t.Fatal("single valid scope rejected")
	}
}

func TestIdentityAuthorityRefusesUnavailableTransport(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		c    *Client
		raw  string
	}{
		{"nil client", nil, "assertion"},
		{"nil transport", &Client{}, "assertion"},
		{"empty assertion", &Client{http: &http.Client{}}, ""},
		{"large assertion", &Client{http: &http.Client{}}, strings.Repeat("a", 16385)},
		{"split assertion", &Client{http: &http.Client{}}, "first\tsecond"},
		{"invalid request", &Client{url: "://invalid", http: &http.Client{}}, "assertion"},
		{"transport failure", &Client{url: "https://api.example.test", http: &http.Client{Transport: aiAuthorityTransport(func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded })}}, "assertion"},
		{"body failure", &Client{url: "https://api.example.test", http: &http.Client{Transport: aiAuthorityTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: aiBrokenBody{}}, nil
		})}}, "assertion"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.c.Authorize(t.Context(), tc.raw)
			if !errors.Is(err, ErrUnavailable) || got != (Principal{}) {
				t.Fatalf("unknown transport granted a principal: %v", err)
			}
		})
	}
}

func TestIdentityAuthorityNeverFollowsRedirect(t *testing.T) {
	t.Parallel()
	c, err := NewClient("https://api.example.test"+AuthorityPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.http.Transport = aiAuthorityTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.example.test" {
			t.Fatal("signed assertion followed a cross-authority redirect")
		}
		return &http.Response{StatusCode: 307, Header: http.Header{"Location": {"https://foreign.example.test" + AuthorityPath}}, Body: http.NoBody, Request: r}, nil
	})
	if _, err := c.Authorize(t.Context(), "assertion"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("redirect result = %v", err)
	}
}

func TestAIIdentityScopesClosedSet(t *testing.T) {
	t.Parallel()
	for _, values := range [][]string{nil, {}, {""}, {InvokeScope, InvokeScope}, {"code-llm:*"}, {InvokeScope, ModelsScope, UsageScope, "extra"}} {
		if _, ok := Scopes(values); ok {
			t.Fatal("invalid or ambiguous scope set admitted")
		}
	}
	values := []string{UsageScope, InvokeScope, ModelsScope}
	got, ok := Scopes(values)
	if !ok || strings.Join(got, " ") != "code-llm:invoke code-llm:models:read code-llm:usage:read" || values[0] != UsageScope {
		t.Fatal("scope normalization broadened or mutated caller input")
	}
}
