package saml

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const MaxMetadataBytes = 1 << 20

// MetadataHTTPFetcher retrieves administrator-supplied SAML metadata without
// allowing the Tikti pod to become an SSRF proxy into private infrastructure.
type MetadataHTTPFetcher struct {
	Resolver *net.Resolver
	Timeout  time.Duration
}

func (f MetadataHTTPFetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	target, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil || target.Fragment != "" {
		return nil, fmt.Errorf("metadata URL must be an HTTPS URL without credentials or fragment")
	}

	resolver := f.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupIP(ctx, "ip", target.Hostname())
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("metadata host could not be resolved")
	}
	for _, ip := range ips {
		if !isPublicMetadataIP(ip) {
			return nil, fmt.Errorf("metadata host resolves to a non-public address")
		}
	}

	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	var nextIP atomic.Uint64
	transport := &http.Transport{
		Proxy:                 nil,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12}, //nolint:gosec
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			_, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, splitErr
			}
			index := nextIP.Add(1) - 1
			ip := ips[int(index%uint64(len(ips)))]
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("metadata URL redirects are not allowed")
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("metadata request could not be created")
	}
	request.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("metadata request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, MaxMetadataBytes))
		return nil, fmt.Errorf("metadata endpoint returned HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxMetadataBytes+1))
	if err != nil {
		return nil, fmt.Errorf("metadata response could not be read")
	}
	if len(raw) > MaxMetadataBytes {
		return nil, fmt.Errorf("metadata document exceeds %d bytes", MaxMetadataBytes)
	}
	return raw, nil
}

func isPublicMetadataIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() &&
		!ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsUnspecified()
}
