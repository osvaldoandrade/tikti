package saml

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
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
	// LookupIP is a test seam for exercising DNS rebinding and special-purpose
	// address rejection. Production callers leave it nil.
	LookupIP func(context.Context, string, string) ([]net.IP, error)
}

func (f MetadataHTTPFetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	target, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil || target.Fragment != "" || target.RawQuery != "" || target.ForceQuery {
		return nil, fmt.Errorf("metadata URL must be an HTTPS URL without credentials, query, or fragment")
	}

	resolver := f.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	lookupIP := resolver.LookupIP
	if f.LookupIP != nil {
		lookupIP = f.LookupIP
	}
	ips, err := lookupIP(ctx, "ip", target.Hostname())
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
			remaining := index % uint64(len(ips))
			ip := ips[0]
			for _, candidate := range ips {
				if remaining == 0 {
					ip = candidate
					break
				}
				remaining--
			}
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
		return nil, fmt.Errorf("metadata request failed")
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
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() {
		return false
	}
	if address.Is4() {
		for _, prefix := range metadataBlockedIPv4Prefixes {
			if prefix.Contains(address) {
				return false
			}
		}
		return true
	}
	// Public IPv6 allocation is currently within 2000::/3. Excluding all
	// special-purpose blocks also prevents NAT64/6to4 endpoints from reaching
	// private IPv4 services through a translator.
	if !metadataPublicIPv6Prefix.Contains(address) {
		return false
	}
	for _, prefix := range metadataBlockedIPv6Prefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var metadataBlockedIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var (
	metadataPublicIPv6Prefix    = netip.MustParsePrefix("2000::/3")
	metadataBlockedIPv6Prefixes = []netip.Prefix{
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
	}
)
