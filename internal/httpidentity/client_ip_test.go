package httpidentity

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientIPResolverTrustBoundary(t *testing.T) {
	resolver, err := NewClientIPResolver([]string{"10.0.0.0/8", "192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		forwarded  []string
		realIP     string
		want       string
	}{
		{
			name: "untrusted peer cannot spoof forwarding headers", remoteAddr: "198.51.100.20:443",
			forwarded: []string{"203.0.113.99"}, realIP: "203.0.113.98", want: "198.51.100.20",
		},
		{
			name: "trusted chain selects first untrusted hop from right", remoteAddr: "10.0.0.9:443",
			forwarded: []string{"203.0.113.5, 198.51.100.7", "192.0.2.8"}, want: "198.51.100.7",
		},
		{
			name: "malformed chain falls back to peer", remoteAddr: "10.0.0.9:443",
			forwarded: []string{"203.0.113.5, not-an-ip"}, want: "10.0.0.9",
		},
		{
			name: "trusted real IP is accepted without forwarded chain", remoteAddr: "10.0.0.9:443",
			realIP: "203.0.113.6", want: "203.0.113.6",
		},
		{
			name: "IPv6 peer is canonical", remoteAddr: "[2001:db8::7]:443",
			forwarded: []string{"203.0.113.99"}, want: "2001:db8::7",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "https://tikti.example.com", nil)
			request.RemoteAddr = tc.remoteAddr
			for _, value := range tc.forwarded {
				request.Header.Add("X-Forwarded-For", value)
			}
			request.Header.Set("X-Real-IP", tc.realIP)
			if got := resolver.Resolve(request); got != tc.want {
				t.Fatalf("Resolve() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClientIPResolverBoundsForwardedChain(t *testing.T) {
	resolver, err := NewClientIPResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "https://tikti.example.com", nil)
	request.RemoteAddr = "10.0.0.9:443"
	request.Header.Set("X-Forwarded-For", strings.Repeat("203.0.113.1,", maximumForwardedAddresses)+"203.0.113.2")
	if got := resolver.Resolve(request); got != "10.0.0.9" {
		t.Fatalf("oversized forwarding chain resolved to %q", got)
	}
}
