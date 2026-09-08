package httpidentity

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const maximumForwardedAddresses = 32

// ClientIPResolver accepts forwarding headers only from explicitly trusted
// proxy networks. An empty trust set always resolves the immediate peer.
type ClientIPResolver struct {
	trusted []netip.Prefix
}

func NewClientIPResolver(cidrs []string) (ClientIPResolver, error) {
	trusted := make([]netip.Prefix, 0, len(cidrs))
	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return ClientIPResolver{}, err
		}
		trusted = append(trusted, prefix.Masked())
	}
	return ClientIPResolver{trusted: trusted}, nil
}

func (r ClientIPResolver) Resolve(request *http.Request) string {
	if request == nil {
		return "unknown"
	}
	peer, ok := parseRemoteAddress(request.RemoteAddr)
	if !ok {
		return "unknown"
	}
	if !r.isTrusted(peer) {
		return peer.String()
	}

	forwarded := request.Header.Values("X-Forwarded-For")
	if len(forwarded) > 0 {
		parts := strings.Split(strings.Join(forwarded, ","), ",")
		if len(parts) > maximumForwardedAddresses {
			return peer.String()
		}
		current := peer
		for index := len(parts) - 1; index >= 0 && r.isTrusted(current); index-- {
			candidate, err := netip.ParseAddr(strings.TrimSpace(parts[index]))
			if err != nil {
				return peer.String()
			}
			current = candidate.Unmap()
		}
		return current.String()
	}

	if raw := strings.TrimSpace(request.Header.Get("X-Real-IP")); raw != "" {
		candidate, err := netip.ParseAddr(raw)
		if err != nil {
			return peer.String()
		}
		return candidate.Unmap().String()
	}
	return peer.String()
}

func (r ClientIPResolver) isTrusted(address netip.Addr) bool {
	for _, prefix := range r.trusted {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func parseRemoteAddress(raw string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		host = strings.TrimSpace(raw)
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}
