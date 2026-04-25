package saml

import "log"

// tidDenylist contains attribute names that must never be taken from a SAML
// assertion because tid is always sourced from the URL path.
var tidDenylist = map[string]bool{
	"tid":       true,
	"tenant_id": true,
	"tenantId":  true,
}

// MapAttributes copies assertion attributes into a new map, stripping any
// attribute whose name matches a tid-like key (tid, tenant_id, tenantId).
// When a tid-like attribute is found it is silently dropped, a metric is
// incremented, and an INFO-level log line is emitted.
//
// urlTID is the tenant ID extracted from the URL path and is used only for
// metric labels — it is never overwritten.
func MapAttributes(attrs map[string][]string, urlTID string, m *Metrics) map[string][]string {
	out := make(map[string][]string, len(attrs))
	for k, v := range attrs {
		if tidDenylist[k] {
			log.Printf("saml: ignoring assertion-supplied %q attribute for tid %s", k, urlTID)
			if m != nil {
				m.TIDOverrideIgnored.WithLabelValues(urlTID).Inc()
			}
			continue
		}
		out[k] = v
	}
	return out
}
