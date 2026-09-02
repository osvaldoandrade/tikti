package services

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/osvaldoandrade/tikti/pkg/domain"
)

// TenantDiscoveryMetrics records only closed, low-cardinality outcomes. Tenant,
// user, membership, and role identifiers are intentionally never metric labels.
type TenantDiscoveryMetrics struct {
	requests          *prometheus.CounterVec
	authorizedTargets *prometheus.HistogramVec
	omissions         *prometheus.CounterVec
}

func NewTenantDiscoveryMetrics(registerer prometheus.Registerer) *TenantDiscoveryMetrics {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}
	metrics := &TenantDiscoveryMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_tenant_target_discovery_requests_total",
			Help: "Tenant target discovery exchanges by closed mode, result, and reason.",
		}, []string{"mode", "result", "reason"}),
		authorizedTargets: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tikti_tenant_target_discovery_authorized_targets",
			Help:    "Number of authorized tenant targets returned by successful discovery exchanges.",
			Buckets: []float64{1, 2, 5, 10, 25, 50, 100},
		}, []string{"mode"}),
		omissions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_tenant_target_discovery_omissions_total",
			Help: "Tenant target candidates omitted by closed mode and reason.",
		}, []string{"mode", "reason"}),
	}
	metrics.requests = registerTenantDiscoveryCounterVec(registerer, metrics.requests)
	metrics.authorizedTargets = registerTenantDiscoveryHistogramVec(registerer, metrics.authorizedTargets)
	metrics.omissions = registerTenantDiscoveryCounterVec(registerer, metrics.omissions)
	return metrics
}

func WithTenantDiscoveryMetrics(metrics *TenantDiscoveryMetrics) UserServiceOption {
	return func(service *userService) {
		service.tenantDiscoveryMetrics = metrics
	}
}

func requestedTenantDiscoveryMode(request domain.TokenExchangeReq) string {
	switch {
	case request.DiscoverTenantTargetsV1 && !request.DiscoverTenantTargetsV2:
		return "v1"
	case request.DiscoverTenantTargetsV2 && !request.DiscoverTenantTargetsV1:
		return "v2"
	case request.DiscoverTenantTargetsV1 || request.DiscoverTenantTargetsV2:
		return "internal"
	default:
		return ""
	}
}

func (m *TenantDiscoveryMetrics) observeRequest(mode string, requestErr error, authorizedTargets int) {
	if m == nil {
		return
	}
	mode = closedTenantDiscoveryMode(mode)
	result, reason := "success", "allowed"
	if requestErr != nil {
		result, reason = "error", tenantDiscoveryErrorReason(requestErr)
	}
	m.requests.WithLabelValues(mode, result, reason).Inc()
	if requestErr == nil {
		m.authorizedTargets.WithLabelValues(mode).Observe(float64(authorizedTargets))
	}
}

func (m *TenantDiscoveryMetrics) observeOmission(mode, reason string) {
	if m != nil {
		m.omissions.WithLabelValues(closedTenantDiscoveryMode(mode), closedTenantDiscoveryOmission(reason)).Inc()
	}
}

func closedTenantDiscoveryMode(value string) string {
	switch value {
	case "v1", "v2", "fallback":
		return value
	default:
		return "internal"
	}
}

func closedTenantDiscoveryOmission(value string) string {
	switch value {
	case "not_in_v1_cohort", "tenant_inactive", "audience_unavailable", "role_unresolvable",
		"membership_limit", "role_budget_exceeded", "target_limit":
		return value
	default:
		return "internal"
	}
}

func tenantDiscoveryErrorReason(err error) string {
	switch {
	case errors.Is(err, domain.ErrInvalidArgument):
		return "invalid_request"
	case errors.Is(err, domain.ErrInvalidToken), errors.Is(err, domain.ErrInvalidCreds):
		return "invalid_token"
	case errors.Is(err, domain.ErrInvalidTenant):
		return "invalid_tenant"
	case errors.Is(err, domain.ErrInvalidAudience):
		return "invalid_audience"
	case errors.Is(err, domain.ErrUnauthorizedScope):
		return "unauthorized_scope"
	case errors.Is(err, domain.ErrNotFound):
		return "dependency_error"
	default:
		return "internal"
	}
}

func registerTenantDiscoveryCounterVec(
	registerer prometheus.Registerer,
	collector *prometheus.CounterVec,
) *prometheus.CounterVec {
	if err := registerer.Register(collector); err != nil {
		if existing, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if value, cast := existing.ExistingCollector.(*prometheus.CounterVec); cast {
				return value
			}
		}
	}
	return collector
}

func registerTenantDiscoveryHistogramVec(
	registerer prometheus.Registerer,
	collector *prometheus.HistogramVec,
) *prometheus.HistogramVec {
	if err := registerer.Register(collector); err != nil {
		if existing, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if value, cast := existing.ExistingCollector.(*prometheus.HistogramVec); cast {
				return value
			}
		}
	}
	return collector
}
