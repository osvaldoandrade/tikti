package storagests

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	requests                *prometheus.CounterVec
	duration                *prometheus.HistogramVec
	authorizerDuration      *prometheus.HistogramVec
	minioDuration           *prometheus.HistogramVec
	inflight                prometheus.Gauge
	throttled               prometheus.Counter
	invalidToken            prometheus.Counter
	providerResponseInvalid prometheus.Counter
	adminRequests           *prometheus.CounterVec
	adminDuration           *prometheus.HistogramVec
}

func NewMetrics(registerer prometheus.Registerer) *Metrics {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}
	metrics := &Metrics{
		requests:                prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tikti_storage_sts_requests_total", Help: "Storage STS requests by closed result and reason."}, []string{"result", "reason"}),
		duration:                prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "tikti_storage_sts_duration_seconds", Help: "Storage STS request duration.", Buckets: prometheus.DefBuckets}, []string{"result"}),
		authorizerDuration:      prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "tikti_storage_authorizer_duration_seconds", Help: "Central storage authorizer duration.", Buckets: prometheus.DefBuckets}, []string{"result"}),
		minioDuration:           prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "tikti_storage_minio_sts_duration_seconds", Help: "MinIO STS dependency duration.", Buckets: prometheus.DefBuckets}, []string{"result"}),
		inflight:                prometheus.NewGauge(prometheus.GaugeOpts{Name: "tikti_storage_sts_in_flight", Help: "Current bounded Storage STS exchanges."}),
		throttled:               prometheus.NewCounter(prometheus.CounterOpts{Name: "tikti_storage_sts_throttled_total", Help: "Storage STS exchanges rejected by the concurrency bound."}),
		invalidToken:            prometheus.NewCounter(prometheus.CounterOpts{Name: "tikti_storage_sts_invalid_token_total", Help: "Projected tokens rejected by strict verification."}),
		providerResponseInvalid: prometheus.NewCounter(prometheus.CounterOpts{Name: "tikti_storage_sts_provider_response_invalid_total", Help: "Invalid bounded MinIO STS responses."}),
		adminRequests:           prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tikti_storage_admin_object_requests_total", Help: "Administrative object requests by closed operation, result, and reason."}, []string{"operation", "result", "reason"}),
		adminDuration:           prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "tikti_storage_admin_object_duration_seconds", Help: "Administrative object request duration by closed operation and result.", Buckets: prometheus.DefBuckets}, []string{"operation", "result"}),
	}
	metrics.requests = registerCounterVec(registerer, metrics.requests)
	metrics.duration = registerHistogramVec(registerer, metrics.duration)
	metrics.authorizerDuration = registerHistogramVec(registerer, metrics.authorizerDuration)
	metrics.minioDuration = registerHistogramVec(registerer, metrics.minioDuration)
	metrics.inflight = registerGauge(registerer, metrics.inflight)
	metrics.throttled = registerCounter(registerer, metrics.throttled)
	metrics.invalidToken = registerCounter(registerer, metrics.invalidToken)
	metrics.providerResponseInvalid = registerCounter(registerer, metrics.providerResponseInvalid)
	metrics.adminRequests = registerCounterVec(registerer, metrics.adminRequests)
	metrics.adminDuration = registerHistogramVec(registerer, metrics.adminDuration)
	return metrics
}

func registerCounterVec(registerer prometheus.Registerer, collector *prometheus.CounterVec) *prometheus.CounterVec {
	if err := registerer.Register(collector); err != nil {
		if existing, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if value, cast := existing.ExistingCollector.(*prometheus.CounterVec); cast {
				return value
			}
		}
	}
	return collector
}

func registerHistogramVec(registerer prometheus.Registerer, collector *prometheus.HistogramVec) *prometheus.HistogramVec {
	if err := registerer.Register(collector); err != nil {
		if existing, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if value, cast := existing.ExistingCollector.(*prometheus.HistogramVec); cast {
				return value
			}
		}
	}
	return collector
}

func registerGauge(registerer prometheus.Registerer, collector prometheus.Gauge) prometheus.Gauge {
	if err := registerer.Register(collector); err != nil {
		if existing, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if value, cast := existing.ExistingCollector.(prometheus.Gauge); cast {
				return value
			}
		}
	}
	return collector
}

func registerCounter(registerer prometheus.Registerer, collector prometheus.Counter) prometheus.Counter {
	if err := registerer.Register(collector); err != nil {
		if existing, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if value, cast := existing.ExistingCollector.(prometheus.Counter); cast {
				return value
			}
		}
	}
	return collector
}

func (m *Metrics) observeRequest(result, reason string, started time.Time) {
	if m == nil {
		return
	}
	m.requests.WithLabelValues(closedResult(result), closedReason(reason)).Inc()
	m.duration.WithLabelValues(closedResult(result)).Observe(time.Since(started).Seconds())
}

func (m *Metrics) observeAuthorizer(result string, started time.Time) {
	if m != nil {
		m.authorizerDuration.WithLabelValues(closedResult(result)).Observe(time.Since(started).Seconds())
	}
}

func (m *Metrics) observeMinIO(result string, started time.Time) {
	if m != nil {
		m.minioDuration.WithLabelValues(closedResult(result)).Observe(time.Since(started).Seconds())
	}
}

func (m *Metrics) observeAdmin(operation, result, reason string, started time.Time) {
	if m == nil {
		return
	}
	operation = closedAdminOperation(operation)
	result = closedResult(result)
	m.adminRequests.WithLabelValues(operation, result, closedReason(reason)).Inc()
	m.adminDuration.WithLabelValues(operation, result).Observe(time.Since(started).Seconds())
}

func closedAdminOperation(value string) string {
	switch value {
	case "list", "upload", "download", "delete":
		return value
	default:
		return "internal"
	}
}

func closedResult(value string) string {
	if value == "success" {
		return "success"
	}
	return "error"
}

func closedReason(value string) string {
	switch value {
	case "allowed", "invalid_request", "invalid_token", "denied", "authorizer_unavailable", "authorizer_invalid",
		"provider_unavailable", "provider_invalid", "object_changed", "throttled", "internal":
		return value
	default:
		return "internal"
	}
}
