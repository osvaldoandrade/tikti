package services

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// WorkloadIdentityMetrics holds the ADR-0022 workload exchange metrics. Labels
// are closed sets or trusted configuration (clusterRef) and verified
// namespaces; tokens, Pod UIDs and binding UIDs never become labels.
type WorkloadIdentityMetrics struct {
	legacyUnscoped     prometheus.Counter
	legacyCodeQAdmin   *prometheus.CounterVec
	bindingExchange    *prometheus.CounterVec
	bindingAuthority   *prometheus.HistogramVec
	bindingAuthorityIn prometheus.Gauge
}

func NewWorkloadIdentityMetrics(registerer prometheus.Registerer) *WorkloadIdentityMetrics {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}
	m := &WorkloadIdentityMetrics{
		legacyUnscoped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tikti_workload_legacy_unscoped_binding_total",
			Help: "Legacy workload exchanges that used an unscoped WorkloadBinding record.",
		}),
		legacyCodeQAdmin: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_workload_legacy_codeq_admin_exchange_total",
			Help: "Verified legacy workload exchanges requesting codeq:admin.",
		}, []string{"cluster_ref", "namespace"}),
		bindingExchange: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_codeq_binding_exchange_total",
			Help: "CodeQ binding exchanges by closed result, code, policy and trusted clusterRef.",
		}, []string{"result", "code", "policy", "cluster_ref"}),
		bindingAuthority: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tikti_codeq_binding_authority_seconds",
			Help:    "CodeQ binding authority call duration by closed result.",
			Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 1.5, 2, 5, 10},
		}, []string{"result"}),
		bindingAuthorityIn: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tikti_codeq_binding_authority_in_flight",
			Help: "Current bounded CodeQ binding authority calls.",
		}),
	}
	m.legacyUnscoped = registerOrExistingCounter(registerer, m.legacyUnscoped)
	m.legacyCodeQAdmin = registerOrExistingCounterVec(registerer, m.legacyCodeQAdmin)
	m.bindingExchange = registerOrExistingCounterVec(registerer, m.bindingExchange)
	m.bindingAuthority = registerOrExistingHistogramVec(registerer, m.bindingAuthority)
	m.bindingAuthorityIn = registerOrExistingGauge(registerer, m.bindingAuthorityIn)
	return m
}

func (m *WorkloadIdentityMetrics) legacyUnscopedBinding() {
	if m != nil {
		m.legacyUnscoped.Inc()
	}
}

func (m *WorkloadIdentityMetrics) legacyCodeQAdminExchange(clusterRef, namespace string) {
	if m != nil {
		m.legacyCodeQAdmin.WithLabelValues(clusterRef, namespace).Inc()
	}
}

func (m *WorkloadIdentityMetrics) codeqBindingExchange(result, code, policy, clusterRef string) {
	if m != nil {
		m.bindingExchange.WithLabelValues(result, code, policy, clusterRef).Inc()
	}
}

func (m *WorkloadIdentityMetrics) codeqBindingAuthority(result string, started time.Time) {
	if m != nil {
		m.bindingAuthority.WithLabelValues(result).Observe(time.Since(started).Seconds())
	}
}

func (m *WorkloadIdentityMetrics) codeqBindingAuthorityInFlight(delta float64) {
	if m != nil {
		m.bindingAuthorityIn.Add(delta)
	}
}

func registerOrExistingCounter(registerer prometheus.Registerer, collector prometheus.Counter) prometheus.Counter {
	if err := registerer.Register(collector); err != nil {
		if existing, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if value, cast := existing.ExistingCollector.(prometheus.Counter); cast {
				return value
			}
		}
	}
	return collector
}

func registerOrExistingCounterVec(registerer prometheus.Registerer, collector *prometheus.CounterVec) *prometheus.CounterVec {
	if err := registerer.Register(collector); err != nil {
		if existing, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if value, cast := existing.ExistingCollector.(*prometheus.CounterVec); cast {
				return value
			}
		}
	}
	return collector
}

func registerOrExistingHistogramVec(registerer prometheus.Registerer, collector *prometheus.HistogramVec) *prometheus.HistogramVec {
	if err := registerer.Register(collector); err != nil {
		if existing, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if value, cast := existing.ExistingCollector.(*prometheus.HistogramVec); cast {
				return value
			}
		}
	}
	return collector
}

func registerOrExistingGauge(registerer prometheus.Registerer, collector prometheus.Gauge) prometheus.Gauge {
	if err := registerer.Register(collector); err != nil {
		if existing, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if value, cast := existing.ExistingCollector.(prometheus.Gauge); cast {
				return value
			}
		}
	}
	return collector
}
