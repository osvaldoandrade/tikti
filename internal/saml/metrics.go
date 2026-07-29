package saml

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus collectors for the SAML subsystem.
// Every field is safe for concurrent use. Construct via NewMetrics.
type Metrics struct {
	// Counters.
	AuthnRequests       *prometheus.CounterVec
	Responses           *prometheus.CounterVec
	ValidationFailures  *prometheus.CounterVec
	JITProvisions       *prometheus.CounterVec
	LogoutRequests      *prometheus.CounterVec
	LogoutResponses     *prometheus.CounterVec
	MetadataRefresh     *prometheus.CounterVec
	ReplayBlocked       *prometheus.CounterVec
	TIDOverrideIgnored  *prometheus.CounterVec
	IdPAdminChanges     *prometheus.CounterVec
	StateCookieRecovery *prometheus.CounterVec

	// Histograms — 2 per HLD §18.
	ValidationDuration *prometheus.HistogramVec
	IdPRoundtrip       *prometheus.HistogramVec

	// Gauges — 2 per HLD §18.
	IdPCertExpiry *prometheus.GaugeVec
	SPCertExpiry  prometheus.Gauge

	// RefreshConsecFailures tracks consecutive background-refresh failures per tenant.
	RefreshConsecFailures *prometheus.GaugeVec
}

// NewMetrics creates and registers all SAML collectors against the supplied
// prometheus.Registerer. Pass prometheus.NewRegistry() in tests to keep them
// hermetic; pass prometheus.DefaultRegisterer in production.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	f := promauto.With(reg)

	return &Metrics{
		// ── Counters ────────────────────────────────────────────────
		AuthnRequests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_saml_authn_requests_total",
			Help: "Total SAML AuthnRequests initiated.",
		}, []string{"tid"}),

		Responses: f.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_saml_responses_total",
			Help: "Total SAML Responses received.",
		}, []string{"tid", "result"}),

		ValidationFailures: f.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_saml_validation_failures_total",
			Help: "Total SAML assertion validation failures.",
		}, []string{"tid", "reason"}),

		JITProvisions: f.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_saml_jit_provisions_total",
			Help: "Total JIT user provisions via SAML.",
		}, []string{"tid"}),

		LogoutRequests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_saml_logout_requests_total",
			Help: "Total SAML LogoutRequests.",
		}, []string{"tid"}),

		LogoutResponses: f.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_saml_logout_responses_total",
			Help: "Total SAML LogoutResponses.",
		}, []string{"tid", "result"}),

		MetadataRefresh: f.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_saml_metadata_refresh_total",
			Help: "Total IdP metadata refresh attempts.",
		}, []string{"tid", "result"}),

		ReplayBlocked: f.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_saml_replay_blocked_total",
			Help: "Total assertion replays blocked.",
		}, []string{"tid"}),

		TIDOverrideIgnored: f.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_saml_tid_override_ignored_total",
			Help: "Total assertion-supplied tid attributes ignored.",
		}, []string{"tid"}),

		IdPAdminChanges: f.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_saml_idp_admin_changes_total",
			Help: "Total SAML IdP administration attempts.",
		}, []string{"operation", "result"}),

		StateCookieRecovery: f.NewCounterVec(prometheus.CounterOpts{
			Name: "tikti_saml_state_cookie_recovery_total",
			Help: "Total same-origin state-cookie recovery outcomes.",
		}, []string{"result"}),

		// ── Histograms ──────────────────────────────────────────────
		ValidationDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tikti_saml_response_validation_duration_seconds",
			Help:    "SAML response validation latency.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1},
		}, []string{"tid"}),

		IdPRoundtrip: f.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tikti_saml_idp_roundtrip_duration_seconds",
			Help: "IdP metadata fetch roundtrip latency.",
		}, []string{"tid"}),

		// ── Gauges ──────────────────────────────────────────────────
		IdPCertExpiry: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tikti_saml_idp_cert_expiry_seconds",
			Help: "Seconds until IdP signing certificate expires.",
		}, []string{"tid", "subject"}),

		SPCertExpiry: f.NewGauge(prometheus.GaugeOpts{
			Name: "tikti_saml_sp_cert_expiry_seconds",
			Help: "Seconds until SP signing certificate expires.",
		}),

		RefreshConsecFailures: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tikti_saml_metadata_refresh_consec_failures",
			Help: "Current count of consecutive IdP metadata refresh failures per tenant.",
		}, []string{"tid"}),
	}
}
