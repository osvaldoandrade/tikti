package services

import "slices"

// WithTrustedClusterRefs fixes the operator-configured clusterRef set. It is
// the only source of clusterRef values a scoped WorkloadBinding may carry.
func WithTrustedClusterRefs(clusterRefs []string) WorkloadIdentityServiceOption {
	return func(s *workloadIdentityService) { s.trustedClusterRefs = slices.Clone(clusterRefs) }
}

// WithScopedWorkloadBindings enables workloadIdentity.scopedWorkloadBindings
// (ADR-0022 R4, default false).
func WithScopedWorkloadBindings(enabled bool) WorkloadIdentityServiceOption {
	return func(s *workloadIdentityService) { s.scopedWorkloadBindings = enabled }
}

// WithLegacyCodeQAdminGrant applies workloadIdentity.legacyCodeQAdminGrant
// (default true). When false, legacy codeq:admin workload exchanges are refused.
func WithLegacyCodeQAdminGrant(enabled bool) WorkloadIdentityServiceOption {
	return func(s *workloadIdentityService) { s.refuseLegacyCodeQAdmin = !enabled }
}

// WithWorkloadIdentityMetrics attaches the ADR-0022 workload metrics.
func WithWorkloadIdentityMetrics(metrics *WorkloadIdentityMetrics) WorkloadIdentityServiceOption {
	return func(s *workloadIdentityService) { s.metrics = metrics }
}
