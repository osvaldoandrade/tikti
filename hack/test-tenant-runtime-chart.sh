#!/usr/bin/env bash
set -euo pipefail

chart="helm/tikti"
baseline=$(helm template tenant-runtime "$chart")
enabled=$(helm template tenant-runtime "$chart" --set config.tenantRuntimeAuthorityV1=true)
baseline_config=$(yq ea '[select(.kind == "ConfigMap") | .data."tikti.yaml"] | .[0]' - <<<"$baseline")
enabled_config=$(yq ea '[select(.kind == "ConfigMap") | .data."tikti.yaml"] | .[0]' - <<<"$enabled")
rg -q '^tenantRuntimeAuthorityV1: false$' <<<"$baseline_config"
rg -q '^tenantRuntimeAuthorityV1: true$' <<<"$enabled_config"
for setting in 'tenantScopedTokenClaimsV1: false' 'tenantTargetDiscoveryV2: false' 'identityGroupsV1: false'; do
  rg -Fq "$setting" <<<"$enabled_config"
done
# Enabling this in-process read cannot add a resource or change pod capacity.
baseline_resources=$(yq ea '[select(.kind != "ConfigMap")]' - <<<"$baseline")
enabled_resources=$(yq ea '[select(.kind != "ConfigMap")]' - <<<"$enabled")
test "$baseline_resources" = "$enabled_resources"
