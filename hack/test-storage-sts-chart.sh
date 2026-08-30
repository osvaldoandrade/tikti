#!/usr/bin/env bash
set -euo pipefail

chart="helm/tikti"

must_fail() {
  if helm template storage-sts "$chart" "$@" >/dev/null 2>&1; then
    echo "expected Helm rendering to reject: $*" >&2
    exit 1
  fi
}

helm lint "$chart"

baseline=$(helm template storage-sts "$chart")
baseline_config=$(yq ea '[select(.kind == "ConfigMap") | .data."tikti.yaml"] | .[0]' - <<<"$baseline")
if ! rg -q '^storageSTS:$|^  enabled: false$' <<<"$baseline_config"; then
  echo "storage STS must render disabled by default" >&2
  exit 1
fi

must_fail --set config.storageSTS.enabled=true
must_fail \
  --set config.storageSTS.enabled=true \
  --set config.issuerBaseUrl=https://tikti.example.com \
  --set config.storageSTS.authorizerUrl=https://api.example.com/internal/v1/object-storage:authorize \
  --set config.storageSTS.minioStsEndpoint=http://minio.code-admin.svc:9000 \
  --set config.workloadIdentity.issuer=https://cluster.example.com \
  --set config.workloadIdentity.clusterRef=code-cloud \
  --set config.workloadIdentity.jwksUrl=https://cluster.example.com/jwks \
  --set config.storageSTS.credentialTtlSeconds=901

enabled=$(helm template storage-sts "$chart" \
  --set config.storageSTS.enabled=true \
  --set config.issuerBaseUrl=https://tikti.example.com \
  --set config.storageSTS.authorizerUrl=https://api.example.com/internal/v1/object-storage:authorize \
  --set config.storageSTS.minioStsEndpoint=http://minio.code-admin.svc:9000 \
  --set config.workloadIdentity.issuer=https://cluster.example.com \
  --set config.workloadIdentity.clusterRef=code-cloud \
  --set config.workloadIdentity.jwksUrl=https://cluster.example.com/jwks)
enabled_config=$(yq ea '[select(.kind == "ConfigMap") | .data."tikti.yaml"] | .[0]' - <<<"$enabled")
for contract in \
  'enabled: true' \
  'syntheticAccountId: "000000000000"' \
  'serviceSubject: "tikti:object-storage-sts"' \
  'credentialTtlSeconds: 900' \
  'maximumConcurrent: 8' \
  'clusterRef: "code-cloud"'; do
  if ! rg -Fq "$contract" <<<"$enabled_config"; then
    echo "enabled storage STS config is missing: $contract" >&2
    exit 1
  fi
done

# CFP-086 owns routes, policies and NetworkPolicies. This chart task must add
# no such resource while toggling the broker process configuration.
for kind in Ingress IngressRoute Middleware NetworkPolicy Job; do
  before=$(yq ea "[select(.kind == \"$kind\")] | length" - <<<"$baseline")
  after=$(yq ea "[select(.kind == \"$kind\")] | length" - <<<"$enabled")
  test "$before" = "$after"
done
