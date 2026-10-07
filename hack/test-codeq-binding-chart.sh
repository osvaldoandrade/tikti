#!/usr/bin/env bash
# ADR-0022 C3: the binding-scoped CodeQ grant renders default-off and the
# chart refuses out-of-contract values before Tikti would.
set -euo pipefail
chart="$(cd "$(dirname "$0")/../helm/tikti" && pwd)"
output="$(mktemp)"
trap 'rm -f "$output"' EXIT
helm template codeq-binding "$chart" > "$output"
python3 - "$output" <<'PY'
import sys,yaml
objects=list(yaml.safe_load_all(open(sys.argv[1])))
config=yaml.safe_load(next(x for x in objects if x and x['kind']=='ConfigMap')['data']['tikti.yaml'])
wi=config['workloadIdentity']
assert wi['codeqBindings']=={'enabled':False,'authorityUrl':'','serviceSubject':'tikti:codeq-binding-exchange','accessTokenTtlSeconds':300,'dependencyTimeoutSeconds':2,'maximumConcurrent':8,'perIdentityPerMinute':6}, wi['codeqBindings']
assert wi['scopedWorkloadBindings'] is False and wi['legacyCodeQAdminGrant'] is True
PY
enabled=(
 --set config.workloadIdentity.codeqBindings.enabled=true
 --set config.workloadIdentity.providers[0].clusterRef=conveste-hostgator
 --set config.workloadIdentity.providers[0].issuer=https://kubernetes.default.svc.cluster.local
 --set config.workloadIdentity.providers[0].jwksUrl=file:///app/etc/workload-jwks/conveste-hostgator.json
)
good='http://code-admin-api.code-admin.svc.cluster.local:8080/internal/v1/codeq-bindings:authorize'
helm template codeq-binding "$chart" "${enabled[@]}" --set config.workloadIdentity.codeqBindings.authorityUrl="$good" > "$output"
helm template codeq-binding "$chart" "${enabled[@]}" --set config.workloadIdentity.codeqBindings.authorityUrl='https://api.internal.example/internal/v1/codeq-bindings:authorize' > "$output"
refuse() {
  if helm template codeq-binding "$chart" "${enabled[@]}" "$@" > "$output" 2>&1; then
    echo "accepted: $*" >&2; exit 1
  fi
}
refuse --set config.workloadIdentity.codeqBindings.authorityUrl=''
refuse --set config.workloadIdentity.codeqBindings.authorityUrl='http://10.0.0.5:8080/internal/v1/codeq-bindings:authorize'
refuse --set config.workloadIdentity.codeqBindings.authorityUrl='http://api.ns.svc.cluster.local/internal/v1/codeq-bindings:authorize'
refuse --set config.workloadIdentity.codeqBindings.authorityUrl="$good" --set config.workloadIdentity.codeqBindings.serviceSubject=tikti:object-storage-sts
refuse --set config.workloadIdentity.codeqBindings.authorityUrl="$good" --set config.workloadIdentity.codeqBindings.accessTokenTtlSeconds=301
refuse --set config.workloadIdentity.codeqBindings.authorityUrl="$good" --set config.workloadIdentity.codeqBindings.dependencyTimeoutSeconds=11
refuse --set config.workloadIdentity.codeqBindings.authorityUrl="$good" --set config.workloadIdentity.codeqBindings.maximumConcurrent=33
refuse --set config.workloadIdentity.codeqBindings.authorityUrl="$good" --set config.workloadIdentity.codeqBindings.perIdentityPerMinute=0
refuse --set config.workloadIdentity.codeqBindings.authorityUrl="$good" --set config.workloadIdentity.providers[1].issuer=https://other.example --set config.workloadIdentity.providers[1].jwksUrl=https://other.example/jwks
echo 'CodeQ binding exchange chart contract passed'
