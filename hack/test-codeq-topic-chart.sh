#!/usr/bin/env bash
set -euo pipefail
chart="$(cd "$(dirname "$0")/../helm/tikti" && pwd)"
output="$(mktemp)"
trap 'rm -f "$output"' EXIT
helm template topic-authority "$chart" > "$output"
python3 - "$output" <<'PY'
import sys,yaml
objects=list(yaml.safe_load_all(open(sys.argv[1])))
config=next(x for x in objects if x and x['kind']=='ConfigMap')['data']['tikti.yaml']
assert yaml.safe_load(config)['workloadIdentity']['codeqTopicController']['enabled'] is False
PY
if helm template topic-authority "$chart" --set config.workloadIdentity.codeqTopicController.enabled=true > "$output" 2>&1; then
  echo 'missing identity accepted' >&2; exit 1
fi
helm template topic-authority "$chart" \
 --set config.workloadIdentity.codeqTopicController.enabled=true \
 --set config.workloadIdentity.codeqTopicController.issuer=https://master.example \
 --set config.workloadIdentity.codeqTopicController.clusterRef=master \
 --set config.workloadIdentity.codeqTopicController.namespace=code-admin \
 --set config.workloadIdentity.codeqTopicController.serviceAccount=controller-cluster \
 --set config.workloadIdentity.codeqTopicController.serviceAccountUID=test-only-uid \
 --set config.workloadIdentity.issuer=https://master.example \
 --set config.workloadIdentity.clusterRef=master \
 --set config.workloadIdentity.jwksUrl=https://master.example/jwks > "$output"
echo 'CodeQ topic authority chart contract passed'
