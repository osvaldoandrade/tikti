# Using external-secrets-operator with SAML SP Keys

This document describes how to provision the SAML SP signing key and
certificate via [external-secrets-operator](https://external-secrets.io)
instead of letting the Helm chart manage the Secret directly.

## Prerequisites

| Component | Minimum version |
|---|---|
| external-secrets-operator | 0.9+ |
| Helm chart `tikti` | 0.1.0+ |

You also need a configured `SecretStore` or `ClusterSecretStore` pointing at
your secrets backend (AWS Secrets Manager, HashiCorp Vault, GCP Secret
Manager, Azure Key Vault, etc.).

## Overview

By default the chart creates a `Secret` named `<release>-saml` containing
`sp.key` and `sp.crt` from `values.yaml`. In production you should **not**
store private key material in Helm values. Instead:

1. Store the SP key and certificate in your external secrets backend.
2. Create an `ExternalSecret` that syncs them into a Kubernetes Secret.
3. Set `saml.existingSecret` in your Helm values so the chart skips its own
   Secret and the deployment references the pre-provisioned one.

## Step 1 — Store secrets in your backend

Example for AWS Secrets Manager:

```bash
aws secretsmanager create-secret \
  --name tikti/saml/sp \
  --secret-string '{
    "sp.key": "<PEM PKCS#8 private key>",
    "sp.crt": "<PEM X.509 certificate>"
  }'
```

## Step 2 — Create an ExternalSecret

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: tikti-saml
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: my-secret-store   # your SecretStore name
    kind: SecretStore
  target:
    name: tikti-saml-external   # the K8s Secret that will be created
    creationPolicy: Owner
  data:
    - secretKey: sp.key
      remoteRef:
        key: tikti/saml/sp
        property: sp.key
    - secretKey: sp.crt
      remoteRef:
        key: tikti/saml/sp
        property: sp.crt
```

After applying this manifest, external-secrets-operator creates a Kubernetes
Secret named `tikti-saml-external` with `sp.key` and `sp.crt` data keys.

## Step 3 — Configure the Helm release

```yaml
# values-production.yaml
saml:
  enabled: true
  existingSecret: tikti-saml-external
  sp:
    key: ""   # ignored when existingSecret is set
    crt: ""   # ignored when existingSecret is set
```

Or via `--set`:

```bash
helm upgrade --install tikti ./helm/tikti \
  --set saml.enabled=true \
  --set saml.existingSecret=tikti-saml-external
```

With `saml.existingSecret` set, the chart does **not** render its own
`Secret` resource. The deployment mounts the named Secret instead.

## Vault example

For HashiCorp Vault with the KV v2 engine:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: tikti-saml
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: tikti-saml-external
    creationPolicy: Owner
  data:
    - secretKey: sp.key
      remoteRef:
        key: secret/data/tikti/saml/sp
        property: sp.key
    - secretKey: sp.crt
      remoteRef:
        key: secret/data/tikti/saml/sp
        property: sp.crt
```

## Key rotation

When rotating SP keys, update the value in your secrets backend. The
external-secrets-operator will sync the change on the next
`refreshInterval`. See [key-rotation.md](key-rotation.md) for the full
2-step rotation procedure.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Pod fails to start with missing mount | `existingSecret` name does not match `ExternalSecret` target | Verify `target.name` in ExternalSecret matches `saml.existingSecret` |
| Secret exists but keys are empty | Remote ref path is wrong | Check `remoteRef.key` and `remoteRef.property` |
| Secret not created | SecretStore auth failure | Run `kubectl describe externalsecret` and check status conditions |
