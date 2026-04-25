# Tikti Helm Chart

The Tikti Helm chart deploys the Tikti identity service into a Kubernetes cluster. It renders a ConfigMap that holds the application's YAML configuration, a Secret that stores credentials and SAML SP keypair material, a Service, a Deployment, and an Ingress resource. The chart reads all tunables from `values.yaml` and accepts overrides through `--set` and `--set-string` flags at install time.

## Install

```bash
helm upgrade --install tikti ./helm/tikti \
  --set image.repository=ghcr.io/osvaldoandrade/tikti \
  --set image.tag=0.1.0 \
  --set-string config.redisAddr=redis:6379 \
  --set-string secrets.jwtSecret=CHANGE_ME \
  --set-string secrets.apiKey=CHANGE_ME \
  --set-string secrets.jwksPrivateKey=CHANGE_ME \
  --set-string secrets.samlSpPrivateKey=CHANGE_ME \
  --set-string secrets.samlSpCertificate=CHANGE_ME
```

## Configuration

The chart exposes values under three groups. `image.repository` and `image.tag` control the container image. `replicaCount` sets the number of pods. `resources` accepts standard Kubernetes resource requests and limits. `config.redisAddr` and `config.redisDb` point the application at a Redis instance. `ingress.enabled`, `ingress.className`, `ingress.hosts`, and `ingress.tls` configure the Ingress resource. Under `secrets`, the chart stores `jwtSecret`, `apiKey`, `redisPassword`, and `jwksPrivateKey` as Kubernetes Secrets.

Ingress is disabled by default. Enable it by setting `ingress.enabled=true` and configuring hosts.

## SAML

Set `saml.enabled=true` to mount `/saml/*` routes and the SP key volume.

### Inline keys

Provide keys directly (suitable for dev/test):

```bash
helm upgrade --install tikti ./helm/tikti \
  --set saml.enabled=true \
  --set-file saml.sp.key=sp.key \
  --set-file saml.sp.crt=sp.crt \
  --set saml.sp.entityID=https://sp.example.com/saml/metadata \
  --set saml.sp.acsURL=https://sp.example.com/saml/acs
```

### External secret (staging / production)

When using `external-secrets-operator` or a pre-provisioned Secret, set `saml.existingSecret` to skip the chart-managed Secret and mount the named Secret instead:

```bash
helm upgrade --install tikti ./helm/tikti \
  --set saml.enabled=true \
  --set saml.existingSecret=tikti-saml-external \
  --set saml.sp.entityID=https://sp.example.com/saml/metadata \
  --set saml.sp.acsURL=https://sp.example.com/saml/acs
```

### Staging overlay

A `values-staging.yaml` overlay is provided for staging dogfood deployments. It enables SAML with defaults for an Okta integration:

```bash
helm upgrade --install tikti ./helm/tikti \
  -f helm/tikti/values-staging.yaml \
  --set saml.existingSecret=tikti-saml-external \
  --set saml.sp.entityID=https://staging.example.com/saml/metadata \
  --set saml.sp.acsURL=https://staging.example.com/saml/acs \
  --set saml.idp.metadataURL=https://your-org.okta.com/app/APPID/sso/saml/metadata
```

After deploying, onboard the test tenant via CLI:

```bash
tikti-cli saml idp register \
  --tid <TENANT_ID> \
  --metadata-url https://your-org.okta.com/app/APPID/sso/saml/metadata
```
