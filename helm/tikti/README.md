# Tikti Helm Chart

This chart installs Tikti with a ConfigMap‑based YAML config and optional Secrets.

## Install

```bash
helm upgrade --install tikti ./helm/tikti \
  --set image.repository=ghcr.io/osvaldoandrade/tikti \
  --set image.tag=0.1.0 \
  --set-string config.redisAddr=redis:6379 \
  --set-string secrets.jwtSecret=CHANGE_ME \
  --set-string secrets.apiKey=CHANGE_ME
```

Ingress is disabled by default. Enable it by setting `ingress.enabled=true` and configuring hosts.
