# SP Key Rotation Runbook

This document describes the 2-step SP signing key rotation procedure
implemented by the `tikti saml sp rotate` CLI command (see HLD §13, App. D).

> **Alert playbook:** This runbook is referenced by the
> [SAML alert playbook](alert-playbook.md) for the
> `SAMLSPCertExpiringSoon` alert.

## Prerequisites

- CLI binary `tikti` available on `$PATH`.
- Network access to the Redis instance used by the SP.
- Read/write access to the SP signing key and certificate files on disk.
- Ability to restart the SP service (or trigger a rolling deployment).

## Overview

SAML IdPs cache the SP metadata (including the signing certificate). To
rotate the SP signing key without breaking SSO, the rotation is split into
two steps with a 72-hour grace period in between for IdPs to refresh their
cached metadata.

```
┌──────────┐   --prepare   ┌──────────┐   IdPs refresh   ┌──────────┐   --commit   ┌──────────┐
│ 1 cert   │──────────────▶│ 2 certs  │─────────────────▶│ 2 certs  │────────────▶│ 1 cert   │
│ (K_old)  │               │(K_old +  │   (72 h grace)   │(K_old +  │             │ (K_new)  │
│          │               │ K_new)   │                  │ K_new)   │             │          │
└──────────┘               └──────────┘                  └──────────┘             └──────────┘
```

## Step 1 — Prepare

```bash
tikti saml sp rotate --prepare \
  --entity-id https://auth.example.com/saml \
  --acs-url   https://auth.example.com/saml/acs \
  --slo-url   https://auth.example.com/saml/slo \
  --signing-key sp.key \
  --signing-cert sp.crt \
  --redis-addr localhost:6379 \
  --out metadata.xml
```

This command:

1. Reads the current SP certificate from `--signing-cert`.
2. Generates a new RSA key pair (written to `sp.key.new` / `sp.crt.new`).
3. Publishes SP metadata containing **both** certificates (old + new).
4. Stores rotation state in Redis at `saml:sp:rotation`.

After this step, distribute the new metadata to all IdPs and wait at least
72 hours for their caches to refresh.

## Step 2 — Commit

```bash
tikti saml sp rotate --commit \
  --entity-id https://auth.example.com/saml \
  --acs-url   https://auth.example.com/saml/acs \
  --slo-url   https://auth.example.com/saml/slo \
  --redis-addr localhost:6379 \
  --out metadata.xml
```

This command:

1. Reads the rotation state from Redis.
2. Publishes SP metadata containing **only** the new certificate.
3. Deletes the rotation state from Redis.

After committing, replace `sp.key` / `sp.crt` with the `.new` files and
restart the SP service:

```bash
cp sp.key.new sp.key
cp sp.crt.new sp.crt
# restart the SP (e.g. kubectl rollout or systemctl)
kubectl rollout restart deployment/tikti -n tikti
```

## Verification

After each step, verify the SP metadata endpoint returns the expected
number of certificates:

```bash
# after --prepare: expect 2 KeyDescriptor elements
curl -s https://auth.example.com/saml/metadata | grep -c '<KeyDescriptor'
# expected: 2

# after --commit: expect 1 KeyDescriptor element
curl -s https://auth.example.com/saml/metadata | grep -c '<KeyDescriptor'
# expected: 1
```

Confirm SSO still works by performing a test login:

```bash
tikti saml test --tid <TENANT_ID> --email user@example.com
```

Monitor the `tikti_saml_sp_cert_expiry_seconds` gauge to confirm the new
certificate's expiry is in the future:

```bash
curl -s http://localhost:9090/api/v1/query?query=tikti_saml_sp_cert_expiry_seconds
```

## Rollback

### During Step 1 (after `--prepare`, before `--commit`)

If something goes wrong after `--prepare` but before `--commit`, remove
the rotation state from Redis and delete the generated `.new` files:

```bash
# Remove rotation state from Redis
redis-cli -h <REDIS_HOST> DEL saml:sp:rotation

# Remove the generated key pair
rm -f sp.key.new sp.crt.new
```

Re-publish the original single-cert metadata:

```bash
tikti saml sp metadata \
  --entity-id https://auth.example.com/saml \
  --signing-key sp.key \
  --signing-cert sp.crt \
  --out metadata.xml
```

No service restart is required — the SP is still using the old key.

### After Step 2 (after `--commit`)

If SSO breaks after `--commit` because some IdPs have not yet refreshed
their cached metadata, revert to the old key:

```bash
# Restore the old key and certificate from backup
cp sp.key.bak sp.key
cp sp.crt.bak sp.crt

# Restart the SP to load the restored key
kubectl rollout restart deployment/tikti -n tikti

# Re-publish single-cert metadata with the old certificate
tikti saml sp metadata \
  --entity-id https://auth.example.com/saml \
  --signing-key sp.key \
  --signing-cert sp.crt \
  --out metadata.xml
```

> **Tip:** Always back up `sp.key` and `sp.crt` before starting the
> rotation: `cp sp.key sp.key.bak && cp sp.crt sp.crt.bak`.

## State Guard

Running `--commit` before `--prepare` is rejected with an error:

```
no pending rotation found — run --prepare first
```

## Redis Key

| Key | Type | TTL | Content |
|---|---|---|---|
| `saml:sp:rotation` | string (msgpack) | none | `{old_cert_pem, new_cert_pem, prepared_at}` |

## Flags

| Flag | Default | Description |
|---|---|---|
| `--prepare` | — | Step 1: publish dual-cert metadata |
| `--commit` | — | Step 2: publish single-cert metadata |
| `--entity-id` | — | SP entity ID |
| `--acs-url` | — | Assertion Consumer Service URL |
| `--slo-url` | — | Single Logout Service URL |
| `--signing-key` | `sp.key` | Path to current SP signing key |
| `--signing-cert` | `sp.crt` | Path to current SP signing cert |
| `--redis-addr` | `localhost:6379` | Redis address |
| `--key-bits` | `2048` | RSA key size for new key (2048 or 3072) |
| `--out` | stdout | Write metadata XML to file |
