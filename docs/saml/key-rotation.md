# SP Key Rotation

This document describes the 2-step SP signing key rotation procedure
implemented by the `tikti saml sp rotate` CLI command (see HLD §13, App. D).

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
restart the SP service.

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
