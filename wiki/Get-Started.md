# Get Started

This guide runs Tikti locally, exercises the sign-in and lookup flows, and shows how to exchange an idToken into a RS256 worker token for downstream services (codeQ).

## Prerequisites

- Go 1.24+
- Redis reachable from Tikti (`redisAddr` in config)
- A local config file, typically `config/tikti.yaml`

## 1) Start Redis

If you do not already have Redis running:

```bash
docker run --rm -p 6379:6379 redis:7
```

## 2) Create/Review a Local Config

Default config path is `config/tikti.yaml`.

Minimum local settings:

```yaml
port: 8080
redisAddr: localhost:6379
jwtSecret: supersecret
apiKey: my_api_key
issuerBaseUrl: http://localhost:8080
defaultAudience: tikti
```

For RS256 access/worker tokens you must configure JWKS (see [Tokens and Keys](Tokens-and-Keys)).

## 3) Run Tikti

```bash
go run ./cmd/tikti -f config/tikti.yaml
```

## 4) Sanity Check

```bash
curl -sS http://localhost:8080/healthz
```

## 5) Build Binaries (Optional)

```bash
go build -o tikti ./cmd/tikti
go build -o tikti-cli ./cmd/tikti-cli
go build -o tikti-migrate ./cmd/tikti-migrate
```

## 6) Try the CLI (Admin)

The CLI stores profiles in `~/.tikti/config.yaml`.

Example:

```bash
./tikti-cli init --base-url http://localhost:8080 --api-key my_api_key --tenant default
./tikti-cli auth login --email admin@example.com
./tikti-cli token exchange --audience codeq-worker --event-types render_video
./tikti-cli token show --type worker
```

## 7) SAML Federation Setup

Register an external SAML 2.0 IdP for a tenant, verify the SP metadata Tikti publishes, and test the SP-initiated login flow.

Enable the SAML block in the runtime config first. At minimum, set `saml.enabled=true`, the SP `entityID`, `acsURL`, `sloURL`, `signingKeyPath`, and `signingCertPath`.

Generate SP metadata for the tenant's IdP administrator:

```bash
./tikti-cli saml sp metadata \
  --entity-id https://auth.example.com/saml \
  --acs-url https://auth.example.com/saml/acs \
  --slo-url https://auth.example.com/saml/slo \
  --signing-cert /etc/tikti/saml/sp.crt \
  --out sp-metadata.xml
```

Register the tenant's IdP metadata:

```bash
./tikti-cli saml idp register --tid <tenantId> --metadata-url <url> --attr-map attr-map.json
```

Optionally map an email domain to the tenant for discovery:

```bash
./tikti-cli saml domain add --tid <tenantId> --domain example.com
```

Test SAML login by navigating to `/saml/login/<tenantId>` in a browser. The IdP authenticates the user and posts an assertion back to Tikti, which issues the same HS256 idToken used by all other flows and adds `amr: ["saml"]`.

For the full protocol sequence see [SAML Federation](SAML-Federation).

## Next Pages

- [Overview](Overview)
- [API Specification](API-Specification)
- [Tokens and Keys](Tokens-and-Keys)
- [Multi-Tenant Authorization](Multi-Tenant-Authorization)
- [SAML Federation](SAML-Federation)
- [Operations and SLO](Operations-and-SLO)
