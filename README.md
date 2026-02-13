# Tikti Identity Service

Tikti is a multi-tenant identity service written in Go with Redis-backed storage. It issues HS256 idTokens for primary authentication and RS256 access tokens for downstream services via token exchange. It ships with a Helm chart, an admin CLI, and a migration tool.

Documentation lives in `docs/` with a full technical specification.

## Configuration

Runtime settings are loaded from a YAML file. Default path is `config/tikti.yaml`.

```yaml
port: 8080
redisAddr: localhost:6379
jwtSecret: supersecret
apiKey: my_api_key
issuerBaseUrl: http://localhost:8080
defaultAudience: tikti
jwksPrivateKey: |
  -----BEGIN PRIVATE KEY-----
  ...
  -----END PRIVATE KEY-----
jwksKeyId: tikti-local-1
```

Run the server:

```bash
go run ./cmd/tikti -f config/tikti.yaml
```

## Binaries

Build the server, CLI, and migration tool:

```bash
go build -o tikti ./cmd/tikti
go build -o tikti-cli ./cmd/tikti-cli
go build -o tikti-migrate ./cmd/tikti-migrate
```

## CLI (admin)

The CLI stores profiles in `~/.tikti/config.yaml`.

Install the CLI from source (requires `go` and `git`):

```bash
curl -fsSL https://raw.githubusercontent.com/osvaldoandrade/tikti/main/install.sh | sh
```

Notes:
- Windows: run the same command from Git Bash (or WSL).
- Pick a version/tag: `TIKTI_REF=v0.2.1 curl -fsSL https://raw.githubusercontent.com/osvaldoandrade/tikti/main/install.sh | sh`
- Pick install dir: `TIKTI_BIN_DIR=$HOME/.local/bin curl -fsSL https://raw.githubusercontent.com/osvaldoandrade/tikti/main/install.sh | sh`

```bash
./tikti-cli init --base-url http://localhost:8080 --api-key my_api_key --tenant default
./tikti-cli auth login --email admin@example.com
./tikti-cli token exchange --audience codeq-worker --event-types render_video
./tikti-cli token show --type worker
./tikti-cli tenant create --name "Acme" --slug acme
./tikti-cli membership add --tenant <tenantId> --email user@example.com --roles COMPANY_EMPLOYEE
./tikti-cli membership remove --tenant <tenantId> --email user@example.com
./tikti-cli role create --tenant <tenantId> --name ops --permissions codeq:claim,codeq:result
./tikti-cli client create --tenant <tenantId> --client-id codeq-worker --grant token_exchange
./tikti-cli jwks
```

## Authentication and Tokens

Tikti issues:
- **idToken (HS256)** for user authentication via `/signIn` and `/signInWithPassword`.
- **accessToken (RS256)** via `/token/exchange`, with `iss`, `aud`, `scope`, `tid`, `eventTypes`, and `ver` claims.

Protected routes require `?key=API_KEY`.

## API Overview (v1)

Core:
- `POST /accounts/signUp`
- `POST /accounts/signIn`
- `POST /accounts/signInWithPassword?key=...`
- `POST /accounts/lookup?key=...`
- `POST /accounts/token/exchange?key=...`
- `GET / .well-known/jwks.json`

Multi-tenant:
- `POST /tenants?key=...`
- `GET /tenants/:id?key=...`
- `POST /tenants/:tenantId/users?key=...`
- `POST /tenants/:tenantId/roles?key=...`
- `GET /tenants/:tenantId/roles?key=...`
- `POST /tenants/:tenantId/clients?key=...`
- `GET /tenants/:tenantId/clients?key=...`

Admin:
- `POST /accounts/status?key=...`
- `POST /accounts/revoke?key=...`
- `POST /accounts/validate?key=...`

Health:
- `GET /healthz`

## Migration (legacy users hash)

The migration tool moves `users` to `users_v2` plus a `userByEmail` index and creates default memberships.

```bash
./tikti-migrate --redis-addr localhost:6379 --default-tenant default --dry-run
./tikti-migrate --redis-addr localhost:6379 --default-tenant default
```

## Helm

```bash
helm upgrade --install tikti ./helm/tikti \
  --set image.repository=ghcr.io/osvaldoandrade/tikti \
  --set image.tag=0.1.0 \
  --set-string config.redisAddr=redis:6379 \
  --set-string secrets.jwtSecret=CHANGE_ME \
  --set-string secrets.apiKey=CHANGE_ME \
  --set-string secrets.jwksPrivateKey=CHANGE_ME
```
