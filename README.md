# Tikti Identity Service

Tikti is a multi-tenant identity service written in Go. It stores all state in Redis, issues HS256 idTokens for primary authentication, and exchanges those idTokens for RS256 access tokens consumed by downstream services. Tikti authenticates users through two paths: a credential-based path (`/signIn`, `/signInWithPassword`) and a SAML 2.0 federation path where Tikti acts as Service Provider and delegates authentication to an external Identity Provider. Both paths produce the same HS256 idToken with identical claims, so downstream token exchange and JWKS verification work without modification regardless of how the user authenticated.

Tikti ships with three binaries (server, CLI, migration tool), a Helm chart for Kubernetes deployment, and a full technical specification under `docs/`.

## Configuration

The server reads its runtime settings from a YAML file. The default path is `config/tikti.yaml`. The file contains the HTTP listen port, Redis address, the HS256 signing secret, an API key for protected admin routes, the issuer base URL embedded in token claims, the default audience, and the RS256 private key used to sign access tokens. A minimal configuration looks like this:

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

When SAML federation is enabled, the configuration file includes an additional `saml` block that controls the SP entity, assertion consumer service URL, signing and encryption key paths, and validation parameters:

```yaml
saml:
  enabled: true
  sp:
    entityID: "${issuerBaseUrl}/saml"
    acsURL: "${issuerBaseUrl}/saml/acs"
    sloURL: "${issuerBaseUrl}/saml/slo"
    signingKeyPath: "/etc/tikti/saml/sp.key"
    signingCertPath: "/etc/tikti/saml/sp.crt"
    encryptionKeyPath: "/etc/tikti/saml/sp.key"
    encryptionCertPath: "/etc/tikti/saml/sp.crt"
    keyBits: 2048
    clockSkewSeconds: 120
    requestTTLSeconds: 300
    allowedSigAlgs: ["rsa-sha256"]
    allowedDigestAlgs: ["sha256"]
    canonicalization: "xml-exc-c14n"
    requireAssertionSigned: true
    requireEncryptedAssertion: false
  acs:
    postLoginURL: "/dashboard"
    deliveryMode: "cookie"
    cookieName: "tikti_idt"
    cookieSameSite: "Lax"
    cookieSecure: true
    cookieHTTPOnly: true
  idp:
    refreshIntervalHours: 24
    backgroundRefresh: true
  discover:
    enabled: true
    emailDomainIndexKey: "saml:discover:domain"
  metrics:
    namespace: "tikti"
    subsystem: "saml"
```

Per-tenant IdP records are not stored in YAML. They live in Redis and are managed through the CLI, keeping the configuration file static at deploy time and the trust table mutable at runtime.

To start the server, pass the config file path:

```bash
go run ./cmd/tikti -f config/tikti.yaml
```

## Binaries

The project produces three binaries. The server binary (`tikti`) runs the HTTP API. The CLI binary (`tikti-cli`) provides admin commands for tenant management, token operations, and SAML federation. The migration binary (`tikti-migrate`) handles schema transitions for the Redis keyspace.

```bash
go build -o tikti ./cmd/tikti
go build -o tikti-cli ./cmd/tikti-cli
go build -o tikti-migrate ./cmd/tikti-migrate
```

## CLI

The CLI stores connection profiles in `~/.tikti/config.yaml`. Each profile holds a base URL, API key, and default tenant.

Install from source (requires `go` and `git`):

```bash
curl -fsSL https://raw.githubusercontent.com/osvaldoandrade/tikti/main/install.sh | sh
```

On Windows, run the same command from Git Bash or WSL. To pin a version, set `TIKTI_REF=v0.2.1` before the curl. To change the install directory, set `TIKTI_BIN_DIR=$HOME/.local/bin`.

Install via npm (requires `node`/`npm`):

```bash
npm install -g @osvaldoandrade/tikti-cli
```

Upgrade to the latest release:

```bash
npm install -g @osvaldoandrade/tikti-cli@latest
```

After installation, initialize a profile and begin issuing commands:

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

### SAML CLI Commands

The CLI includes a `saml` command group for managing SAML federation. These commands register and inspect IdP trust relationships, rotate SP keys, and map email domains to tenants for discovery.

Print the SP metadata XML that you provide to an external IdP during onboarding:

```bash
./tikti-cli saml metadata [--out FILE]
```

Register an IdP for a tenant by fetching its metadata URL. The CLI downloads the IdP's `EntityDescriptor`, extracts the SSO URL and signing certificates, and writes a `saml:idp:{tid}` record to Redis:

```bash
./tikti-cli saml idp register --tid <tenantId> --metadata-url <URL> [--attr-map FILE]
```

Inspect the stored IdP configuration for a tenant:

```bash
./tikti-cli saml idp show --tid <tenantId> [--json]
```

Rotate SP signing and encryption keys using a two-step process. The `--prepare` step publishes both old and new certificates in the SP metadata, giving IdPs time to refresh. The `--commit` step removes the old certificate:

```bash
./tikti-cli saml keys rotate --prepare
./tikti-cli saml keys rotate --commit
```

Additional SAML CLI commands include `saml idp update`, `saml idp remove`, `saml idp list`, `saml idp fetch` (force metadata refresh), `saml test` (emit a test AuthnRequest URL), `saml domain add`, and `saml domain remove`.

## Authentication and Tokens

Tikti issues two token types. The idToken is signed with HS256 using the `jwtSecret` from configuration. The credential-based path (`/signIn`, `/signInWithPassword`) and the SAML federation path (`/saml/acs`) both produce this idToken. When authentication occurs through SAML, the idToken carries an `amr: ["saml"]` claim; the credential path sets `amr: ["pwd"]`. All other claims (`sub`, `tid`, `iat`, `exp`) remain identical across both paths.

The access token is signed with RS256 using the private key specified by `jwksPrivateKey`. Clients obtain it by calling `/token/exchange` with a valid idToken. The access token carries `iss`, `aud`, `scope`, `tid`, `eventTypes`, and `ver` claims. Relying parties verify access tokens offline by fetching the public key from `/.well-known/jwks.json`.

Protected admin routes require the API key as a query parameter: `?key=API_KEY`.

## SAML 2.0 Federation

Tikti acts as a SAML 2.0 Service Provider. Each tenant binds to one external Identity Provider (Azure AD, Okta, Ping, ADFS, Google Workspace, OneLogin, Keycloak, or any SAML 2.0-compliant IdP). The federation uses the Web Browser SSO Profile with HTTP-Redirect binding for outbound AuthnRequests and HTTP-POST binding for inbound Responses.

### SP-Initiated SSO Flow

The browser requests `GET /saml/login/{tid}`. Tikti loads the IdP record for that tenant from Redis (`saml:idp:{tid}`), builds a signed `AuthnRequest` (RSA-SHA256), stores a request correlation record in Redis with a 300-second TTL (`saml:req:{id}`), and redirects the browser to the IdP's SSO URL with the deflated, base64-encoded `SAMLRequest`, `RelayState`, `SigAlg`, and `Signature` query parameters.

The IdP authenticates the user and returns a signed SAML Response via HTTP-POST to `/saml/acs`. Tikti validates the response through a 10-step pipeline: verify `InResponseTo` correlation, check `Destination` matches the ACS URL, confirm top-level `Status` is `Success`, verify the Response signature against the pinned IdP certificate, decrypt `EncryptedAssertion` if present, verify the Assertion signature, check `Issuer` matches the configured IdP `entityID`, confirm `Audience` contains the Tikti SP `entityID`, validate `NotBefore`/`NotOnOrAfter` within the 120-second clock skew, and verify `SubjectConfirmationData`. The first failing step rejects the response.

After validation, Tikti deletes the request correlation record, writes a replay guard (`saml:seen:{assertionID}`, TTL 3600 seconds), maps assertion attributes to user fields using the tenant's attribute map, JIT-provisions or updates the user record, and calls `auth.issueIDToken` with `amr=["saml"]`. The resulting HS256 idToken is delivered to the browser via a cookie (`tikti_idt`), and the browser is redirected to the `RelayState` URL. From this point, the token exchange path proceeds identically to the credential-based flow.

### Single Logout

Tikti supports SP-initiated and IdP-initiated Single Logout. For SP-initiated logout, `GET /saml/logout/{tid}` builds a signed `LogoutRequest` containing the user's `NameID` and `SessionIndex`, then redirects to the IdP's SLO URL. The IdP processes the logout and redirects back to `/saml/slo` with a `LogoutResponse`. Tikti verifies the response, deletes the session and SAML index records from Redis, and redirects to the post-logout URL.

For IdP-initiated logout, the IdP POSTs a `LogoutRequest` to `/saml/slo`. Tikti verifies the signature, extracts the `NameID` and `SessionIndex`, deletes the corresponding session and index records, and returns a signed `LogoutResponse` to the IdP.

### Tenant Routing and Discovery

The `tid` is extracted from the URL path in `/saml/login/{tid}`, never from the SAML assertion, to prevent tenant escalation via a compromised IdP. For deployments with tenant-specific hostnames, the host header maps to a `tid` via an alias table. The `/saml/discover` endpoint provides email-domain-based tenant lookup: the browser submits an email address, Tikti resolves the domain to a `tid`, and redirects to `/saml/login/{tid}`.

## API Overview (v1)

### Core

| Endpoint | Method | Description |
|---|---|---|
| `/accounts/signUp` | POST | Register a new user account |
| `/accounts/signIn` | POST | Authenticate and receive an HS256 idToken |
| `/accounts/signInWithPassword?key=...` | POST | Admin-initiated password authentication |
| `/accounts/lookup?key=...` | POST | Look up an account by email |
| `/accounts/token/exchange?key=...` | POST | Exchange an HS256 idToken for an RS256 access token |
| `/workloads/token/exchange` | POST | Exchange a projected Kubernetes ServiceAccount JWT for a tenant-bound provider token |
| `/workloads/bindings` | POST | Create or replace a workload-to-tenant authorization binding (`X-API-Key`) |
| `/workloads/bindings/revoke` | POST | Revoke a workload binding (`X-API-Key`) |
| `/.well-known/jwks.json` | GET | Publish RS256 public keys for offline verification |

### Multi-Tenant

| Endpoint | Method | Description |
|---|---|---|
| `/tenants?key=...` | POST | Create a tenant |
| `/tenants/:tenantId` | PUT | Create a deterministic tenant without overwrite (`X-API-Key` required) |
| `/tenants/:id?key=...` | GET | Retrieve a tenant |
| `/tenants/:tenantId/users?key=...` | POST | Add a user to a tenant |
| `/tenants/:tenantId/roles?key=...` | POST | Create a role within a tenant |
| `/tenants/:tenantId/roles?key=...` | GET | List roles within a tenant |
| `/tenants/:tenantId/clients?key=...` | POST | Register a client for a tenant |
| `/tenants/:tenantId/clients?key=...` | GET | List clients for a tenant |

### Admin

| Endpoint | Method | Description |
|---|---|---|
| `/accounts/status?key=...` | POST | Set account status (enable/disable) |
| `/accounts/revoke?key=...` | POST | Revoke an account's tokens |
| `/accounts/validate?key=...` | POST | Validate an account's credentials |

### SAML

| Endpoint | Method | Description |
|---|---|---|
| `/saml/metadata` | GET | Emit the SP `EntityDescriptor` XML |
| `/saml/login/{tid}` | GET | Build a signed `AuthnRequest` and redirect to the IdP |
| `/saml/acs` | POST | Consume the IdP's SAML Response and issue an idToken |
| `/saml/logout/{tid}` | GET | Build a signed `LogoutRequest` and redirect to the IdP |
| `/saml/slo` | GET, POST | Handle SP-initiated logout response or IdP-initiated logout request |
| `/saml/discover` | GET | Resolve an email domain to a `tid` for tenant routing |

### Health

| Endpoint | Method | Description |
|---|---|---|
| `/healthz` | GET | Liveness check |

## Migration

The migration tool moves user records from the `users` hash to `users_v2` with a `userByEmail` index and creates default tenant memberships. Run with `--dry-run` first to preview changes:

```bash
./tikti-migrate --redis-addr localhost:6379 --default-tenant default --dry-run
./tikti-migrate --redis-addr localhost:6379 --default-tenant default
```

When SAML federation is enabled, migration `0007_saml_user_fields` adds the `authSource` field (values: `password`, `saml`; default: `password`) and the `externalSubject` field (default: empty string) to every user record. Existing users retain `authSource=password`. Users provisioned through SAML JIT receive `authSource=saml` and an `externalSubject` set to the IdP's `NameID`.

## Helm

Deploy Tikti to Kubernetes using the bundled Helm chart. The chart creates the deployment, service, config map, and secrets. Pass the Redis address, HS256 secret, API key, and RS256 private key as values:

```bash
helm upgrade --install tikti ./helm/tikti \
  --set image.repository=ghcr.io/osvaldoandrade/tikti \
  --set image.tag=0.1.0 \
  --set-string config.redisAddr=redis:6379 \
  --set-string secrets.jwtSecret=CHANGE_ME \
  --set-string secrets.apiKey=CHANGE_ME \
  --set-string secrets.jwksPrivateKey=CHANGE_ME
```

For SAML federation, add the SP signing key and certificate. The chart mounts them into the pod at the paths specified by `saml.sp.signingKeyPath` and `saml.sp.signingCertPath`. Append these flags to the `helm upgrade` command above:

```bash
  --set saml.enabled=true \
  --set-file secrets.samlSigningKey=sp.key \
  --set-file secrets.samlSigningCert=sp.crt
```
