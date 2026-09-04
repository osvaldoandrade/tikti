# 09 CLI Specification

This document specifies the Tikti command-line interface. The CLI is a client that exercises the HTTP API and provides automation for operators, CI, and local development. The CLI covers tenant administration, SAML federation management, token exchange, and validation workflows required by codeQ and other resource servers.

## Purpose and scope

The CLI provides four categories of functionality. It authenticates a user and manages the local session context, including base URLs, API keys, and tokens. It exposes administrative operations: tenant creation, user membership management, role and client configuration, and API key rotation. It manages SAML 2.0 federation lifecycle: IdP registration, SP metadata retrieval, and SP key rotation. It supports token exchange and local inspection of tokens and JWKS for integration debugging.

The CLI does not depend on environment variables for operation. It supports interactive initialization and command flags. It persists configuration locally in a file at a fixed path and never prints secrets unless the operator requests it. Network requests are idempotent where the HTTP method allows it and return machine-parseable output for automation.

## Configuration model

The CLI stores configuration in a YAML file at `~/.tikti/config.yaml`. The file contains named profiles. Each profile includes the Tikti base URL, IAM API key, a tenant identifier, and the tokens from the last authentication or exchange operation. The CLI operates in one profile at a time. The operator selects a profile per command via `--profile`.

```yaml
currentProfile: default
profiles:
  default:
    baseUrl: https://api.storifly.ai
    apiKey: <api_key>
    tenantId: tenant-1
    idToken: <hs256-token>
    accessToken: <rs256-token>
    workerToken: <rs256-token>
```

The CLI supports both interactive and non-interactive initialization. Interactive initialization prompts for the base URL and API key, and optionally a tenant. Non-interactive initialization uses flags and never prompts. If a profile exists, the CLI updates only the provided fields and preserves existing tokens unless the operator overwrites them.

Configuration lookup is O(1) with respect to the number of profiles because it is a keyed lookup on the profile name. When a profile is missing, the CLI returns an error rather than creating a profile.

## Authentication commands

The CLI exposes an `auth` command that authenticates a user and stores the resulting idToken in the profile. Authentication uses the `signInWithPassword` endpoint and requires an API key.

```bash
tikti-cli init
tikti-cli auth login --email admin@codecompany.com.br
```

The `auth login` command prompts for the password if it is not provided by flag. The password is never logged or stored. The resulting idToken is stored in the profile and used by subsequent commands that require user identity.

The CLI also provides `auth logout`, which clears stored tokens for the profile. This command is idempotent and returns success even if no tokens are present.

## Token exchange commands

The CLI provides a `token exchange` command that calls the `token/exchange` endpoint and stores the resulting access or worker token. The command accepts the audience, scopes, tenant id, subject, and event types. The idToken from the profile is used unless the operator overrides it.

```bash
tikti-cli token exchange \
  --audience codeq-worker \
  --scopes codeq:claim,codeq:result,codeq:subscribe \
  --event-types render_video,generate_master \
  --tenant tenant-1 \
  --subject worker-1
```

The CLI translates comma-separated scopes and event types into arrays in the request body. The CLI stores the returned token in the profile under `workerToken` if the audience is `codeq-worker`, and under `accessToken` otherwise. This rule eliminates ambiguity and makes subsequent worker operations deterministic.

Token exchange is O(1) in local computation. The cost is dominated by network round-trip and server-side authorization, which is outside the CLI's complexity model.

## Tenant administration commands

The CLI exposes a `tenant` command group. These commands require an idToken with admin role. The CLI does not enforce roles locally; it relies on server responses.

```bash
tikti-cli tenant create --name "Code Company" --slug codecompany
tikti-cli tenant get --tenant tenant-1
```

The CLI includes the profile's idToken in the Authorization header when calling admin endpoints. It rejects execution if no idToken is present and instructs the operator to log in.

## User administration commands

The CLI exposes a `user` command group for user lifecycle operations. These commands require an admin token and operate either globally (user creation) or within a tenant (membership and status). The CLI makes the scope explicit via flags so the operator does not apply a change across tenants by mistake.

`user create` creates a user with email, password, and a role. This maps to `POST /v1/accounts/signUp` and uses the admin token in the Authorization header. The CLI never prints the password after submission.

```bash
tikti-cli user create --email user@company.com --password 'Secret123' --role COMPANY_EMPLOYEE
```

`user get` fetches identity metadata for the current idToken. This maps to `lookup`.

```bash
tikti-cli user get
```

`user suspend` sets user status to SUSPENDED, which prevents new token exchanges and sign-in. This requires `POST /v1/accounts/status`.

```bash
tikti-cli user suspend --email user@company.com
```

`user activate` sets user status to ACTIVE.

```bash
tikti-cli user activate --email user@company.com
```

`user delete` deletes the current user (idToken owner). This maps to `POST /v1/accounts/delete`.

```bash
tikti-cli user delete --confirm
```

The CLI requires `--confirm` for destructive actions. The output includes the user id and affected tenants when the server provides them.

## Membership and role commands

The CLI exposes `membership` and `role` command groups for managing tenant memberships and roles. These commands send and receive JSON as defined in `04_api_spec.md` and require explicit tenant targeting.

```bash
tikti-cli membership add --tenant tenant-1 --email user@company.com --roles TENANT_USER
tikti-cli membership remove --tenant tenant-1 --email user@company.com
tikti-cli role create --tenant tenant-1 --name CODEQ_ADMIN \
   --permissions codeq:admin,codeq:claim,codeq:result
```

Tenant, role and client reads, plus membership commands, require the profile's
scoped RS256 `accessToken`, send the API key only in `X-API-Key`, and never
append it to the URL. If no access token is stored, the CLI stops locally and
instructs the operator to exchange one for the target tenant. The server remains
authoritative for audience, scope, and exact `tid` matching.

The CLI validates that role names and permissions are non-empty strings but does not enforce policy semantics client-side. The server remains authoritative.

## Access revocation commands

The CLI exposes a `revoke` command group for revoking access. Revocation invalidates tokens before expiration. The system supports two revocation strategies: status-based revocation and token-version revocation. The CLI supports both methods when the server supports them.

### Status-based revocation

Suspending a user or removing a membership prevents future token exchange. This is implemented via `user suspend` and `membership remove`. Issued tokens remain valid until they expire, but renewal is blocked. This is sufficient for operations with token lifetimes between 900 and 3600 seconds.

### Token-version revocation

To invalidate tokens before expiry, Tikti supports a global token version mechanism. A `tokenVersion` field is stored on the user. Tokens include `ver` and are rejected if `ver` does not match the stored version.

The CLI command `revoke tokens` increments the global token version for a user:

```bash
tikti-cli revoke tokens --email user@company.com
```

This calls `POST /v1/accounts/revoke` with `scope=global`. The retained
`--tenant` and `--scope` flags do not claim a capability that the storage model
does not have: `--tenant`, `--scope tenant`, and any non-global scope fail
locally without an HTTP request. The server returns the new global token version
and revocation timestamp. This operation is O(1) because it updates one user
record in Redis.

### JTI blacklist

As an alternative, Tikti can maintain a blacklist keyed by token `jti` with TTL set to token expiration. The CLI exposes `revoke jti --token <jwt>` which extracts `jti` and calls a blacklist endpoint. This approach is O(1) per revoke and O(1) per validation but increases Redis memory proportional to the number of revoked tokens.

The CLI states which revocation strategy is active by inspecting server capabilities or configuration.

## Client and API key commands

The CLI manages clients and API keys because these objects are required for token exchange and protected endpoints. The CLI never prints client secrets unless `--show-secret` is provided, and it redacts secrets in logs.

```bash
tikti-cli client create --tenant tenant-1 --client-id codeq-worker --type SERVICE \
   --grant token_exchange --scopes codeq:claim,codeq:result
```

When a client secret is generated, the CLI prints it once and stores it only if the operator passes `--store-secret`. By default the secret is not persisted in the local config.

## SAML federation commands

The CLI exposes a `saml` command group for managing SAML 2.0 federation lifecycle. These commands handle SP metadata retrieval, IdP registration and inspection, and SP signing key rotation. They are part of the standard admin toolset alongside tenant, membership, role, client, and token commands.

### SP metadata retrieval

`saml metadata` fetches the SP metadata XML from the Tikti server and writes it to stdout. Operators use this output to register Tikti as an SP in the IdP admin console during initial SAML setup.

```bash
tikti-cli saml metadata
tikti-cli saml metadata --output json
```

The command sends `GET /saml/metadata` and returns the XML document. When `--output json` is specified, the CLI parses the XML and emits a JSON object containing the entity ID, ACS URL, SLO URL, and signing certificate.

### IdP registration

`saml idp register` registers an external IdP for a tenant. The command accepts IdP metadata as a URL or a local file path. It parses the IdP metadata XML to extract the entity ID, SSO URL, SLO URL, and signing certificate, then stores the configuration in Redis under `saml:idp:{tenantId}`.

```bash
tikti-cli saml idp register --tenant tenant-1 --metadata-url https://idp.example.com/metadata
tikti-cli saml idp register --tenant tenant-1 --metadata-file /path/to/idp-metadata.xml
```

For environments where metadata XML is unavailable, the command accepts manual configuration flags:

```bash
tikti-cli saml idp register --tenant tenant-1 \
  --entity-id https://idp.example.com \
  --sso-url https://idp.example.com/sso \
  --slo-url https://idp.example.com/slo \
  --cert-file /path/to/idp-signing.pem
```

The command requires either `--metadata-url` or `--metadata-file` or the full set of manual flags (`--entity-id`, `--sso-url`, `--cert-file`). The `--slo-url` flag is optional because not all IdPs support Single Logout. The command validates the certificate format before storing the configuration and returns the stored entity ID and tenant binding on success.

| Flag | Required | Description |
|------|----------|-------------|
| `--tenant` | yes | Target tenant identifier |
| `--metadata-url` | one of metadata-url, metadata-file, or manual set | URL of the IdP metadata XML endpoint |
| `--metadata-file` | one of metadata-url, metadata-file, or manual set | Local file path to IdP metadata XML |
| `--entity-id` | required if no metadata | IdP entity ID |
| `--sso-url` | required if no metadata | IdP SSO endpoint URL |
| `--slo-url` | no | IdP SLO endpoint URL |
| `--cert-file` | required if no metadata | Path to IdP signing certificate PEM file |

### IdP configuration inspection

`saml idp show` displays the stored IdP configuration for a tenant. The output includes the entity ID, SSO URL, SLO URL, certificate fingerprint (SHA-256), and attribute mapping.

```bash
tikti-cli saml idp show --tenant tenant-1
tikti-cli saml idp show --tenant tenant-1 --output json
```

The command reads from `saml:idp:{tenantId}` in Redis via the API. It never outputs the full certificate; it prints only the SHA-256 fingerprint.

### SP key rotation

`saml keys rotate` rotates the SP signing keypair used to sign SAML AuthnRequests. The command generates a new RSA keypair, publishes both old and new keys in the SP metadata during an overlap window, and removes the old key after a grace period.

```bash
tikti-cli saml keys rotate
tikti-cli saml keys rotate --grace-period 24h
```

The `--grace-period` flag controls how long both keys remain in the SP metadata. The default is 24 hours. During this window, IdPs that cache SP metadata can validate signatures made with either key. After the grace period, the old key is removed from the metadata and deleted from storage.

The command requires an admin idToken. It calls the key rotation endpoint and returns the new key's `kid`, the overlap window start time, and the scheduled removal time for the old key.

## JWKS inspection

The CLI includes a `jwks` command that fetches and prints the JWKS. This is used for integration debugging.

```bash
tikti-cli jwks
```

The CLI supports `--output json` and `--output pretty` formatting. The JWKS fetch is a GET request and the CLI caches the response for the duration of the process.

## Output format and exit codes

All commands support `--output json` for automation. In JSON mode, the CLI emits a single JSON object or array to stdout with no formatting beyond the JSON structure. In human mode, the CLI emits text lines. Errors are written to stderr and include the HTTP status code and response body when the server provides them.

Exit codes:

- 0 on success
- 1 on validation or request errors
- 2 on authentication errors
- 3 on configuration errors

## Security requirements

The CLI never logs passwords, access tokens, or API keys. It stores tokens in the local config file with file permissions restricted to the current user. On Unix systems, the CLI sets `0600` permissions when writing the config file. The CLI does not use environment variables by default, but it reads them for non-interactive automation when the operator enables `--use-env`.

## Example: end-to-end worker setup

This example shows a flow that initializes config, logs in, exchanges a worker token, and prints it.

```bash
tikti-cli init --base-url https://api.storifly.ai --api-key $API_KEY --tenant tenant-1
tikti-cli auth login --email admin@codecompany.com.br
tikti-cli token exchange \
   --audience codeq-worker \
   --scopes codeq:claim,codeq:heartbeat,codeq:result \
   --event-types render_video \
   --tenant tenant-1 \
   --subject worker-1
tikti-cli token show --type worker
```

This flow is deterministic and does not require environment variables. All state is stored in the profile.

## Example: SAML IdP onboarding

This example shows the flow for onboarding a tenant's IdP via SAML federation.

```bash
tikti-cli auth login --email admin@codecompany.com.br
tikti-cli saml metadata > sp-metadata.xml
tikti-cli saml idp register --tenant tenant-1 \
  --metadata-url https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml
tikti-cli saml idp show --tenant tenant-1
```

The operator exports the SP metadata XML and uploads it to the IdP admin console. Then the operator registers the IdP metadata URL with Tikti. The `saml idp show` command confirms that the IdP configuration is stored and the trust relationship is established.

## Command surface

The CLI includes these command groups: `init`, `auth`, `token`, `tenant`, `user`, `membership`, `role`, `client`, `apikey`, `jwks`, `saml`, `revoke`, and `config`. The `saml` group contains `metadata`, `idp register`, `idp show`, and `keys rotate` subcommands.
