# CLI Reference

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

The CLI validates that role names and permissions are non-empty strings but does not enforce policy semantics client-side. The server remains authoritative.

## Access revocation commands

The CLI exposes a `revoke` command group for revoking access. Revocation invalidates tokens before expiration. The system supports two revocation strategies: status-based revocation and token-version revocation. The CLI supports both methods when the server supports them.

### Status-based revocation

Suspending a user or removing a membership prevents future token exchange. This is implemented via `user suspend` and `membership remove`. Issued tokens remain valid until they expire, but renewal is blocked. This is sufficient for operations with token lifetimes between 900 and 3600 seconds.

### Token-version revocation

To invalidate tokens before expiry, Tikti supports a token version mechanism. A `tokenVersion` field is stored on the user and on the membership. Tokens include `ver` and are rejected if `ver` does not match the stored version.

The CLI command `revoke tokens` increments the token version for a user or tenant membership:

```bash
tikti-cli revoke tokens --email user@company.com
tikti-cli revoke tokens --tenant tenant-1 --email user@company.com
```

This requires a dedicated endpoint (`POST /v1/accounts/revoke` or `POST /v1/tenants/{tenantId}/memberships/{userId}/revoke`). The server returns the new token version and the revocation timestamp. This operation is O(1) because it updates a single record in Redis.

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

The CLI exposes a `saml` command group for managing the SAML 2.0 federation lifecycle. These commands generate SP metadata, register and inspect IdP trust records, refresh IdP metadata, manage email-domain discovery, create manual test AuthnRequests, and rotate SP signing keys. They are part of the standard admin toolset alongside tenant, membership, role, client, and token commands.

### SP metadata generation

`saml sp metadata` emits SP metadata XML from local SP settings and certificate material. Operators upload this XML to the IdP admin console during initial SAML setup.

```bash
tikti-cli saml sp metadata \
  --entity-id https://auth.example.com/saml \
  --acs-url https://auth.example.com/saml/acs \
  --slo-url https://auth.example.com/saml/slo \
  --signing-cert /etc/tikti/saml/sp.crt \
  --out sp-metadata.xml
```

The command also accepts `--encryption-cert` when the encryption certificate differs from the signing certificate, and `--valid-until YYYY-MM-DD` when the metadata validity window must be pinned.

### IdP registration

`saml idp register` registers an external IdP for a tenant. The command accepts IdP metadata as a URL or a local file path. It parses the IdP metadata XML to extract the entity ID, SSO URL, SLO URL, signing certificates, encryption certificates, and NameID format, then stores the configuration in Redis under `saml:idp:{tenantId}`.

```bash
tikti-cli saml idp register --tid tenant-1 --metadata-url https://idp.example.com/metadata
tikti-cli saml idp register --tid tenant-1 --metadata-file /path/to/idp-metadata.xml
```

The command can also apply a JSON attribute map:

```bash
tikti-cli saml idp register --tid tenant-1 \
  --metadata-url https://idp.example.com/metadata \
  --attr-map attr-map.json
```

The command requires either `--metadata-url` or `--metadata-file`. It validates metadata XML, rejects missing signing certificates, rejects expired signing certificates, rejects insecure SSO URLs, and rejects unsupported bindings before storing the trust record.

| Flag | Required | Description |
|------|----------|-------------|
| `--tid` | yes | Target tenant identifier. |
| `--metadata-url` | one of metadata-url or metadata-file | URL of the IdP metadata XML endpoint. |
| `--metadata-file` | one of metadata-url or metadata-file | Local file path to IdP metadata XML. |
| `--attr-map` | no | Path to a JSON attribute map using `email`, `name`, and `roles` keys. |
| `--redis-addr` | no | Redis address, defaulting to `REDIS_ADDR` or `localhost:6379`. |

### IdP inspection and refresh

`saml idp show` displays the stored IdP configuration for a tenant. `saml idp list` lists all registered IdPs. `saml idp fetch` forces a metadata refresh for one tenant. `saml idp update` refreshes an existing IdP record from a metadata URL or file and preserves the old signing certificate during the overlap window.

```bash
tikti-cli saml idp show --tid tenant-1 --output json
tikti-cli saml idp list
tikti-cli saml idp fetch --tid tenant-1
tikti-cli saml idp update --tid tenant-1 --metadata-url https://idp.example.com/metadata
```

Remove an IdP registration with explicit confirmation:

```bash
tikti-cli saml idp remove --tid tenant-1 --yes
```

### Domain discovery mappings

`saml domain add` maps an email domain to a tenant so `/saml/discover?email=user@example.com` can route the user to the correct IdP. `saml domain remove` deletes the mapping.

```bash
tikti-cli saml domain add --tid tenant-1 --domain example.com
tikti-cli saml domain remove --domain example.com
```

### Manual SAML test

`saml test` emits a signed AuthnRequest redirect URL for validating an IdP setup without building a full application login page.

```bash
tikti-cli saml test \
  --tid tenant-1 \
  --email user@example.com \
  --entity-id https://auth.example.com/saml \
  --acs-url https://auth.example.com/saml/acs \
  --signing-key /etc/tikti/saml/sp.key \
  --signing-cert /etc/tikti/saml/sp.crt
```

### SP key rotation

`saml sp rotate` rotates the SP signing keypair used to sign SAML AuthnRequests. The command is intentionally split into a prepare step and a commit step so IdPs have time to refresh cached SP metadata.

```bash
tikti-cli saml sp rotate --prepare \
  --entity-id https://auth.example.com/saml \
  --acs-url https://auth.example.com/saml/acs \
  --slo-url https://auth.example.com/saml/slo \
  --signing-key /etc/tikti/saml/sp.key \
  --signing-cert /etc/tikti/saml/sp.crt \
  --redis-addr localhost:6379 \
  --out sp-metadata.xml

tikti-cli saml sp rotate --commit \
  --entity-id https://auth.example.com/saml \
  --acs-url https://auth.example.com/saml/acs \
  --slo-url https://auth.example.com/saml/slo \
  --signing-key /etc/tikti/saml/sp.key \
  --signing-cert /etc/tikti/saml/sp.crt \
  --redis-addr localhost:6379 \
  --out sp-metadata.xml
```

The prepare step writes `.new` key and certificate files, publishes metadata containing both certificates, and stores rotation state in Redis at `saml:sp:rotation`. The commit step publishes metadata containing only the new certificate and deletes the rotation state.

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
tikti-cli saml sp metadata \
  --entity-id https://auth.example.com/saml \
  --acs-url https://auth.example.com/saml/acs \
  --slo-url https://auth.example.com/saml/slo \
  --signing-cert /etc/tikti/saml/sp.crt \
  --out sp-metadata.xml
tikti-cli saml idp register --tid tenant-1 \
  --metadata-url https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml
tikti-cli saml domain add --tid tenant-1 --domain codecompany.com.br
tikti-cli saml idp show --tid tenant-1
```

The operator exports the SP metadata XML and uploads it to the IdP admin console. Then the operator registers the IdP metadata URL with Tikti. The `saml idp show` command confirms that the IdP configuration is stored and the trust relationship is established.

## Command surface

The CLI includes these command groups: `init`, `auth`, `token`, `tenant`, `user`, `membership`, `role`, `client`, `apikey`, `jwks`, `saml`, `revoke`, and `config`. The `saml` group contains `sp metadata`, `sp rotate`, `idp register`, `idp update`, `idp remove`, `idp list`, `idp show`, `idp fetch`, `domain add`, `domain remove`, and `test` subcommands.
