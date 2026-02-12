# CLI Reference

This document specifies the Tikti command‑line interface. The CLI is a thin client that exercises the HTTP API and provides deterministic automation for operators, CI, and local development. The CLI must be feature‑complete for tenant administration, token exchange, and validation workflows required by codeQ and other resource servers. The design favors explicit configuration, reproducible outputs, and secure token handling.

## Purpose and scope

The CLI provides three categories of functionality. First, it authenticates a user and manages the local session context, including base URLs, API keys, and tokens. Second, it exposes administrative operations such as tenant creation, user membership management, role and client configuration, and API key rotation. Third, it supports token exchange and local inspection of tokens and JWKS for integration debugging.

The CLI must not depend on environment variables for normal use. It must support interactive initialization and explicit command flags. It must persist configuration locally in a predictable file and never print secrets unless explicitly requested. All network requests must be idempotent where possible and must return machine‑parseable output for automation.

## Configuration model

The CLI stores configuration in a YAML file at `~/.tikti/config.yaml`. The file contains named profiles. Each profile includes the Tikti base URL, IAM API key, optional default tenant, and the most recently issued tokens. The CLI always operates in a single active profile. The active profile can be changed per command via `--profile`.

A minimal configuration structure is:

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

The CLI must support both interactive initialization and non‑interactive initialization. Interactive initialization prompts for the base URL and API key, and optionally a default tenant. Non‑interactive initialization uses explicit flags and never prompts. If a profile already exists, the CLI must update only the provided fields and preserve existing tokens unless explicitly overwritten.

The configuration lookup algorithm is deterministic and O(1) with respect to the number of profiles because it is a keyed lookup on the profile name. When a profile is missing, the CLI must return a clear error rather than silently creating a new profile.

## Authentication commands

The CLI exposes an `auth` command that authenticates a user and stores the resulting idToken in the active profile. Authentication uses the `signInWithPassword` endpoint and is API‑key protected.

The canonical flow is:

```bash
tikti-cli init
tikti-cli auth login --email admin@codecompany.com.br
```

The `auth login` command must prompt for the password if it is not provided by flag. The password must never be logged or stored. The resulting idToken must be stored in the profile and used by subsequent commands that require user identity.

The CLI must also provide `auth logout`, which clears stored tokens for the active profile. This command must be idempotent and should return success even if no tokens are present.

## Token exchange commands

The CLI provides a `token exchange` command that calls the `token/exchange` endpoint and stores the resulting access or worker token. The command accepts the audience, scopes, tenant id, subject, and event types. The idToken from the active profile is used unless explicitly overridden.

Example:

```bash
tikti-cli token exchange \
  --audience codeq-worker \
  --scopes codeq:claim,codeq:result,codeq:subscribe \
  --event-types render_video,generate_master \
  --tenant tenant-1 \
  --subject worker-1
```

The CLI must translate comma‑separated scopes and event types into arrays in the request body. The CLI must store the returned access token in the profile under `workerToken` if the audience is `codeq-worker`, and under `accessToken` otherwise. This rule avoids ambiguity and makes subsequent worker operations deterministic.

The token exchange command is O(1) in local computation. The dominant cost is network round‑trip and server‑side authorization, which is outside the CLI’s complexity model.

## Tenant administration commands

The CLI must expose a `tenant` command group. These commands are administrative and require an idToken with admin role. The CLI does not enforce roles locally; it relies on server responses.

Examples:

```bash
# Create a tenant
tikti-cli tenant create --name "Code Company" --slug codecompany

# Get tenant details
tikti-cli tenant get --tenant tenant-1
```

The CLI must include the active profile’s idToken in the Authorization header when calling admin endpoints. It must reject execution if no idToken is present and instruct the user to log in.

## User administration commands

The CLI must expose a `user` command group for administrative user lifecycle operations. These commands require an admin token and operate either globally (user creation) or within a tenant (membership and status). The CLI should not hide complexity; it must make the scope explicit via flags so the operator does not accidentally apply a change across tenants.

The minimal user command set is:

1. `user create` — creates a user with email, password, and optional global role. This maps to `POST /v1/accounts/signUp` and uses the admin token in the Authorization header. The CLI must never print the password after submission. Example:

```bash
tikti-cli user create --email user@company.com --password 'Secret123' --role COMPANY_EMPLOYEE
```

2. `user get` — fetches identity metadata for the current idToken. This maps to `lookup`. Example:

```bash
tikti-cli user get
```

3. `user suspend` — sets user status to SUSPENDED, which invalidates new token exchanges and prevents sign‑in. This requires `POST /v1/accounts/status`. Example:

```bash
tikti-cli user suspend --email user@company.com
```

4. `user activate` — sets user status to ACTIVE. Example:

```bash
tikti-cli user activate --email user@company.com
```

5. `user delete` — deletes the current user (idToken owner). This maps to `POST /v1/accounts/delete`. Example:

```bash
tikti-cli user delete --confirm
```

The CLI must require `--confirm` for destructive actions. The output must include the user id and affected tenants when possible.

## Membership and role commands

The CLI must expose `membership` and `role` command groups for managing tenant memberships and roles. These commands send and receive JSON as defined in `04_api_spec.md` and must support explicit tenant targeting.

Examples:

```bash
# Add a user to a tenant
tikti-cli membership add --tenant tenant-1 --email user@company.com --roles TENANT_USER

# Remove a user from a tenant
tikti-cli membership remove --tenant tenant-1 --email user@company.com

# Create a role with permissions
tikti-cli role create --tenant tenant-1 --name CODEQ_ADMIN \
   --permissions codeq:admin,codeq:claim,codeq:result
```

The CLI must validate that role names and permissions are non‑empty strings but must not enforce policy semantics client‑side. The server remains authoritative.

## Access revocation commands

The CLI must expose a `revoke` command group for revoking access. Revocation is the operational mechanism to invalidate tokens before expiration. The system supports two complementary revocation strategies: status‑based revocation and token‑version revocation. The CLI must support both methods when the server supports them.

### 1) Status‑based revocation

Suspending a user or removing a membership prevents future token exchange. This is implemented via `user suspend` and `membership remove`. This does not invalidate already issued tokens immediately, but it prevents renewal. This is sufficient for most operations with short token lifetimes (900–3600 seconds).

### 2) Token‑version revocation

To invalidate tokens immediately, Tikti must support a token version or blacklist mechanism. The recommended approach is a `tokenVersion` field stored on the user and optionally on the membership. Tokens include `ver` and are rejected if `ver` does not match the current version.

The CLI command `revoke tokens` increments the token version for a user or tenant membership:

```bash
tikti-cli revoke tokens --email user@company.com
tikti-cli revoke tokens --tenant tenant-1 --email user@company.com
```

This requires a dedicated endpoint (for example, `POST /v1/accounts/revoke` or `POST /v1/tenants/{tenantId}/memberships/{userId}/revoke`). The server must return the new token version and the effective revocation time. This operation is O(1) because it updates a single record in Redis.

### 3) JTI blacklist (optional)

If token versions are not feasible, Tikti can maintain a blacklist keyed by token `jti` with TTL set to token expiration. The CLI may expose `revoke jti --token <jwt>` which extracts `jti` and calls a blacklist endpoint. This approach is O(1) per revoke and O(1) per validation but increases Redis memory proportional to the number of revoked tokens.

The CLI must clearly state which revocation strategy is active by inspecting server capabilities or configuration.

## Client and API key commands

The CLI must manage clients and API keys because these objects are required for token exchange and protected endpoints. The CLI must never print client secrets unless `--show-secret` is provided explicitly, and it must redact secrets in logs.

Example:

```bash
# Create a client
tikti-cli client create --tenant tenant-1 --client-id codeq-worker --type SERVICE \
   --grant token_exchange --scopes codeq:claim,codeq:result
```

When a client secret is generated, the CLI must print it exactly once and store it only if the user passes `--store-secret`. By default the secret is not persisted in the local config.

## JWKS inspection

The CLI must include a `jwks` command that fetches and prints the current JWKS. This is essential for integration debugging.

Example:

```bash
tikti-cli jwks
```

The CLI must support `--output json` and `--output pretty` formatting. The JWKS fetch is a simple GET request and should cache the response for the duration of the process.

## Output format and exit codes

All commands must support `--output json` to enable automation. In JSON mode, the CLI must emit a single JSON object or array to stdout with no additional formatting. In human mode, the CLI should emit concise text lines. Errors must be written to stderr and must include the HTTP status code and response body when available.

Exit codes:

- 0 on success
- 1 on validation or request errors
- 2 on authentication errors
- 3 on configuration errors

## Security requirements

The CLI must never log passwords, access tokens, or API keys. It must store tokens in the local config file with file permissions restricted to the current user. On Unix systems, the CLI must set `0600` permissions when writing the config file. The CLI must not use environment variables by default, but it may read them for non‑interactive automation when explicitly enabled by a `--use-env` flag.

## Example: end‑to‑end worker setup

The following example shows a complete flow: initialize config, login, exchange a worker token, and print it.

```bash
# 1) Initialize profile
tikti-cli init --base-url https://api.storifly.ai --api-key $API_KEY --tenant tenant-1

# 2) Login and store idToken
tikti-cli auth login --email admin@codecompany.com.br

# 3) Exchange worker token
tikti-cli token exchange \
   --audience codeq-worker \
   --scopes codeq:claim,codeq:heartbeat,codeq:result \
   --event-types render_video \
   --tenant tenant-1 \
   --subject worker-1

# 4) Print token
tikti-cli token show --type worker
```

This flow is deterministic and does not require environment variables. All state is stored in the profile.

## Minimal command surface

The CLI must include these command groups at minimum: `init`, `auth`, `token`, `tenant`, `membership`, `role`, `client`, `apikey`, `jwks`, and `config`. Additional commands are allowed but must not change the semantics of the core set.
