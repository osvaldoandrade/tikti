# Overview

TIKTI is a multi-tenant identity service that provides authentication and authorization contracts across services.

It keeps a Firebase-compatible API surface for sign-in and lookup, but extends it with issuer/audience binding, multi-tenant membership, and RS256 access tokens for downstream resource servers.

## What Tikti Does

Tikti authenticates users through email/password and OOB email flows, then issues HS256 idTokens. It also delegates authentication to external SAML 2.0 identity providers (Azure AD, Okta, Ping Identity, Google Workspace) and produces the same HS256 idToken regardless of which authentication method the user chose.

Tikti resolves idTokens via `lookup` for legacy clients and for service-side introspection. Clients that need downstream authorization exchange an idToken into an RS256 access token scoped to a resource server (`aud`) with explicit scopes (`scope`) and tenant context (`tid`).

Tikti publishes JWKS endpoints so resource servers can verify RS256 tokens without contacting Tikti at runtime.

## The Token Contract

Tikti issues three token classes:

- idToken (HS256): identity for sign-in and lookup, and as input to token exchange.
- access token (RS256): authorization for a specific resource server audience.
- worker token (RS256): a specialized access token for codeQ workers that includes `eventTypes`.

For claim requirements, lifetimes, and validation rules, see [Tokens and Keys](Tokens-and-Keys).

## Multi-Tenant Model

A tenant is the authorization boundary. A user is global. Membership binds a user to a tenant and carries roles that expand into scopes.

Tenant-scoped operations require an explicit tenant context and a membership check. This prevents cross-tenant access.

See [Multi-Tenant Authorization](Multi-Tenant-Authorization) and [Architecture](Architecture-and-Data-Model).

## Compatibility

Compatibility with existing clients is a constraint:

- `/signInWithPassword` and `/lookup` keep the same request/response shape.
- New response fields are additive and must not change the meaning of existing fields.
- Existing HS256 idTokens remain valid until expiration.

## Reading Path

The reading path for end-to-end evaluation is:

1. [Get Started](Get-Started)
2. [API Specification](API-Specification)
3. [Tokens and Keys](Tokens-and-Keys)
4. [Architecture](Architecture-and-Data-Model)
5. [SAML Federation](SAML-Federation)
6. [Use Cases](Use-Cases)
