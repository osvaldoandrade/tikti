# Overview

TIKTI is a multi-tenant identity service that provides deterministic authentication and authorization contracts across services.

It keeps a Firebase-compatible API surface for sign-in and lookup, but extends it with explicit issuer/audience, multi-tenant membership, and RS256 access tokens for downstream resource servers.

## What Tikti Does

- Authenticates users (email/password and OOB flows) and issues HS256 idTokens.
- Resolves idTokens via `lookup` for legacy clients and service-side introspection.
- Exchanges idTokens into RS256 access tokens scoped to a resource server (`aud`) with explicit scopes (`scope`) and tenant context (`tid`).
- Publishes JWKS for RS256 verification by resource servers.

## The Token Contract

Tikti issues three token classes:

- idToken (HS256): identity for sign-in and lookup, and as input to token exchange.
- access token (RS256): authorization for a specific resource server audience.
- worker token (RS256): a specialized access token for codeQ workers that includes `eventTypes`.

For claim requirements, lifetimes, and validation rules, see [Tokens and Keys](Tokens-and-Keys).

## Multi-Tenant Model

A tenant is the authorization boundary. A user is global. Membership binds a user to a tenant and carries roles that expand into scopes.

Tenant-scoped operations must always have an explicit tenant context and a membership check. This is what prevents cross-tenant access by accident.

See [Multi-Tenant Authorization](Multi-Tenant-Authorization) and [Architecture](Architecture-and-Data-Model).

## Compatibility

Compatibility with existing clients is a hard constraint:

- `/signInWithPassword` and `/lookup` keep the same request/response shape.
- New response fields are additive and must not change the meaning of existing fields.
- Existing HS256 idTokens remain valid until expiration.

## Reading Path

If you are evaluating Tikti end-to-end, the fastest reading path is:

1. [Get Started](Get-Started)
2. [API Specification](API-Specification)
3. [Tokens and Keys](Tokens-and-Keys)
4. [Architecture](Architecture-and-Data-Model)
5. [Use Cases](Use-Cases)
