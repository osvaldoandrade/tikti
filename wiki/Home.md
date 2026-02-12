# Tikti Wiki

Tikti is a multi-tenant identity service in Go with Redis persistence, HS256 idTokens for user identity, and RS256 access tokens for resource-server authorization.

This wiki is organized in the same docs-first style used by large engineering documentation portals: start with onboarding, then move into concepts, API contracts, operations, and testing.

## Quick Start Path

1. [Get Started](Get-Started)
2. [Overview](Overview)
3. [Architecture and Data Model](Architecture-and-Data-Model)
4. [Tokens and Keys](Tokens-and-Keys)
5. [API Specification](API-Specification)

## Documentation Map

### Foundations

- [Get Started](Get-Started)
- [Overview](Overview)
- [Architecture and Data Model](Architecture-and-Data-Model)
- [Security Model](Security-Model)

### Core Contracts

- [Tokens and Keys](Tokens-and-Keys)
- [API Specification](API-Specification)
- [Multi-Tenant Authorization](Multi-Tenant-Authorization)
- [codeQ Integration](codeQ-Integration)

### Use Cases

- [Use Cases](Use-Cases)
- [Use Case: OOB Email Sign-In](Use-Cases-OOB-Email-Sign-In)
- [Use Case: Password Sign-In](Use-Cases-Password-Sign-In)
- [Use Case: codeQ Worker Token Exchange](Use-Cases-codeQ-Worker-Token-Exchange)
- [Use Case: Tenant Admin Lifecycle](Use-Cases-Tenant-Admin-Lifecycle)
- [Use Case: Resource Server Token Validation](Use-Cases-Resource-Server-Token-Validation)

### Operations

- [Operations and SLO](Operations-and-SLO)
- [Troubleshooting](Troubleshooting)
- [Release and Compatibility](Release-and-Compatibility)

### Tooling and Validation

- [CLI Reference](CLI-Reference)
- [Unit Test Functional Matrix](Unit-Test-Functional-Matrix)
- [Unit Test Execution Backlog](Unit-Test-Execution-Backlog)

## Source of Truth

The canonical technical specs live in [`docs/`](https://github.com/osvaldoandrade/tikti/tree/main/docs) in the main repository. This wiki mirrors those specs and adds navigation for operational use.
