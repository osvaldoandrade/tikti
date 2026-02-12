# Use Cases

This section defines concrete end-to-end scenarios for Tikti. Each use case maps business intent to API calls, token semantics, and expected outcomes.

## Why this section exists

- It makes product behavior explicit for engineering, QA, and integration teams.
- It reduces ambiguity between API contract and runtime behavior.
- It provides scenario-driven acceptance criteria, not only endpoint-level docs.

## Core use cases

1. [OOB Email Sign-In](Use-Cases-OOB-Email-Sign-In)
2. [Password Sign-In](Use-Cases-Password-Sign-In)
3. [codeQ Worker Token Exchange](Use-Cases-codeQ-Worker-Token-Exchange)
4. [Tenant Admin Lifecycle](Use-Cases-Tenant-Admin-Lifecycle)
5. [Resource Server Token Validation](Use-Cases-Resource-Server-Token-Validation)

## Traceability map

- Identity and authentication contracts: [API Specification](API-Specification)
- Token claims and validation: [Tokens and Keys](Tokens-and-Keys)
- Tenant-aware authorization: [Multi-Tenant Authorization](Multi-Tenant-Authorization)
- codeQ behavior and claims: [codeQ Integration](codeQ-Integration)
