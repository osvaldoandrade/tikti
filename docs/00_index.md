# 00 Index

This directory contains the Tikti identity specification. Each document is a normative technical description that can be implemented without external references. The documents are ordered intentionally; later sections depend on definitions and constraints established earlier. When in doubt, the token semantics in `03_tokens_and_keys.md` and the authorization algorithm in `05_multi_tenant_authorization.md` take precedence.

The specification is structured as a sequence of chapters rather than independent notes. The overview establishes the scope and compatibility contract. The architecture section formalizes the data model and storage layout. The tokens section defines all cryptographic claims and verification rules. The API specification defines request and response semantics. The multi-tenant authorization section formalizes the access control algorithm. The codeQ integration section is the binding contract for worker and producer flows. The operations section defines production constraints, and the migration plan describes the transition from the current system to the target state. The CLI specification documents the `tikti-cli` admin client that exercises these endpoints. The unit test matrix and execution backlog define coverage targets and prioritized test work. The SAML 2.0 federation chapter specifies how Tikti delegates authentication to external Identity Providers while preserving the existing token-exchange and authorization contracts; it is a peer to the password and OOB authentication paths, not an extension bolted on after the fact.

Document order:

1. `01_overview.md` — scope, goals, invariants, and compatibility.
2. `02_architecture_and_data_model.md` — data model, storage layout, algorithms, and complexity.
3. `03_tokens_and_keys.md` — token taxonomy, claims, signing, JWKS, rotation, and validation.
4. `04_api_spec.md` — endpoint contracts, payloads, validation rules, and error semantics.
5. `05_multi_tenant_authorization.md` — authorization algorithm and tenant enforcement.
6. `06_codeq_integration.md` — required flows and claims for codeQ.
7. `07_operations_and_slo.md` — configuration, health, rate limiting, logging, audit, metrics, SLOs.
8. `08_migration_and_implementation_plan.md` — staged execution plan with acceptance criteria.
9. `09_cli_spec.md` — command‑line interface specification for administration and token workflows.
10. `10_unit_test_functional_matrix.md` — exhaustive functional unit test matrix (all functions except bootstrap/main), with black-box case packs and CFG-driven structural coverage targets.
11. `11_unit_test_execution_backlog.md` — execution backlog for unit testing, prioritized by risk with quality gates and completion criteria.
12. `12_saml_federation_hld.md` — SAML 2.0 federation high-level design for Tikti as Service Provider, including flows, threat model, rollout, FAQ, and appendices.
13. `13_workload_identity.md` — Kubernetes workload exchange, explicit bindings, the bounded workload-account broker, revocation, and rollout.
14. `14_edge_forward_auth.md` — Traefik ForwardAuth contract for bearer access tokens and SAML browser sessions.
