> Canonical source: [`docs/11_unit_test_execution_backlog.md`](https://github.com/osvaldoandrade/tikti/blob/main/docs/11_unit_test_execution_backlog.md)
> Synced on: 2026-02-12

# Unit Test Execution Backlog

## Objective

Convert the functional matrix (`10_unit_test_functional_matrix.md`) into an executable unit-testing plan, focused on business risk, security, and structural coverage.

## Global Criteria

- Mandatory base: functional testing (black-box) driven by SPEC.
- Complementary technique: structural testing (CFG) to increase quality.
- Minimum target per function: >=85% executable-path coverage.
- Forbidden: assertions without a functional business oracle.
- Unit granularity rule: one function equals one unit; interactions between functions belong to integration testing.

## Execution Order (Risk-Based)

### Phase 1 - Critical (Auth and Security)

Packages:

- `PF-22` (`M-SVC-USER-SignIn`, `M-SVC-USER-SignUp`, `M-SVC-USER-Lookup`)
- `PF-23` (`M-SVC-USER-SendOob`, `M-SVC-USER-SendOobForTenant`, `M-SVC-USER-SignInWithOobCode`, `M-SVC-USER-ResetPassword`)
- `PF-24` (`M-SVC-USER-TokenExchange`, `M-SVC-USER-ValidateAccessToken`, `M-SVC-USER-JWKS`, `M-SVC-USER-issueIDToken`, `M-SVC-USER-getRSAPrivateKey`)
- `PF-28` (`M-UTIL-JWKS-BuildJWKS`, `M-UTIL-JWKS-Marshal`, `M-UTIL-PARSERSA`, `M-UTIL-VALIDATERS256`, `M-UTIL-PARSETOKEN`)
- `PF-27` (`M-UTIL-APIKEY`)
- `PF-02` (`M-CTRL-ADMIN-GUARD`)

Expected delivery:

- Enforce functional rules for authentication, token issuance/validation, and OOB per SPEC.
- Cover security error scenarios: invalid signature, expired token, invalid issuer/audience, invalid role/status.

### Phase 2 - High (HTTP Contract and Administrative Operations)

Packages:

- `PF-06` (auth/OOB/JWKS/token exchange controllers)
- `PF-07` (update/delete/status/revoke/membership remove controllers)
- `PF-25` (admin user services)

Expected delivery:

- Contract assertions: status code, payload, shape, and functional messages.
- Validation of administrative rules and denials (`403/401/400` as applicable).

### Phase 3 - Medium (Multi-Tenant Domain and Authorization)

Packages:

- `PF-19` (membership service)
- `PF-20` (role service)
- `PF-21` (tenant service)
- `PF-26` (authorization helpers)

Expected delivery:

- Functional coverage of tenant/role/scope rules.
- Boundary cases for lists, sets, and tenant-context fallback.

### Phase 4 - Medium/Low (Repositories and Providers)

Packages:

- `PF-10`, `PF-11`, `PF-12`, `PF-13`, `PF-14`, `PF-15`, `PF-16`, `PF-17`
- `PF-08`, `PF-09`

Expected delivery:

- Validate functional CRUD and persistence semantics (not found, duplication, idempotency, error propagation).
- Validate repository OOB behavior with requestType enforcement and single-use.

### Phase 5 - Low (Constructors and Remaining Helpers)

Packages:

- `PF-01`, `PF-03`, `PF-04`, `PF-05`, `PF-18`, `PF-29`

Expected delivery:

- Validate wiring, write/read handler contracts, and configuration loading with defaults/errors.

## Per-Function Technical Sprint (Mandatory Template)

For each function in the matrix:

1. Identify the `PF/CF` package.
2. Derive input equivalence classes and boundaries.
3. Enumerate independent CFG paths.
4. Define functional cases that cover those paths.
5. Implement minimal doubles/mocks/fakes to isolate the function.
6. Write functional-oracle assertions (SPEC-expected results).
7. Measure path coverage and refine cases until >=85%.

## PR Quality Gates

- [ ] No tautological test assertions (`assert.True(true)` etc.).
- [ ] Every test references a functional requirement from the corresponding `CF` package.
- [ ] Failure cases validate functional errors (code/message/state), not generic errors only.
- [ ] Per-function coverage is reported and >=85% executable paths.
- [ ] Boundary cases are explicitly documented in case/table naming.

## Operational Backlog (Checklist)

### Block A - Security/Auth Core

- [ ] Implement/adjust all tests for `PF-22`, `PF-23`, `PF-24`.
- [ ] Close gaps in `PF-27`, `PF-28`, `PF-02`.
- [ ] Review oracles against SPEC requirements for tokens/OOB.

### Block B - HTTP Contract

- [ ] Cover `PF-06` and `PF-07` with valid and invalid request/response matrices.
- [ ] Guarantee 1:1 correspondence with `docs/04_api_spec.md`.

### Block C - Multi-Tenant Domain

- [ ] Cover `PF-19`, `PF-20`, `PF-21`, `PF-26` with role/scope/tenant boundaries.

### Block D - Persistence/Provider

- [ ] Cover `PF-10` through `PF-17` with store-error and legacy-compatibility scenarios.
- [ ] Guarantee idempotency and requestType binding for OOB.

### Block E - Remaining Unit Surface

- [ ] Cover `PF-01`, `PF-03`, `PF-04`, `PF-05`, `PF-18`, `PF-29`.
- [ ] Consolidate the final per-function coverage report.

## Unit Phase Definition of Done

The unit phase is complete when:

- every function in the matrix (133) has implemented functional cases;
- no function in scope is below 85% executable-path coverage;
- the final report explicitly lists bugs found by `PF` package;
- all tests are traceable to SPEC functional rules.
