# 11 Unit Test Execution Backlog

## Objective

This document converts the functional matrix (`10_unit_test_functional_matrix.md`) into an execution plan for unit testing. The plan orders work by business risk and security impact, assigns SAML 2.0 federation testing to the appropriate risk tiers, and defines quality gates for each block.

## Global Criteria

Functional testing (black-box) driven by the SPEC is the mandatory base for every test. Structural testing via CFG analysis complements functional testing to increase coverage confidence. Each function must reach a minimum of 85% executable-path coverage. Assertions without a functional business oracle are forbidden. One function equals one unit; interactions between functions belong to integration testing.

## Execution Order (Risk-Based)

### Phase 1 - Critical (Auth, Security, and SAML Assertion Validation)

Packages:

- `PF-22` (`M-SVC-USER-SignIn`, `M-SVC-USER-SignUp`, `M-SVC-USER-Lookup`)
- `PF-23` (`M-SVC-USER-SendOob`, `M-SVC-USER-SendOobForTenant`, `M-SVC-USER-SignInWithOobCode`, `M-SVC-USER-ResetPassword`)
- `PF-24` (`M-SVC-USER-TokenExchange`, `M-SVC-USER-ValidateAccessToken`, `M-SVC-USER-JWKS`, `M-SVC-USER-issueIDToken`, `M-SVC-USER-getRSAPrivateKey`)
- `PF-28` (`M-UTIL-JWKS-BuildJWKS`, `M-UTIL-JWKS-Marshal`, `M-UTIL-PARSERSA`, `M-UTIL-VALIDATERS256`, `M-UTIL-PARSETOKEN`)
- `PF-27` (`M-UTIL-APIKEY`)
- `PF-02` (`M-CTRL-ADMIN-GUARD`)
- `PF-31` (`M-SAML-VALIDATE-RESPONSE`) -- SAML 10-step assertion validation
- `PF-33` (`M-SAML-REPLAY-CHECK`) -- SAML replay protection
- `PF-37` (`M-SAML-VALIDATE-TIME`) -- SAML clock skew enforcement

SAML assertion validation (`PF-31`) is a security boundary. A defect in any of the 10 validation steps permits unauthorized access. This profile belongs in Phase 1 alongside password authentication and token validation. SAML replay protection (`PF-33`) prevents assertion reuse attacks and is tested here for the same reason. Clock skew validation (`PF-37`) enforces the 120 s tolerance window that gates assertion acceptance.

This phase enforces functional rules for authentication, token issuance/validation, OOB per SPEC, and SAML assertion acceptance/rejection. It covers security error scenarios: invalid signature, expired token, invalid issuer/audience, invalid role/status, tampered SAML response, replayed assertion ID, and clock skew beyond 120 s.

### Phase 2 - High (HTTP Contract, Administrative Operations, and SAML AuthnRequest)

Packages:

- `PF-06` (auth/OOB/JWKS/token exchange controllers)
- `PF-07` (update/delete/status/revoke/membership remove controllers)
- `PF-25` (admin user services)
- `PF-30` (`M-SAML-AUTHN-BUILD`, `M-SAML-AUTHN-GENID`) -- SAML AuthnRequest generation
- `PF-34` (`M-SAML-SESSION-STORE`, `M-SAML-SESSION-LOGOUT`) -- SAML session/SLO

This phase validates contract assertions: status code, payload shape, and functional messages. It tests administrative rules and denials (`403/401/400` as applicable). SAML AuthnRequest generation (`PF-30`) tests request ID format (20-byte hex), RSA-SHA256 signature, deflate encoding, and redirect URL construction including SAMLRequest, RelayState, SigAlg, and Signature query parameters. SAML session management (`PF-34`) tests `saml:idx:{NameID}` storage on ACS and session deletion during SP-initiated and IdP-initiated SLO.

### Phase 3 - Medium (Multi-Tenant Domain, Authorization, and SAML JIT Provisioning)

Packages:

- `PF-19` (membership service)
- `PF-20` (role service)
- `PF-21` (tenant service)
- `PF-26` (authorization helpers)
- `PF-32` (`M-SAML-JIT-PROVISION`) -- SAML JIT user provisioning

This phase covers tenant/role/scope rules with boundary cases for lists, sets, and tenant-context fallback. SAML JIT provisioning (`PF-32`) tests user creation on first SAML login, idempotent attribute updates on subsequent logins, membership assignment using the tenant ID from the URL path (not from the assertion, to prevent tenant escalation), and rejection when NameID is missing.

### Phase 4 - Medium/Low (Repositories and Providers)

Packages:

- `PF-10`, `PF-11`, `PF-12`, `PF-13`, `PF-14`, `PF-15`, `PF-16`, `PF-17`
- `PF-08`, `PF-09`

This phase validates CRUD and persistence semantics: not found, duplication, idempotency, and error propagation. It validates OOB behavior with requestType enforcement and single-use semantics.

### Phase 5 - Low (Constructors, Helpers, and SAML Metadata)

Packages:

- `PF-01`, `PF-03`, `PF-04`, `PF-05`, `PF-18`, `PF-29`
- `PF-35` (`M-SAML-META-SP`) -- SP metadata generation
- `PF-36` (`M-SAML-META-IDP`) -- IdP metadata parsing

This phase validates wiring, write/read handler contracts, and configuration loading with defaults/errors. SP metadata generation (`PF-35`) tests that the EntityDescriptor XML contains the entityID, ACS URL with HTTP-POST binding, SLO URL, and the SP signing certificate in the X509Certificate element. IdP metadata parsing (`PF-36`) tests entityID extraction, SSO URL extraction, signing certificate extraction, default attribute mapping, and rejection of invalid XML.

## Per-Function Technical Sprint

For each function in the matrix, follow these steps. First, identify the `PF/CF` package. Second, derive input equivalence classes and boundaries. Third, enumerate independent CFG paths. Fourth, define functional cases that cover those paths. Fifth, implement minimal doubles/mocks/fakes to isolate the function. Sixth, write functional-oracle assertions using SPEC-expected results. Seventh, measure path coverage and refine cases until the function reaches 85%.

## PR Quality Gates

- [ ] No tautological test assertions (`assert.True(true)` or equivalent).
- [ ] Every test references a functional requirement from the corresponding `CF` package.
- [ ] Failure cases validate functional errors (code/message/state), not generic errors.
- [ ] Per-function coverage is reported and reaches 85% executable paths.
- [ ] Boundary cases are documented in case/table naming.
- [ ] SAML assertion validation (`PF-31`) has 100% branch coverage for all 10 steps of the validation pipeline.
- [ ] SAML clock skew tests (`PF-37`) cover all four boundary values: -121 s, -120 s, +120 s, +121 s.

## Operational Backlog

### Block A - Security/Auth Core

- [ ] Implement/adjust all tests for `PF-22`, `PF-23`, `PF-24`.
- [ ] Close gaps in `PF-27`, `PF-28`, `PF-02`.
- [ ] Review oracles against SPEC requirements for tokens/OOB.

### Block A-SAML - SAML Security Core

- [ ] Implement all tests for `PF-31` (10-step assertion validation) with 100% branch coverage.
- [ ] Implement all tests for `PF-33` (replay protection via `saml:seen:{assertionID}` with 3600 s TTL).
- [ ] Implement all tests for `PF-37` (clock skew at -121 s, -120 s, +120 s, +121 s boundaries).
- [ ] Review oracles against the 10-step validation sequence in `docs/12_saml_federation_hld.md` section 9.2.

### Block B - HTTP Contract

- [ ] Cover `PF-06` and `PF-07` with valid and invalid request/response matrices.
- [ ] Guarantee 1:1 correspondence with `docs/04_api_spec.md`.

### Block B-SAML - SAML Request and Session

- [ ] Implement all tests for `PF-30` (AuthnRequest generation: ID format, signature, deflate, redirect URL).
- [ ] Implement all tests for `PF-34` (session index storage in `saml:idx:{NameID}`, SLO processing).

### Block C - Multi-Tenant Domain

- [ ] Cover `PF-19`, `PF-20`, `PF-21`, `PF-26` with role/scope/tenant boundaries.

### Block C-SAML - SAML JIT Provisioning

- [ ] Implement all tests for `PF-32` (user creation, idempotent update, tenant assignment from URL path, missing NameID rejection).

### Block D - Persistence/Provider

- [ ] Cover `PF-10` through `PF-17` with store-error and legacy-compatibility scenarios.
- [ ] Guarantee idempotency and requestType binding for OOB.

### Block E - Remaining Unit Surface

- [ ] Cover `PF-01`, `PF-03`, `PF-04`, `PF-05`, `PF-18`, `PF-29`.
- [ ] Consolidate the final per-function coverage report.

### Block E-SAML - SAML Metadata

- [ ] Implement all tests for `PF-35` (SP metadata: entityID, ACS URL, SLO URL, certificate).
- [ ] Implement all tests for `PF-36` (IdP metadata parsing: entityID, ssoURL, signingCerts, attributeMap, invalid XML).

## Definition of Done

The unit phase is complete when every function in the matrix (133 existing plus the SAML surface) has implemented functional cases, no function in scope is below 85% executable-path coverage, SAML assertion validation (`PF-31`) has 100% branch coverage across all 10 validation steps, the final report lists bugs found by `PF` package, and all tests are traceable to SPEC functional rules.
