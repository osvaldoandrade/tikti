# Release and Compatibility

This page consolidates compatibility contracts, rollout sequence, and release validation for Tikti.

## Compatibility Contract

API contracts remain backward compatible unless a new version is introduced through explicit versioning. Token claim semantics — `iss`, `aud`, `scope`, `tid`, `ver` — are stable contracts that integrators depend on and must not change meaning between releases. Multi-tenant authorization behavior is deterministic and must not drift between releases without a versioned migration path. SAML 2.0 SP metadata published at the metadata endpoint conforms to the OASIS EntityDescriptor schema; changes to metadata structure require a compatibility review.

## Rollout Strategy

Each release follows a fixed deployment sequence. First, validate API compatibility and token contract stability in pre-production. Second, deploy JWKS and RS256 token validation paths with monitoring enabled. Third, enable multi-tenant authorization checks and audit trail enforcement. Fourth, validate SAML 2.0 federation by running assertion validation against each supported IdP. Fifth, roll out token exchange and codeQ integration flows. Sixth, verify SLO compliance, error budget impact, and rollback readiness before full rollout.

## Release Checklist

Before each release, the following validations must pass.

API regressions are validated against the [API Specification](API-Specification). Token validation matrix is checked against [Tokens and Keys](Tokens-and-Keys). Unit quality gates are satisfied per the [Unit Test Execution Backlog](Unit-Test-Execution-Backlog). Operational readiness is validated via [Operations and SLO](Operations-and-SLO).

SAML assertion validation is tested against each supported IdP: Azure AD, Okta, Ping, and Google Workspace. The SP metadata endpoint is verified to return a valid EntityDescriptor document. SP key rotation is tested with overlapping validity windows to confirm that assertions encrypted with the outgoing key remain decryptable during the transition. SAML audit events — including AuthnRequest issuance, assertion acceptance, assertion rejection, and replay rejection — are verified in structured log output.
