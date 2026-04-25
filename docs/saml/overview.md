# SAML 2.0 Federation — Overview

Tikti supports SAML 2.0 Web Browser SSO Profile in the **Service Provider
(SP)** role. This lets your organization delegate authentication to an
external Identity Provider (IdP) — such as Azure AD / Entra ID, Okta, Google
Workspace, Ping, ADFS, OneLogin, JumpCloud, or Keycloak — so users sign in
with their existing corporate credentials.

## Who is this for?

SAML federation is designed for **enterprise customers** whose identity teams
already operate a SAML IdP. Typical reasons to enable it:

- Your security policy requires single sign-on through a corporate IdP.
- You want centralized user lifecycle management (hire → provision, leave →
  deprovision) without duplicating accounts in Tikti.
- Your procurement checklist requires SAML 2.0 support.

If you only need local email-and-password authentication, no SAML
configuration is required — the existing password flow continues to work
unchanged.

## Supported flows

Tikti implements three SAML flows:

### 1. SP-Initiated Single Sign-On (SSO)

The most common flow. A user visits Tikti, is redirected to the corporate
IdP, authenticates there, and is returned to Tikti with a signed SAML
assertion. Tikti validates the assertion, provisions or updates the user
record (JIT provisioning), and issues the same HS256 identity token that the
password path produces — so every downstream service (token exchange, JWKS
verification) keeps working with zero changes.

```
Browser ──▶ GET /saml/login/{tid}
         ◀── 302 redirect to IdP with signed AuthnRequest
Browser ──▶ IdP authenticates user
         ◀── POST /saml/acs with signed SAMLResponse
Tikti   ──▶ validates assertion, issues idToken
         ◀── 302 redirect to application
```

### 2. SP-Initiated Single Logout (SLO)

When a user logs out of Tikti, a signed `LogoutRequest` is sent to the IdP.
The IdP terminates its own session and responds. Tikti then removes the local
session.

```
Browser ──▶ GET /saml/logout/{tid}
         ◀── 302 redirect to IdP with signed LogoutRequest
IdP     ──▶ terminates session
         ◀── redirect to /saml/slo with LogoutResponse
Tikti   ──▶ removes local session
         ◀── 302 redirect to post-logout URL
```

### 3. IdP-Initiated Single Logout

The IdP can also start logout (for example, when an admin revokes a user's
access). The IdP sends a `LogoutRequest` to Tikti's SLO endpoint. Tikti
removes the local session and returns a signed `LogoutResponse`.

```
IdP     ──▶ POST /saml/slo with signed LogoutRequest
Tikti   ──▶ removes local session
         ◀── LogoutResponse to IdP
```

## Endpoints at a glance

| Path | Method | Purpose |
|---|---|---|
| `/saml/metadata` | GET | SP metadata XML — import this into your IdP |
| `/saml/login/{tid}` | GET | Start SP-initiated SSO for a tenant |
| `/saml/acs` | POST | Assertion Consumer Service (receives IdP responses) |
| `/saml/logout/{tid}` | GET | Start SP-initiated logout |
| `/saml/slo` | GET / POST | Single Logout endpoint (receives IdP logout messages) |
| `/saml/discover` | GET | Email-domain lookup for tenant routing |

## Admin CLI

All IdP trust configuration is managed at runtime through the `tikti saml`
CLI — no YAML edits or process restarts required. Common commands:

```text
tikti saml idp register  --tid TID --metadata-url URL   # onboard a new IdP
tikti saml idp list                                      # show all IdP bindings
tikti saml idp show      --tid TID                       # inspect one IdP
tikti saml idp remove    --tid TID                       # remove an IdP binding
tikti saml sp  metadata  [--out FILE]                    # export SP metadata
tikti saml sp  rotate    {--prepare | --commit}          # rotate the SP signing key
```

Run `tikti saml --help` for the full command reference. Key-rotation
procedures are documented in [`key-rotation.md`](key-rotation.md).

## Further reading

| Topic | Document |
|---|---|
| High-Level Design | [`docs/12_saml_federation_hld.md`](../12_saml_federation_hld.md) |
| SP Key Rotation | [`docs/saml/key-rotation.md`](key-rotation.md) |
| Kubernetes Secrets | [`docs/saml/k8s-external-secrets.md`](k8s-external-secrets.md) |
| Audit Event Schema | [`docs/saml/audit-schema.json`](audit-schema.json) |
| CLI Specification | [`docs/09_cli_spec.md`](../09_cli_spec.md) |
