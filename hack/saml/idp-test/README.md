# SAML Test IdP

This directory supports the SAML end-to-end integration tests defined in
`test/integration/saml_e2e_test.go`.

## Overview

The E2E tests spin up an **in-process** mock IdP (no Docker required) that
uses ephemeral RSA keys to sign SAML Responses and LogoutResponses.  The
SP Handler under test is wired to `net/http/httptest` servers so the full
SSO and SLO flows can be driven by a plain `net/http` client.

### What is tested

| Flow | Steps |
|------|-------|
| SSO  | `GET /saml/login/{tid}` → IdP redirect → mock SAML Response → `POST /saml/acs` → idToken cookie set |
| SLO  | `GET /saml/logout/{tid}` → IdP redirect → mock LogoutResponse → `GET /saml/slo` → session cleared |

### Running locally

```bash
go test -v -run TestSAMLE2E ./test/integration/ -timeout 60s
```

### CI

The tests run inside the standard `go test` CI workflow.  They require no
external services and complete in < 10 s on commodity hardware.
