# IdP Onboarding Runbook

Step-by-step guide to register an external SAML 2.0 Identity Provider (IdP)
with Tikti. Estimated time: **15 minutes**.

> **Audience:** Platform engineers. No prior SAML experience required.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| **Tikti CLI** | `tikti-cli` built and on `$PATH` |
| **Redis** | Running instance reachable from the CLI (default `localhost:6379`) |
| **SP signing key + cert** | PEM files for the Service Provider (see [key-rotation.md](key-rotation.md) for generation) |
| **IdP metadata URL** | Provided by the IdP administrator (e.g. `https://idp.example.com/metadata`) |
| **Tenant ID** | The Tikti tenant that will use this IdP |

---

## Step 1 — Generate SP metadata

The IdP needs to know about your Service Provider. Generate the SP metadata
XML and send it to the IdP administrator:

```bash
tikti-cli saml sp metadata \
  --entity-id  https://auth.example.com/saml \
  --acs-url    https://auth.example.com/saml/acs \
  --slo-url    https://auth.example.com/saml/slo \
  --signing-cert /etc/tikti/saml/sp-cert.pem \
  --out sp-metadata.xml
```

Send `sp-metadata.xml` to the IdP admin. They will configure a relying-party
trust and provide you with a **metadata URL** (or XML file).

---

## Step 2 — Register the IdP

Once you have the IdP metadata URL:

```bash
tikti-cli saml idp register \
  --tid        acme-corp \
  --metadata-url https://idp.example.com/metadata
```

The CLI will:

1. Fetch the metadata XML from the URL.
2. Parse and validate it (entity ID, signing certificates, HTTPS SSO URL).
3. Store the `IdPRecord` in Redis keyed by tenant ID.

### Using a local metadata file

If the IdP provides an XML file instead of a URL, pass `--metadata-file`:

```bash
tikti-cli saml idp register \
  --tid        acme-corp \
  --metadata-file /tmp/idp-metadata.xml
```

---

## Step 3 — (Optional) Apply an attribute map

If the IdP sends attributes with names that differ from what Tikti expects,
create a JSON mapping file:

```json
{
  "email": ["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"],
  "displayName": ["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"],
  "groups": ["http://schemas.xmlsoap.org/claims/Group"]
}
```

Register (or update) with the map:

```bash
tikti-cli saml idp register \
  --tid        acme-corp \
  --metadata-url https://idp.example.com/metadata \
  --attr-map   attr-map.json
```

To update an existing registration:

```bash
tikti-cli saml idp update \
  --tid        acme-corp \
  --attr-map   attr-map.json
```

---

## Step 4 — Map the email domain

Link the corporate email domain to the tenant so Tikti can route login
requests to the correct IdP:

```bash
tikti-cli saml domain add \
  --tid    acme-corp \
  --domain example.com
```

---

## Step 5 — Verify the registration

Inspect the stored IdP record:

```bash
tikti-cli saml idp show --tid acme-corp --json
```

Expected fields in the output:

| Field | Example |
|---|---|
| `entityID` | `https://idp.example.com/saml` |
| `ssoURL` | `https://idp.example.com/sso` |
| `signingCerts` | 1 or more base64-encoded certificates |
| `tenantID` | `acme-corp` |

---

## Step 6 — Dry-run a SAML login

Generate a test AuthnRequest URL to validate the end-to-end flow:

```bash
tikti-cli saml test \
  --tid   acme-corp \
  --email user@example.com
```

The command prints a redirect URL. Open it in a browser:

1. You are redirected to the IdP login page.
2. Authenticate with a test account on the IdP.
3. The IdP POSTs a SAML response back to the ACS URL.
4. Tikti validates the assertion and creates a session.

If the ACS returns a session cookie and a `200 OK` (or redirects to
`/debug/ok`), the onboarding is complete.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `IdP already registered for tenant "X"` | Duplicate registration | Use `tikti-cli saml idp update` or `tikti-cli saml idp remove --tid X` first |
| `no signing certificate` | Metadata XML has no `<KeyDescriptor use="signing">` | Ask the IdP admin to include a signing certificate |
| `SSO URL not using HTTPS` | IdP metadata contains an HTTP SSO endpoint | Ask the IdP admin to publish an HTTPS endpoint |
| `expired signing certificate` | All certificates in the metadata are expired | Ask the IdP admin to rotate their signing certificate |
| `domain "X" is already mapped to tenant "Y"` | Email domain conflict | Remove the old mapping with `tikti-cli saml domain remove --domain X` |
| AuthnRequest URL returns IdP error | SP metadata not imported on IdP side | Re-send `sp-metadata.xml` to the IdP admin (Step 1) |
| ACS rejects the assertion | Clock skew or signature mismatch | Check `clockSkewSeconds` in `tikti.yaml`; verify the IdP signing cert matches |

---

## Quick-reference: CLI commands

```text
tikti-cli saml sp metadata   --entity-id ... --acs-url ... --signing-cert ... [--out FILE]
tikti-cli saml idp register  --tid TID --metadata-url URL [--attr-map FILE]
tikti-cli saml idp update    --tid TID [--metadata-url URL] [--attr-map FILE]
tikti-cli saml idp remove    --tid TID
tikti-cli saml idp list
tikti-cli saml idp show      --tid TID [--json]
tikti-cli saml idp fetch     --tid TID
tikti-cli saml domain add    --tid TID --domain DOMAIN
tikti-cli saml domain remove --domain DOMAIN
tikti-cli saml test          --tid TID --email USER
```

---

## Related docs

- [key-rotation.md](key-rotation.md) — SP signing key rotation procedure
- [k8s-external-secrets.md](k8s-external-secrets.md) — Provisioning SP keys via external-secrets-operator
- [HLD §17 — Admin CLI Additions](../12_saml_federation_hld.md) — Full CLI specification
