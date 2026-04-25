# PingFederate / PingOne — SAML Onboarding Guide

This guide walks through configuring **Ping Identity** (PingFederate or
PingOne) as the SAML Identity Provider for a Tikti tenant.

> **Prerequisite:** Tikti must be running with SAML enabled (`saml.enabled: true`)
> and the SP signing key provisioned. See [key-rotation.md](../key-rotation.md)
> for key lifecycle details.

## 1. Export Tikti SP metadata

Download the SP metadata XML that Ping will import:

```bash
tikti saml sp metadata --out tikti-sp-metadata.xml
# — or —
curl -o tikti-sp-metadata.xml https://<TIKTI_HOST>/saml/metadata
```

## 2. Create an SP connection

### PingFederate

1. Open the PingFederate admin console.
2. Navigate to **SP Connections → Create New**.
3. On the **Connection Type** tab, select **Browser SSO Profiles → SAML 2.0**.
4. On the **Import Metadata** tab, upload `tikti-sp-metadata.xml`.
5. PingFederate auto-populates the partner entity ID, ACS URL, and SLO URL.

### PingOne

1. Sign in to the [PingOne admin console](https://admin.pingone.com).
2. Navigate to **Connections → Applications → Add Application**.
3. Select **SAML Application** and click **Configure**.
4. Choose **Import Metadata** and upload `tikti-sp-metadata.xml`.

In both cases the following fields are populated:

| Field | Expected value |
|---|---|
| Partner Entity ID | `https://<TIKTI_HOST>/saml/metadata` |
| ACS URL | `https://<TIKTI_HOST>/saml/acs` |
| SLO Endpoint | `https://<TIKTI_HOST>/saml/slo` |

## 3. Configure attribute mapping

Add the following attribute contract mappings:

| SAML attribute | Source |
|---|---|
| `NameID` (Subject) | User email (e.g. `LDAP:mail`) |
| `mail` | `LDAP:mail` or `PingOne:Email Address` |
| `displayName` | `LDAP:displayName` or `PingOne:Formatted` |
| `groups` | `LDAP:memberOf` or PingOne group membership |

### PingFederate

Configure the **Attribute Contract** on the **Browser SSO → Assertion
Creation** tab, then map each contract attribute to the appropriate
LDAP or data-store source in the **Attribute Sources & User Lookup** section.

### PingOne

On the **Attribute Mappings** screen, map PingOne user attributes to the
SAML attribute names listed above.

## 4. Enable Single Logout (optional)

### PingFederate

Under **SP Connection → Browser SSO → SAML Profiles**, enable
**SP-Initiated SLO**. Upload Tikti's `sp.crt` as the SLO verification
certificate and set the SLO endpoint to `https://<TIKTI_HOST>/saml/slo`.

### PingOne

Under the application's **SAML Settings**, set the **SLO Endpoint** and
upload the SP signing certificate.

## 5. Activate the connection

- **PingFederate:** Set the connection to **Active** on the summary screen.
- **PingOne:** Toggle the application to **Enabled**.

Assign users or groups that should have access to Tikti.

## 6. Download the IdP metadata

### PingFederate

Navigate to **Server Settings → Server Configuration → Metadata Export** or
construct the URL:

```
https://<PINGFED_HOST>/pf/federation_metadata.ping?PartnerSpId=https://<TIKTI_HOST>/saml/metadata
```

### PingOne

In the application's **Configuration** tab, copy the **IDP Metadata URL**:

```
https://auth.pingone.com/<ENV_ID>/saml20/metadata/<APP_ID>
```

## 7. Register the IdP in Tikti

```bash
# From a metadata URL (recommended):
tikti saml idp register \
  --tid <TENANT_ID> \
  --metadata-url "<PING_METADATA_URL>"

# — or from a downloaded file —
tikti saml idp register \
  --tid <TENANT_ID> \
  --metadata-file ping-metadata.xml
```

Confirm the registration:

```bash
tikti saml idp show --tid <TENANT_ID>
```

## 8. Test the login

Open a browser and navigate to:

```
https://<TIKTI_HOST>/saml/login/<TENANT_ID>
```

You should be redirected to the Ping login page. After authenticating, the
SAML response is posted to the ACS endpoint and you are redirected back with
a valid session cookie.

## 9. Test Single Logout (optional)

```
https://<TIKTI_HOST>/saml/logout/<TENANT_ID>
```

Tikti sends a `LogoutRequest` to Ping. After the IdP confirms, the
local session is removed.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `assertion_signature_invalid` | Ping rotated its signing certificate | Re-download metadata and re-register, or use metadata URL for auto-refresh |
| `subject_confirmation_mismatch` | ACS URL mismatch | Verify ACS URL in Ping matches `https://<TIKTI_HOST>/saml/acs` |
| `clock_skew` | Clock drift between Tikti and Ping | Sync NTP on the Tikti host |
| `algorithm_disallowed` | Ping is configured for SHA-1 signatures | Switch to SHA-256 in the Ping signing configuration |
| `tid_unknown` | Tenant not registered | Run `tikti saml idp register` |

See [troubleshooting.md](../troubleshooting.md) for the full rejection-reason reference.
