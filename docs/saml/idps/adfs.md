# AD FS — SAML Onboarding Guide

This guide walks through configuring **Active Directory Federation Services
(AD FS)** as the SAML Identity Provider for a Tikti tenant.

> **Prerequisite:** Tikti must be running with SAML enabled (`saml.enabled: true`)
> and the SP signing key provisioned. See [key-rotation.md](../key-rotation.md)
> for key lifecycle details.

## 1. Export Tikti SP metadata

Download the SP metadata XML that AD FS will import:

```bash
tikti saml sp metadata --out tikti-sp-metadata.xml
# — or —
curl -o tikti-sp-metadata.xml https://<TIKTI_HOST>/saml/metadata
```

## 2. Add a Relying Party Trust

1. Open the **AD FS Management** console on your federation server.
2. Navigate to **Trust Relationships → Relying Party Trusts** (AD FS 3.x)
   or **Relying Party Trusts** (AD FS 4.x / 2019+).
3. Click **Add Relying Party Trust** to launch the wizard.
4. Select **Claims aware** and click **Start**.
5. Choose **Import data about the relying party from a file** and select
   `tikti-sp-metadata.xml` from step 1. Click **Next**.
6. Set the **Display name** (e.g. `Tikti SSO`) and click **Next**.
7. Configure access control (e.g. **Permit everyone** or a specific group)
   and click **Next**.
8. Review the settings and click **Close**.

AD FS auto-populates:

| Field | Expected value |
|---|---|
| Identifier (Entity ID) | `https://<TIKTI_HOST>/saml/metadata` |
| SAML Assertion Consumer Endpoint | `https://<TIKTI_HOST>/saml/acs` |
| SAML Logout Endpoint | `https://<TIKTI_HOST>/saml/slo` |

## 3. Configure claim issuance rules

Edit the claim rules for the new Relying Party Trust:

### Rule 1 — Send LDAP attributes as claims

| Outgoing claim | LDAP attribute |
|---|---|
| E-Mail Address | `E-Mail-Addresses` |
| Name | `Display-Name` |
| Name ID | `E-Mail-Addresses` (format: Email) |

1. Click **Add Rule → Send LDAP Attributes as Claims**.
2. Set the **Attribute store** to **Active Directory**.
3. Add the mappings above and click **Finish**.

### Rule 2 — Send group membership (optional)

1. Click **Add Rule → Send Group Membership as a Claim**.
2. Set the **Outgoing claim type** to `groups`.
3. Select the Active Directory groups that should be sent and click
   **Finish**.

The resulting SAML attributes map to Tikti's default attribute contract:

| Tikti attribute | AD FS claim URI |
|---|---|
| `NameID` | *(Subject — Email format)* |
| `email` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` |
| `displayName` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` |
| `groups` | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |

## 4. Configure signing algorithm

Tikti requires SHA-256 signatures. Verify this in the Relying Party Trust:

1. Open the trust properties → **Advanced** tab.
2. Set **Secure hash algorithm** to **SHA-256**.

## 5. Enable Single Logout (optional)

AD FS supports SP-initiated SLO via the `SingleLogoutService` endpoint
imported from SP metadata. Verify the endpoint is listed under:

**Relying Party Trust → Endpoints → SAML Logout Endpoints**

| Binding | URL |
|---|---|
| POST or Redirect | `https://<TIKTI_HOST>/saml/slo` |

## 6. Download the IdP metadata

AD FS publishes its federation metadata at:

```
https://<ADFS_HOST>/FederationMetadata/2007-06/FederationMetadata.xml
```

Copy this URL or download the file.

## 7. Register the IdP in Tikti

```bash
# From the metadata URL (recommended):
tikti saml idp register \
  --tid <TENANT_ID> \
  --metadata-url "https://<ADFS_HOST>/FederationMetadata/2007-06/FederationMetadata.xml"

# — or from a downloaded file —
tikti saml idp register \
  --tid <TENANT_ID> \
  --metadata-file adfs-metadata.xml
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

You should be redirected to the AD FS sign-in page. After authenticating
with Active Directory credentials, AD FS posts the SAML response to the
Tikti ACS endpoint and you are redirected back with a valid session cookie.

## 9. Test Single Logout (optional)

```
https://<TIKTI_HOST>/saml/logout/<TENANT_ID>
```

Tikti sends a `LogoutRequest` to AD FS. After the IdP confirms, the
local session is removed.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `assertion_signature_invalid` | AD FS token-signing certificate expired or rotated | Re-download metadata and re-register, or use metadata URL for auto-refresh |
| `algorithm_disallowed` | SHA-1 is configured on the Relying Party Trust | Change **Secure hash algorithm** to SHA-256 in the trust's Advanced tab |
| `subject_confirmation_mismatch` | ACS URL mismatch | Verify the SAML Consumer Endpoint matches `https://<TIKTI_HOST>/saml/acs` |
| `clock_skew` | Clock drift between Tikti and the AD FS server | Sync NTP on both hosts |
| `tid_unknown` | Tenant not registered | Run `tikti saml idp register` |

See [troubleshooting.md](../troubleshooting.md) for the full rejection-reason reference.
