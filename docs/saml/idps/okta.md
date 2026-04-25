# Okta — SAML Onboarding Guide

This guide walks through configuring **Okta** as the SAML Identity Provider
for a Tikti tenant.

> **Prerequisite:** Tikti must be running with SAML enabled (`saml.enabled: true`)
> and the SP signing key provisioned. See [key-rotation.md](../key-rotation.md)
> for key lifecycle details.

## 1. Export Tikti SP metadata

Download the SP metadata XML that Okta will import:

```bash
tikti saml sp metadata --out tikti-sp-metadata.xml
# — or —
curl -o tikti-sp-metadata.xml https://<TIKTI_HOST>/saml/metadata
```

## 2. Create a SAML application in Okta

1. Sign in to the [Okta Admin Console](https://admin.okta.com).
2. Navigate to **Applications → Applications → Create App Integration**.
3. Select **SAML 2.0** and click **Next**.
4. Set the **App name** (e.g. `Tikti SSO`) and click **Next**.

## 3. Configure SAML settings

On the **Configure SAML** tab, enter:

| Field | Value |
|---|---|
| Single sign-on URL | `https://<TIKTI_HOST>/saml/acs` |
| Audience URI (SP Entity ID) | `https://<TIKTI_HOST>/saml/metadata` |
| Name ID format | `EmailAddress` |
| Application username | `Email` |

Under **Single Logout**:

| Field | Value |
|---|---|
| Enable Single Logout | ✅ Checked |
| Single Logout URL | `https://<TIKTI_HOST>/saml/slo` |
| SP Issuer | `https://<TIKTI_HOST>/saml/metadata` |
| Signature Certificate | Upload `sp.crt` from the Tikti SP key pair |

> **Tip:** You can also upload `tikti-sp-metadata.xml` via **Upload Metadata**
> to populate these fields automatically, if your Okta plan supports it.

## 4. Configure attribute statements

Add the following attribute statements on the same screen:

| Name | Value |
|---|---|
| `mail` | `user.email` |
| `displayName` | `user.firstName + " " + user.lastName` |

For group attribute statements:

| Name | Filter | Value |
|---|---|---|
| `groups` | Matches regex `.*` | *(all groups)* |

Click **Next**, select **I'm an Okta customer adding an internal app**, and
click **Finish**.

## 5. Assign users / groups

In the **Assignments** tab of the new application, assign the Okta users or
groups that should have access to Tikti.

## 6. Download the IdP metadata

1. Go to the **Sign On** tab.
2. In the **SAML Signing Certificates** section, find the active certificate
   and click **Actions → View IdP metadata**.
3. Copy the metadata URL. It typically looks like:

   ```
   https://<ORG>.okta.com/app/<APP_ID>/sso/saml/metadata
   ```

4. Alternatively, right-click the link and save the XML file.

## 7. Register the IdP in Tikti

```bash
# From a metadata URL (recommended):
tikti saml idp register \
  --tid <TENANT_ID> \
  --metadata-url "https://<ORG>.okta.com/app/<APP_ID>/sso/saml/metadata"

# — or from a downloaded file —
tikti saml idp register \
  --tid <TENANT_ID> \
  --metadata-file okta-metadata.xml
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

Okta presents its login page (or skips it if you have an active Okta
session). After authentication, the SAML response is posted to the ACS
endpoint and you are redirected back with a valid session cookie.

## 9. Test Single Logout (optional)

```
https://<TIKTI_HOST>/saml/logout/<TENANT_ID>
```

Tikti sends a `LogoutRequest` to Okta. After the IdP confirms, the
local session is removed.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `assertion_signature_invalid` | Okta rotated its signing certificate | Re-download metadata and re-register, or use metadata URL for auto-refresh |
| `subject_confirmation_mismatch` | ACS URL mismatch | Ensure **Single sign-on URL** in Okta matches `https://<TIKTI_HOST>/saml/acs` |
| `clock_skew` | Clock drift between Tikti and Okta | Sync NTP on the Tikti host |
| `tid_unknown` | Tenant not registered | Run `tikti saml idp register` |

See [troubleshooting.md](../troubleshooting.md) for the full rejection-reason reference.
