# Google Workspace — SAML Onboarding Guide

This guide walks through configuring **Google Workspace** as the SAML
Identity Provider for a Tikti tenant.

> **Note:** This guide covers the **enterprise SAML** path for managed
> Google Workspace domains (e.g. `@corp.example.com`). Personal Gmail
> accounts use OIDC and are handled separately.

> **Prerequisite:** Tikti must be running with SAML enabled (`saml.enabled: true`)
> and the SP signing key provisioned. See [key-rotation.md](../key-rotation.md)
> for key lifecycle details.

## 1. Export Tikti SP metadata

Download the SP metadata XML. You will use the values from it to configure
Google Workspace (Google does not support uploading SP metadata directly):

```bash
tikti saml sp metadata --out tikti-sp-metadata.xml
# — or —
curl -o tikti-sp-metadata.xml https://<TIKTI_HOST>/saml/metadata
```

Open the file and note the **Entity ID**, **ACS URL**, and **SLO URL**.

## 2. Create a custom SAML app

1. Sign in to the [Google Admin console](https://admin.google.com) as a
   super administrator.
2. Navigate to **Apps → Web and mobile apps**.
3. Click **Add app → Add custom SAML app**.
4. Enter an **App name** (e.g. `Tikti SSO`) and optionally upload a logo.
   Click **Continue**.

## 3. Copy the Google IdP metadata

On the **Google Identity Provider details** screen:

1. Click **Download Metadata** to save the IdP metadata XML file, **or**
   copy the **SSO URL**, **Entity ID**, and **Certificate** values for
   manual configuration.
2. Click **Continue**.

> The metadata URL is not auto-refreshable in Google Workspace. Save the
> downloaded XML file; you will use it in step 7.

## 4. Configure Service Provider details

Enter the following on the **Service Provider Details** screen:

| Field | Value |
|---|---|
| ACS URL | `https://<TIKTI_HOST>/saml/acs` |
| Entity ID | `https://<TIKTI_HOST>/saml/metadata` |
| Start URL | `https://<TIKTI_HOST>/saml/login/<TENANT_ID>` *(optional)* |
| Name ID format | `EMAIL` |
| Name ID | `Basic Information > Primary email` |

Check **Signed Response** to ensure both the response and assertion are
signed.

Click **Continue**.

## 5. Configure attribute mapping

Add the following attribute mappings:

| Google Directory attribute | App attribute |
|---|---|
| Primary email | `mail` |
| First name + Last name | `displayName` |

> Google Workspace does not natively send group membership in SAML
> assertions. If you need group-based roles, consider syncing groups via
> an external mechanism or using a custom attribute.

Click **Finish**.

## 6. Enable the app for users

1. On the app's settings page, click **User access**.
2. Select **ON for everyone** (or restrict to specific organizational
   units).
3. Click **Save**.

> Changes may take up to 24 hours to propagate across Google Workspace,
> though they typically take effect within minutes.

## 7. Register the IdP in Tikti

Because Google Workspace does not provide a stable metadata URL, use the
downloaded metadata file from step 3:

```bash
tikti saml idp register \
  --tid <TENANT_ID> \
  --metadata-file google-idp-metadata.xml
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

You should be redirected to the Google sign-in page. After authenticating
with your managed Google Workspace account, Google posts the SAML response
to the Tikti ACS endpoint and you are redirected back with a valid session
cookie.

## 9. Test Single Logout (optional)

```
https://<TIKTI_HOST>/saml/logout/<TENANT_ID>
```

> **Note:** Google Workspace has limited SLO support. SP-initiated logout
> will terminate the Tikti session, but the Google Workspace session may
> remain active. Users should be instructed to sign out of Google
> separately if full session termination is required.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `assertion_signature_invalid` | Google rotated its signing certificate | Download fresh metadata from the Admin console and re-register with `tikti saml idp register` |
| `subject_confirmation_mismatch` | ACS URL mismatch | Verify **ACS URL** in the Google SAML app matches `https://<TIKTI_HOST>/saml/acs` |
| `clock_skew` | Clock drift between Tikti and Google | Sync NTP on the Tikti host |
| `tid_unknown` | Tenant not registered | Run `tikti saml idp register` |
| App shows "not available" | User access not enabled | Enable the app for the organizational unit in Google Admin |

See [troubleshooting.md](../troubleshooting.md) for the full rejection-reason reference.
