# Azure AD / Entra ID — SAML Onboarding Guide

This guide walks through configuring **Microsoft Entra ID** (formerly
Azure Active Directory) as the SAML Identity Provider for a Tikti tenant.

> **Prerequisite:** Tikti must be running with SAML enabled (`saml.enabled: true`)
> and the SP signing key provisioned. See [key-rotation.md](../key-rotation.md)
> for key lifecycle details.

## 1. Export Tikti SP metadata

Download the SP metadata XML that Entra ID will import:

```bash
tikti saml sp metadata --out tikti-sp-metadata.xml
# — or —
curl -o tikti-sp-metadata.xml https://<TIKTI_HOST>/saml/metadata
```

Keep this file handy; you will upload it in step 3.

## 2. Create an Enterprise Application in Entra ID

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com).
2. Navigate to **Identity → Applications → Enterprise applications**.
3. Click **New application → Create your own application**.
4. Name it (e.g. `Tikti SSO`), select **Integrate any other application you
   don't find in the gallery (Non-gallery)**, and click **Create**.

## 3. Configure SAML SSO

1. In the new application, go to **Single sign-on → SAML**.
2. Click **Upload metadata file** and select `tikti-sp-metadata.xml` from
   step 1. Entra ID will auto-populate the following fields:

   | Field | Expected value |
   |---|---|
   | Identifier (Entity ID) | `https://<TIKTI_HOST>/saml/metadata` |
   | Reply URL (ACS URL) | `https://<TIKTI_HOST>/saml/acs` |
   | Logout URL | `https://<TIKTI_HOST>/saml/slo` |

3. Verify the values match your Tikti deployment and click **Save**.

## 4. Configure attribute claims

Entra ID sends attributes as claims. Map them to Tikti's expected names:

| Tikti attribute | Claim name | Source |
|---|---|---|
| `NameID` | *(default)* | `user.userprincipalname` (Email format) |
| `email` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | `user.mail` |
| `displayName` | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` | `user.displayname` |
| `groups` | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` | Group object IDs |

To emit group claims:

1. Go to **Single sign-on → Attributes & Claims → Edit**.
2. Click **Add a group claim**, select **Security groups** or **Groups
   assigned to the application**, and set the source attribute to
   **Group ID**.

## 5. Assign users / groups

Under **Users and groups**, assign the users or Azure AD groups that should
have access to Tikti.

## 6. Download the IdP metadata

1. In **SAML Certificates**, find **App Federation Metadata Url** and copy it.
   The URL has the form:

   ```
   https://login.microsoftonline.com/<TENANT_ID>/federationmetadata/2007-06/federationmetadata.xml?appid=<APP_ID>
   ```

2. Alternatively, click **Download** next to **Federation Metadata XML** to
   save the file locally.

## 7. Register the IdP in Tikti

Use the CLI to register the IdP for your tenant:

```bash
# From a metadata URL (recommended — enables automatic metadata refresh):
tikti saml idp register \
  --tid <TENANT_ID> \
  --metadata-url "https://login.microsoftonline.com/<AZURE_TENANT>/federationmetadata/2007-06/federationmetadata.xml?appid=<APP_ID>"

# — or from a downloaded file —
tikti saml idp register \
  --tid <TENANT_ID> \
  --metadata-file federation-metadata.xml
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

You should be redirected to the Microsoft login page. After authenticating,
Entra ID posts the SAML response to the Tikti ACS endpoint and you are
redirected back to the application with a valid session cookie.

## 9. Test Single Logout (optional)

```
https://<TIKTI_HOST>/saml/logout/<TENANT_ID>
```

Tikti sends a `LogoutRequest` to Entra ID. After the IdP confirms, the
local session is removed.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `assertion_signature_invalid` | Certificate mismatch after Entra auto-rotates signing keys | Re-register metadata or enable metadata URL for auto-refresh |
| `clock_skew` | VM clock drift | Sync NTP on the Tikti host |
| `subject_confirmation_mismatch` | Reply URL mismatch | Verify ACS URL in Entra matches `https://<TIKTI_HOST>/saml/acs` |
| `tid_unknown` | Tenant not registered | Run `tikti saml idp register` |

See [troubleshooting.md](../troubleshooting.md) for the full rejection-reason reference.
