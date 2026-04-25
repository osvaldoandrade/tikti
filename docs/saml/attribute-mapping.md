# Attribute Mapping Reference

Tikti's SAML SP extracts three user fields — **email**, **name**, and
**roles** — from every verified assertion. The **subject** (`NameID`) is
always taken from the SAML `<Subject>` element.

This document covers the default mapping table, how to override it per
tenant, and ready-to-use configurations for common identity providers.

## Default Attribute Map

When no custom map is supplied via `--attr-map`, Tikti uses the built-in
defaults shown below:

| Tikti field | Source | Default IdP attribute names (tried in order) | Required |
|---|---|---|---|
| `subject` | `<Subject>` / `NameID` | *(always extracted — not configurable)* | Yes |
| `email` | `<AttributeStatement>` | `mail`, `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` | Yes |
| `name` | `<AttributeStatement>` | `displayName`, `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` | No |
| `roles` | `<AttributeStatement>` | `groups`, `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` | No |

**First-match semantics** — for each Tikti field the mapped IdP attribute
names are tried left-to-right; the first attribute present with a non-empty
value wins. For `roles`, all values of the first matched attribute are
collected.

> **Security note:** the attributes `tid`, `tenant_id`, and `tenantId`
> (exact matches only) are **always stripped** from every assertion before
> mapping. The tenant identifier is taken exclusively from the URL path to
> prevent cross-tenant escalation via a compromised IdP.

## Override Syntax

Create a JSON file that maps each Tikti field to an ordered list of IdP
attribute names:

```json
{
  "email": ["mail"],
  "name":  ["displayName"],
  "roles": ["memberOf"]
}
```

Pass it when registering or updating an IdP:

```bash
# At registration time
tikti saml idp register \
  --tid acme \
  --metadata-url https://idp.acme.com/metadata \
  --attr-map attr-map.json

# Update an existing registration
tikti saml idp update \
  --tid acme \
  --attr-map attr-map.json
```

Only the fields present in the file are overridden; omitted fields fall back
to the defaults.

### Rules

* Every value in the JSON arrays is matched **case-sensitively** against the
  `Name` attribute of `<saml:Attribute>` elements in the assertion.
* `email` is the only **required** field. If none of the mapped attribute
  names resolve to a value, the assertion is rejected with reason
  `missing_attribute`.
* `name` and `roles` are optional. If they cannot be resolved, the user is
  provisioned with an empty name or no roles, respectively.
* `subject` is not configurable — it always comes from `NameID`.

## Vendor Examples

### 1. Azure AD / Entra ID

Azure AD emits WS-Federation-style claim URIs by default.

```json
{
  "email": [
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
  ],
  "name": [
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
  ],
  "roles": [
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
  ]
}
```

> **Tip:** In the Azure portal, ensure *User.mail* and *Group IDs* (or
> *Group names*) are included in the SAML claims configuration for the
> enterprise application.

### 2. Okta

Okta uses short attribute names by default in its attribute statements.

```json
{
  "email": ["mail", "email"],
  "name":  ["displayName", "name"],
  "roles": ["groups"]
}
```

> **Tip:** In Okta Admin → Applications → *your app* → SAML Settings →
> Attribute Statements, add `mail` → `user.email`, `displayName` →
> `user.firstName + " " + user.lastName`, and under Group Attribute
> Statements add `groups` with a regex filter.

### 3. Google Workspace

Google Workspace SAML apps expose attributes configured under
Admin console → Apps → Web and mobile apps → *your app* → Attribute mapping.

```json
{
  "email": ["email"],
  "name":  ["displayName", "name"],
  "roles": ["groups"]
}
```

> **Tip:** Google does not send group membership by default. Use
> [Google Cloud Directory Sync](https://support.google.com/a/answer/106368)
> or the Admin SDK to emit a `groups` attribute, or omit `roles` from the
> map and assign roles within Tikti directly.

### 4. AD FS

AD FS uses the same WS-Federation claim URIs as Azure AD.

```json
{
  "email": [
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
  ],
  "name": [
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
  ],
  "roles": [
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
    "http://schemas.xmlsoap.org/claims/Group"
  ]
}
```

> **Tip:** In the AD FS Management console, edit the Relying Party Trust's
> *Claim Issuance Policy* and add rules to send LDAP attributes as claims
> (`E-Mail-Addresses` → `E-Mail Address`, `Token-Groups - Unqualified
> Names` → `Group`).

### 5. PingFederate

PingFederate uses short names by default when configured with an LDAP data
store.

```json
{
  "email": ["mail", "email"],
  "name":  ["cn", "displayName"],
  "roles": ["memberOf", "groups"]
}
```

> **Tip:** In the PingFederate admin console, create an SP Connection and
> map LDAP attributes in the *Attribute Contract* tab. Ensure the
> `mail`, `cn`, and `memberOf` attributes are included in the attribute
> contract fulfillment.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Assertion rejected with `missing_attribute` | The IdP does not release a matching `email` attribute | Decode the SAML response, inspect `<AttributeStatement>`, and add the correct attribute name to the `email` list in your `--attr-map` file. |
| User provisioned with empty name | `name` attribute key doesn't match | Same approach — add the IdP's actual attribute name to `name`. |
| No roles assigned after login | IdP does not send group/role claims or the attribute name doesn't match | Add a group attribute statement in the IdP and update `roles` in the map. |
| `tid`-related attributes ignored (INFO log) | The assertion contained a `tid`, `tenant_id`, or `tenantId` attribute | This is expected — Tikti always sources `tid` from the URL path. No action required. |

## See Also

* [SAML Federation HLD — §10 Attribute Mapping](../12_saml_federation_hld.md)
* [SP Key Rotation](key-rotation.md)
* [External Secrets for SP Keys](k8s-external-secrets.md)
