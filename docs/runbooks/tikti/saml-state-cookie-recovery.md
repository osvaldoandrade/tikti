# SAML state-cookie recovery

## Symptom

Users return from Google Workspace to a blocked or bad-request page, while
Cloud Logging records `saml.assertion` with
`decision=reject reason=request_not_found` for the production Tikti container.

## Triage

1. Count ACS responses and status codes:

   ```sh
   gcloud logging read \
     'httpRequest.requestUrl:"/saml/"' \
     --project=code-company-admin-prod \
     --freshness=30m \
     --order=desc \
     --limit=100
   ```

2. Read Tikti decisions without request bodies:

   ```sh
   gcloud logging read \
     'resource.type="k8s_container" AND resource.labels.container_name="tikti" AND textPayload:"saml.assertion"' \
     --project=code-company-admin-prod \
     --freshness=30m \
     --order=desc \
     --limit=100
   ```

3. Confirm the IdP configuration through Code Foundry
   `Tenants & IAM > Service Grants`; do not remove or replace it during
   cookie triage.

## Mitigation

1. Confirm the current deployment uses a Tikti image that contains
   ADR-0002.
2. Run one SP-initiated login from Code Foundry `Entrar com SAML`.
3. Require one `repost` followed by one `success` in
   `tikti_saml_state_cookie_recovery_total` when the browser withholds the
   cross-site cookie.
4. Require the final `saml.assertion` decision to equal `accept`.

## Rollback

Restore the production image used by Tikti `v0.2.62`, then wait for the
deployment to become ready:

```sh
helm rollback tikti <previous-revision> \
  --namespace codecloud-identity \
  --wait \
  --timeout 5m
```

Rollback does not remove the Google Workspace app or the tenant IdP metadata
stored in Kvrocks.

## Post-incident

Record measured production results and any remaining browser-specific failure
under `docs/incidents/YYYY-MM-DD-saml-state-cookie-recovery.md`.
