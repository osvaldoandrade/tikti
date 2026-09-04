# Password Sign-In

Authenticate an existing user with email and password. This is the credential-based authentication path; SAML SSO provides a federated alternative for tenants with an external IdP.

## Actors

- End user
- Client application
- Tikti API

## Preconditions

The user exists with an active account status. A password hash is stored for the identity.

## Main flow

1. User submits email and password in the client application.
2. Client calls `POST /v1/accounts/signInWithPassword` with `X-API-Key: API_KEY`.
3. Tikti validates the credentials and account status.
4. Tikti returns an idToken and the authentication payload.
5. Client may call `POST /v1/accounts/lookup` with `X-API-Key: API_KEY` to resolve identity metadata.

### Sequence diagram

```mermaid
sequenceDiagram
    participant U as End User
    participant F as Client App
    participant T as Tikti API

    U->>F: Enter email/password and submit
    F->>T: POST /v1/accounts/signInWithPassword (X-API-Key)
    T->>T: Validate credentials and account status
    T-->>F: idToken + auth payload
    opt Resolve profile metadata
        F->>T: POST /v1/accounts/lookup (X-API-Key)
        T-->>F: Identity metadata
    end
    F-->>U: Authenticated session
```

## Expected outcomes

Correct credentials produce a valid authentication payload. Invalid credentials are rejected with stable error semantics. Suspended or inactive users cannot authenticate regardless of credential validity.

## Failure scenarios

Wrong password: authentication denied.

Unknown email: authentication denied.

Suspended user: authentication denied even with correct credentials.

## Related specs

- [API Specification](API-Specification)
- [Operations and SLO](Operations-and-SLO)
