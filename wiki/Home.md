# TIKTI

TIKTI (code-tikti) is a multi-tenant identity service that issues JWTs for user authentication (HS256 idTokens) and downstream authorization (RS256 access/worker tokens via JWKS). It delegates authentication to local credential stores (email/password, OOB email) and to external SAML 2.0 identity providers through SP-initiated federation.

TIKTI keeps a Firebase-compatible surface for sign-in and lookup, but makes tenant scoping and resource-server authorization explicit through `iss`, `aud`, `tid`, and `scope`.

Start with [Get Started](Get-Started).

The reading path for end-to-end evaluation is:

1. [Get Started](Get-Started)
2. [Overview](Overview)
3. [Architecture](Architecture-and-Data-Model)
4. [Tokens and Keys](Tokens-and-Keys)
5. [API Specification](API-Specification)
6. [SAML Federation](SAML-Federation)

For scenario-based behavior, read [Use Cases](Use-Cases).
