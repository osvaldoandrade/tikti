# TIKTI

TIKTI (code-tikti) is a multi-tenant identity service that issues deterministic JWTs for both user authentication (HS256 idTokens) and downstream authorization (RS256 access/worker tokens via JWKS).

It keeps a Firebase-compatible surface for sign-in and lookup, but makes tenant scoping and resource-server authorization explicit through `iss`, `aud`, `tid`, and `scope`.

Start with [Get Started](Get-Started).

If you are evaluating TIKTI end-to-end, the fastest reading path is:

1. [Get Started](Get-Started)
2. [Overview](Overview)
3. [Architecture](Architecture-and-Data-Model)
4. [Tokens and Keys](Tokens-and-Keys)
5. [API Specification](API-Specification)

For scenario-based behavior, read [Use Cases](Use-Cases).
