# HLD Verification — 2026-04-24

## 1. issueIDToken
- Package: `internal/services`
- File: `internal/services/user_service.go`
- Signature: `func (s *userService) issueIDToken(u *domain.User) (string, int, error)`
- Notes: Unexported method on `userService`. Signs an HS256 JWT using the configured `jwtSecret`. Returns the signed token string, an expiry duration (3600 seconds), and an error. Called after successful password verification in `SignIn` and after OOB code validation in `SignInWithOobCode`.

## 2. User model
- Package: `pkg/domain`
- File: `pkg/domain/user.go`
- Struct: `domain.User`
- Current fields: `Id` (string), `Email` (string), `Password` (string), `Role` (UserRole), `Status` (UserStatus), `CompanyId` (*string), `TokenVersion` (int), `CreatedAt` (time.Time)
- Notes: No dedicated `TenantID` field on the user struct. Tenant association is handled through the `Membership` model (`pkg/domain/membership.go`) and the `CompanyId` pointer field on User. `UserStatus` enum values: `ACTIVE`, `INACTIVE`, `SUSPENDED`. `UserRole` enum values: `ADMIN`, `COMPANY_ADMIN`, `COMPANY_EMPLOYEE`.

## 3. Token exchange endpoint
- Route: `POST /v1/accounts/token/exchange`
- Handler: `internal/controllers/token_exchange_controller.go` → `tokenExchangeController.Handle`
- Registration: `internal/app/url_mappings.go` (behind API-key middleware)
- Notes: Exchanges an HS256 idToken for an RS256 scoped access token. The handler delegates to `userService.TokenExchange` which validates the inbound HS256 idToken, resolves the user, enforces scope/audience constraints, and signs an RS256 JWT using the configured JWKS private key.

## 4. Audit sink
- **No audit sink exists in the codebase.**
- There is no `audit` package, no audit writer interface, no audit log implementation, and no audit-related code in any of the service, controller, or repository layers.
- The term "audit" appears only in documentation files (e.g., `docs/07_operations_and_slo.md`, `docs/12_saml_federation_hld.md`) but has no corresponding implementation.

## 5. Router
- Library: `github.com/gin-gonic/gin v1.10.1`
- CORS middleware: `github.com/gin-contrib/cors v1.7.6`
- Notes: Not `chi`, `echo`, `gorilla/mux`, or plain `net/http`. The application bootstraps a `gin.Default()` engine in `internal/app/application.go` and registers routes via `internal/app/url_mappings.go`. Route groups use Gin's `engine.Group()` and `Use()` for middleware.

## 6. Redis client
- Library: `github.com/go-redis/redis/v8 v8.11.5`
- Notes: This is the older `go-redis/redis/v8` module, **not** the newer `github.com/redis/go-redis/v9`. The provider is in `internal/providers/redis_provider.go` and uses `context.Context`-based APIs.

## 7. Anything surprising that affects the HLD
- **Router mismatch**: The HLD may assume `chi` but the repo uses `gin`. Any SAML middleware or route-group design must target the Gin API (`gin.HandlerFunc`, `gin.Context`), not `chi` or `net/http` middleware signatures.
- **Redis client version mismatch**: The HLD may reference `github.com/redis/go-redis/v9` but the repo uses the older `github.com/go-redis/redis/v8`. If new SAML code needs v9 features (e.g., new stream APIs), a migration is required.
- **No audit infrastructure**: The HLD references an audit sink, but none exists. This must be built from scratch.
- **`issueIDToken` is unexported**: The function is a private method on `userService`, not a standalone exported function. SAML sign-in flows that need to issue idTokens will need to either call `issueIDToken` from within `userService` or the method will need to be refactored.
- **No `TenantID` on User struct**: Tenant association is modeled through the separate `Membership` entity and the optional `CompanyId` pointer on `User`, not a direct `TenantID` field. The HLD user-model description may need updating.
- **`TokenVersion` for revocation**: The user model includes a `TokenVersion` field used for token revocation checks during RS256 access-token validation. SAML-issued tokens should respect this mechanism.
