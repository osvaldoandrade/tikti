# 10 Unit Functional Test Matrix

## Objective

This document defines the functional matrix for Tikti unit tests. The matrix covers every function in scope (except bootstrap/main), organized by functional profile. Functional testing (black-box) serves as the validation criterion. Structural testing via control flow graph (CFG) analysis serves as a complementary coverage metric. Each function must reach a minimum of 85% executable-path coverage.

## Scope

The matrix includes functions in `internal/controllers`, `internal/services`, `internal/repository`, `internal/providers`, `internal/saml`, `internal/utils`, and `pkg/config`. Bootstrap and main functions in `internal/app` and `cmd/tikti/main.go` are excluded. The matrix maps 133 functions from the existing codebase plus the SAML 2.0 federation surface defined in `docs/12_saml_federation_hld.md`.

## Method

For each function the test plan follows five steps. First, model the control flow graph and enumerate independent paths (the base path set). Second, derive equivalence classes and input boundaries from the SPEC or functional contract. Third, map each path to a functional case consisting of an input and an expected output (the oracle). Fourth, cover paths until the function reaches 85% executable-path coverage. Fifth, reject assertions that lack a functional oracle (for example, `assert.True(true)` without business meaning).

## Canonical Fake Data

Emails: `valid.user@acme.test`, `unknown@acme.test`, `admin@acme.test`, `saml.user@corp.test`. Passwords: `P@ssw0rd!`, `wrong-pass`, `new-pass-123`. Tenant IDs: `tenant-1`, `tenant-404`, `tenant-other`, `tenant-saml`. Roles: `ADMIN`, `COMPANY_ADMIN`, `COMPANY_EMPLOYEE`, `TENANT_USER`. Scopes: `codeq:claim`, `codeq:heartbeat`, `codeq:result`, `codeq:admin`. OOB: valid, expired, consumed, and mismatched `requestType` codes. Tokens: valid JWT, expired JWT, invalid signature, invalid audience/issuer. SAML assertion IDs: `_a1b2c3d4e5f6`, `_reused-assertion-id`. SAML request IDs: `_req-20byte-hex`. SAML NameIDs: `saml.user@corp.test`. SAML session indices: `_session-idx-001`. IdP entity IDs: `https://idp.corp.test/metadata`. SP entity ID: `https://tikti.example.com/saml`.

## Functional Profiles (PF) and Case Packs (CF)

| PF | CF Pack | Functional Partitions (black-box) | Key Boundaries | Functional Oracle |
| --- | --- | --- | --- | --- |
| `PF-01` Constructors/factories | `CF-01-01..03` | valid dependencies, partial nil, full nil | nil vs non-nil dependencies | non-nil instance, no panic, consistent wiring |
| `PF-02` Admin guard controller | `CF-02-01..05` | missing token, invalid token, non-admin role, admin role | empty header, `Bearer`/raw token | `401/403/200` according to ADMIN rule |
| `PF-03` Async wrapper | `CF-03-01..03` | success callback, error callback, concurrency | immediate channel return | channel returns result or error and closes |
| `PF-04` HTTP create mutation | `CF-04-01..05` | valid payload, invalid JSON, validation error, service error, success | empty required fields | status code and error/success payload according to contract |
| `PF-05` HTTP read/list | `CF-05-01..05` | valid params, invalid params, not found, service error, success | empty/missing query/path | response shape and status codes |
| `PF-06` HTTP auth/oob contract | `CF-06-01..07` | valid request, invalid credentials, invalid token, invalid/expired OOB, success | empty email, empty oob | responses match auth/OOB SPEC |
| `PF-07` HTTP admin mutation | `CF-07-01..06` | authorized/unauthorized, invalid payload, domain error, success | invalid status, invalid scope | mutations with status codes |
| `PF-08` Provider string helpers | `CF-08-01..04` | normal string, placeholder, empty, whitespace-only | `""`, whitespace, placeholder token | deterministic normalization |
| `PF-09` Provider host:port parser | `CF-09-01..04` | valid host+port, host without port, invalid port, IPv6 | port 0, 1, 65535, >65535 | host/port parsed with fallback |
| `PF-10` Provider redis options | `CF-10-01..06` | full config, partial config, invalid config, TLS on/off | zero timeout, db boundary, empty addr | resulting options consistent with config |
| `PF-11` Repo key builders | `CF-11-01..03` | valid tenant/code, empty, special characters | empty/minimal strings | canonical and stable key |
| `PF-12` Repo create/update | `CF-12-01..06` | valid entity, duplicate, invalid serialization, redis error, success | required fields nil/empty | persistence or propagated error |
| `PF-13` Repo get/list/ensure | `CF-13-01..05` | found, not found, empty collection, corrupted payload, redis error | empty id, list 0/1/N | return/error according to contract |
| `PF-14` Repo delete | `CF-14-01..04` | existing delete, missing target, redis error, invalid id | empty id | idempotent delete + failures |
| `PF-15` Repo status/version | `CF-15-01..05` | valid status, invalid status, missing user, redis error, success | status transitions | final status/tokenVersion are correct |
| `PF-16` Repo OOB lifecycle | `CF-16-01..06` | save, consume valid, consume expired, mismatched reqType, reuse, store error | TTL 0/positive | single-use + requestType binding |
| `PF-17` Repo coercion/legacy | `CF-17-01..05` | string type, non-string, nil, valid/invalid legacy payload | nil interface, partial map | deterministic coercion/legacy compatibility |
| `PF-18` Service client | `CF-18-01..07` | valid create/get/list, missing client, validation failure, repo error, secret generated | secret length 0/1/N | client business rules respected |
| `PF-19` Service membership | `CF-19-01..06` | valid create/remove/list, missing user, missing tenant, repo error | empty roles | response and effects follow domain rules |
| `PF-20` Service role | `CF-20-01..06` | valid create/list, duplicate role, resolve permissions, repo error | empty/duplicate permissions | canonical permission set |
| `PF-21` Service tenant | `CF-21-01..05` | valid create/get/default, missing tenant, repo error | empty/invalid slug | tenant output according to rules |
| `PF-22` Service user basic auth | `CF-22-01..07` | valid signIn/signUp/lookup, invalid credentials, suspended/inactive user, invalid token | empty email/password | auth and lookup according to SPEC |
| `PF-23` Service user OOB | `CF-23-01..08` | sendOob, sendOobForTenant, signInWithOobCode, resetPassword; invalid/expired/consumed code | non-existent email, mismatched requestType | OOB flow according to SPEC |
| `PF-24` Service user token/JWKS | `CF-24-01..08` | valid/invalid tokenExchange, validate token, JWKS build, key parse fail, claim mismatch | ttl 0/max, empty scopes | strict claims/aud/iss/scope/eventTypes |
| `PF-25` Service user admin ops | `CF-25-01..07` | valid setStatus/revoke/update/delete/getAll, missing user, invalid status/scope | status outside enum | final user state |
| `PF-26` Service helper authorization | `CF-26-01..06` | contains/subset true/false, empty lists, tenant resolve fallback, deref nil | lists 0/1/N | deterministic helpers |
| `PF-27` API key middleware | `CF-27-01..04` | correct key, incorrect key, missing key, expected empty | empty query param | valid requests pass |
| `PF-28` JWT/JWKS utils | `CF-28-01..06` | valid parse/verify, invalid signature, expired, invalid issuer/audience, marshal fail | malformed token | cryptographic validation and claims |
| `PF-29` Config loader | `CF-29-01..05` | valid file, missing file, invalid YAML, missing/default fields, invalid types | empty path | final config or descriptive error |
| `PF-30` SAML AuthnRequest | `CF-30-01..06` | valid request generation, missing IdP config, invalid SP key, deflate encoding, redirect URL construction, request ID format (20-byte hex) | empty tenant ID, nil SP key, IdP without SSO URL | signed redirect URL with SAMLRequest+RelayState+SigAlg+Signature params, request stored in `saml:req:{id}` with 300 s TTL |
| `PF-31` SAML assertion validation | `CF-31-01..12` | step 1 InResponseTo match, step 2 destination equals ACS URL, step 3 status success, step 4 response signature against pinned IdP cert, step 5 decryption of EncryptedAssertion with SP key, step 6 assertion signature, step 7 issuer equals IdP entityID, step 8 audience contains SP entityID, step 9 NotBefore/NotOnOrAfter within 120 s skew, step 10 SubjectConfirmationData Recipient+NotOnOrAfter; missing InResponseTo key, tampered signature | each step fails independently; clock at boundary -121 s / -120 s / +120 s / +121 s | rejection at each failing step with step number in error; acceptance only when all 10 steps pass |
| `PF-32` SAML JIT provisioning | `CF-32-01..05` | first login creates user with `authSource=saml`, second login updates attributes idempotently, membership assigned to tenant from URL path (not assertion), missing NameID rejected, attribute mapping per tenant `attributeMap` | empty email attribute, empty groups | user record created/updated with `tid` from URL, `externalSubject` from NameID; roles mapped from groups |
| `PF-33` SAML replay protection | `CF-33-01..04` | first assertion accepted and `saml:seen:{assertionID}` written with 3600 s TTL, same assertion ID rejected on second submission, expired TTL allows re-use (test with 0-TTL boundary), Redis error propagated | duplicate assertion ID, TTL 0/3600 | acceptance on first use, rejection on replay, error propagated on store failure |
| `PF-34` SAML session and SLO | `CF-34-01..06` | session index stored in `saml:idx:{NameID}` on ACS, SP-initiated logout builds signed LogoutRequest with NameID+SessionIndex, IdP-initiated logout verifies signature and deletes session, missing session index handled, LogoutResponse status verified | empty NameID, missing SessionIndex, invalid LogoutRequest signature | session created on login, deleted on logout, LogoutResponse status checked |
| `PF-35` SAML SP metadata | `CF-35-01..04` | metadata XML contains entityID, ACS URL with HTTP-POST binding, SLO URL, SP signing certificate in X509Certificate element | empty SP cert, missing entityID config | valid XML EntityDescriptor with AssertionConsumerService and SingleLogoutService |
| `PF-36` SAML IdP metadata parsing | `CF-36-01..05` | entityID extracted, SSO URL extracted, signing certificate extracted, attribute mapping defaults applied, invalid XML rejected | missing entityID, missing SSO URL, expired certificate | parsed IdP record with entityID, ssoURL, signingCerts, attributeMap |
| `PF-37` SAML clock skew | `CF-37-01..04` | assertion with NotBefore = now - 119 s accepted, NotBefore = now - 121 s rejected, NotOnOrAfter = now + 119 s accepted, NotOnOrAfter = now + 121 s rejected | boundary at 120 s in both directions | acceptance within 120 s window, rejection outside |

## Full Functional Matrix by Function (133 + SAML)

Legend: `Matrix ID` is the identifier in the test plan. `PF Profile` is the functional profile. `CF Pack` is the case pack instantiated with fake data.

| Function | Matrix ID | PF Profile | CF Pack | Main Functional Rule |
| --- | --- | --- | --- | --- |
| `internal/controllers/admin_guard.go:requireAdmin` | `M-CTRL-ADMIN-GUARD` | `PF-02` | `CF-02-01..05` | 401/403/200 according to ADMIN role |
| `internal/controllers/async_runner.go:runCommandAsync` | `M-CTRL-ASYNC-RUNNER` | `PF-03` | `CF-03-01..03` | Channel returns result or error and closes |
| `internal/controllers/client_controller.go:NewClientController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/client_controller.go:Create` | `M-CTRL-CLIENT-CREATE` | `PF-04` | `CF-04-01..05` | HTTP write with bind+validation+service |
| `internal/controllers/client_controller.go:Get` | `M-CTRL-CLIENT-GET` | `PF-05` | `CF-05-01..05` | HTTP read with parse and response contract |
| `internal/controllers/client_controller.go:List` | `M-CTRL-CLIENT-LIST` | `PF-05` | `CF-05-01..05` | HTTP read with parse and response contract |
| `internal/controllers/delete_controller.go:NewDeleteController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/delete_controller.go:Handle` | `M-CTRL-DELETE-HANDLE` | `PF-07` | `CF-07-01..06` | Admin mutations with status codes |
| `internal/controllers/jwks_controller.go:NewJWKSController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/jwks_controller.go:Handle` | `M-CTRL-JWKS-HANDLE` | `PF-06` | `CF-06-01..07` | Auth/OOB contract according to SPEC |
| `internal/controllers/list_controller.go:NewListController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/list_controller.go:Handle` | `M-CTRL-LIST-HANDLE` | `PF-05` | `CF-05-01..05` | HTTP read with parse and response contract |
| `internal/controllers/lookup_controller.go:NewLookupController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/lookup_controller.go:Handle` | `M-CTRL-LOOKUP-HANDLE` | `PF-06` | `CF-06-01..07` | Auth/OOB contract according to SPEC |
| `internal/controllers/membership_controller.go:NewMembershipController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/membership_controller.go:Create` | `M-CTRL-MEMBERSHIP-CREATE` | `PF-04` | `CF-04-01..05` | HTTP write with bind+validation+service |
| `internal/controllers/membership_controller.go:Remove` | `M-CTRL-MEMBERSHIP-REMOVE` | `PF-07` | `CF-07-01..06` | Admin mutations with status codes |
| `internal/controllers/oob_controller.go:NewOobSendController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/oob_controller.go:NewOobResetController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/oob_controller.go:Handle` | `M-CTRL-OOB-SEND-HANDLE` | `PF-06` | `CF-06-01..07` | Auth/OOB contract according to SPEC |
| `internal/controllers/oob_controller.go:Handle` | `M-CTRL-OOB-RESET-HANDLE` | `PF-06` | `CF-06-01..07` | Auth/OOB contract according to SPEC |
| `internal/controllers/oob_dispatch_controller.go:NewOobDispatchController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/oob_dispatch_controller.go:Handle` | `M-CTRL-OOB-DISPATCH-HANDLE` | `PF-06` | `CF-06-01..07` | Auth/OOB contract according to SPEC |
| `internal/controllers/oob_signin_controller.go:NewOobSignInController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/oob_signin_controller.go:Handle` | `M-CTRL-OOB-SIGNIN-HANDLE` | `PF-06` | `CF-06-01..07` | Auth/OOB contract according to SPEC |
| `internal/controllers/role_controller.go:NewRoleController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/role_controller.go:Create` | `M-CTRL-ROLE-CREATE` | `PF-04` | `CF-04-01..05` | HTTP write with bind+validation+service |
| `internal/controllers/role_controller.go:List` | `M-CTRL-ROLE-LIST` | `PF-05` | `CF-05-01..05` | HTTP read with parse and response contract |
| `internal/controllers/signup_controller.go:NewSignUpController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/signup_controller.go:Handle` | `M-CTRL-SIGNUP-HANDLE` | `PF-06` | `CF-06-01..07` | Auth/OOB contract according to SPEC |
| `internal/controllers/singin_controller.go:NewSignInController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/singin_controller.go:Handle` | `M-CTRL-SIGNIN-HANDLE` | `PF-06` | `CF-06-01..07` | Auth/OOB contract according to SPEC |
| `internal/controllers/tenant_controller.go:NewTenantController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/tenant_controller.go:Create` | `M-CTRL-TENANT-CREATE` | `PF-04` | `CF-04-01..05` | HTTP write with bind+validation+service |
| `internal/controllers/tenant_controller.go:Get` | `M-CTRL-TENANT-GET` | `PF-05` | `CF-05-01..05` | HTTP read with parse and response contract |
| `internal/controllers/token_exchange_controller.go:NewTokenExchangeController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/token_exchange_controller.go:Handle` | `M-CTRL-TOKEN-EXCHANGE-HANDLE` | `PF-06` | `CF-06-01..07` | Auth/OOB contract according to SPEC |
| `internal/controllers/update_controller.go:NewUpdateController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/update_controller.go:Handle` | `M-CTRL-UPDATE-HANDLE` | `PF-07` | `CF-07-01..06` | Admin mutations with status codes |
| `internal/controllers/user_admin_controller.go:NewUserAdminController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/user_admin_controller.go:SetStatus` | `M-CTRL-USER-SETSTATUS` | `PF-07` | `CF-07-01..06` | Admin mutations with status codes |
| `internal/controllers/user_admin_controller.go:Revoke` | `M-CTRL-USER-REVOKE` | `PF-07` | `CF-07-01..06` | Admin mutations with status codes |
| `internal/controllers/validate_controller.go:NewValidateController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/controllers/validate_controller.go:Handle` | `M-CTRL-VALIDATE-HANDLE` | `PF-06` | `CF-06-01..07` | Auth/OOB contract according to SPEC |
| `internal/providers/redis_provider.go:cleanPlaceholder` | `M-PROVIDER-REDIS-cleanPlaceholder` | `PF-08` | `CF-08-01..04` | Deterministic string normalization |
| `internal/providers/redis_provider.go:firstNonEmpty` | `M-PROVIDER-REDIS-firstNonEmpty` | `PF-08` | `CF-08-01..04` | Deterministic string normalization |
| `internal/providers/redis_provider.go:hostPortFromAddr` | `M-PROVIDER-REDIS-hostPortFromAddr` | `PF-09` | `CF-09-01..04` | Host:port parsing with fallback |
| `internal/providers/redis_provider.go:NewRedisProvider` | `M-PROVIDER-REDIS-NewRedisProvider` | `PF-10` | `CF-10-01..06` | Redis options consistent with configuration |
| `internal/providers/redis_provider.go:buildRedisOptions` | `M-PROVIDER-REDIS-buildRedisOptions` | `PF-10` | `CF-10-01..06` | Redis options consistent with configuration |
| `internal/repository/client_repository.go:NewClientRepo` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/repository/client_repository.go:Create` | `M-REPO-CLIENT-Create` | `PF-12` | `CF-12-01..06` | Create/update persistence with propagated errors |
| `internal/repository/client_repository.go:Get` | `M-REPO-CLIENT-Get` | `PF-13` | `CF-13-01..05` | Get/List/Ensure with not-found and success paths |
| `internal/repository/client_repository.go:List` | `M-REPO-CLIENT-List` | `PF-13` | `CF-13-01..05` | Get/List/Ensure with not-found and success paths |
| `internal/repository/client_repository.go:clientsKey` | `M-REPO-CLIENT-clientsKey` | `PF-11` | `CF-11-01..03` | Canonical persistence key |
| `internal/repository/membership_repository.go:NewMembershipRepo` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/repository/membership_repository.go:Create` | `M-REPO-MEMBERSHIP-Create` | `PF-12` | `CF-12-01..06` | Create/update persistence with propagated errors |
| `internal/repository/membership_repository.go:Get` | `M-REPO-MEMBERSHIP-Get` | `PF-13` | `CF-13-01..05` | Get/List/Ensure with not-found and success paths |
| `internal/repository/membership_repository.go:ListTenantIDsByUser` | `M-REPO-MEMBERSHIP-ListTenantIDsByUser` | `PF-13` | `CF-13-01..05` | Get/List/Ensure with not-found and success paths |
| `internal/repository/membership_repository.go:Delete` | `M-REPO-MEMBERSHIP-Delete` | `PF-14` | `CF-14-01..04` | Idempotent delete + failure paths |
| `internal/repository/membership_repository.go:membershipsKey` | `M-REPO-MEMBERSHIP-membershipsKey` | `PF-11` | `CF-11-01..03` | Canonical persistence key |
| `internal/repository/role_repository.go:NewRoleRepo` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/repository/role_repository.go:Create` | `M-REPO-ROLE-Create` | `PF-12` | `CF-12-01..06` | Create/update persistence with propagated errors |
| `internal/repository/role_repository.go:Get` | `M-REPO-ROLE-Get` | `PF-13` | `CF-13-01..05` | Get/List/Ensure with not-found and success paths |
| `internal/repository/role_repository.go:List` | `M-REPO-ROLE-List` | `PF-13` | `CF-13-01..05` | Get/List/Ensure with not-found and success paths |
| `internal/repository/role_repository.go:rolesKey` | `M-REPO-ROLE-rolesKey` | `PF-11` | `CF-11-01..03` | Canonical persistence key |
| `internal/repository/tenant_repository.go:NewTenantRepo` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/repository/tenant_repository.go:Create` | `M-REPO-TENANT-Create` | `PF-12` | `CF-12-01..06` | Create/update persistence with propagated errors |
| `internal/repository/tenant_repository.go:Get` | `M-REPO-TENANT-Get` | `PF-13` | `CF-13-01..05` | Get/List/Ensure with not-found and success paths |
| `internal/repository/tenant_repository.go:EnsureDefault` | `M-REPO-TENANT-EnsureDefault` | `PF-13` | `CF-13-01..05` | Get/List/Ensure with not-found and success paths |
| `internal/repository/user_repository.go:UpdateUser` | `M-REPO-USER-UpdateUser` | `PF-12` | `CF-12-01..06` | Create/update persistence with propagated errors |
| `internal/repository/user_repository.go:DeleteByEmail` | `M-REPO-USER-DeleteByEmail` | `PF-14` | `CF-14-01..04` | Idempotent delete + failure paths |
| `internal/repository/user_repository.go:SetStatus` | `M-REPO-USER-SetStatus` | `PF-15` | `CF-15-01..05` | Status/tokenVersion updated correctly |
| `internal/repository/user_repository.go:IncrementTokenVersion` | `M-REPO-USER-IncrementTokenVersion` | `PF-15` | `CF-15-01..05` | Status/tokenVersion updated correctly |
| `internal/repository/user_repository.go:SaveOobCode` | `M-REPO-USER-SaveOobCode` | `PF-16` | `CF-16-01..06` | OOB single-use + requestType enforcement |
| `internal/repository/user_repository.go:ConsumeOobCode` | `M-REPO-USER-ConsumeOobCode` | `PF-16` | `CF-16-01..06` | OOB single-use + requestType enforcement |
| `internal/repository/user_repository.go:GetAllUsers` | `M-REPO-USER-GetAllUsers` | `PF-13` | `CF-13-01..05` | Get/List/Ensure with not-found and success paths |
| `internal/repository/user_repository.go:oobKey` | `M-REPO-USER-oobKey` | `PF-11` | `CF-11-01..03` | Canonical persistence key |
| `internal/repository/user_repository.go:coerceString` | `M-REPO-USER-coerceString` | `PF-17` | `CF-17-01..05` | Deterministic legacy compatibility |
| `internal/repository/user_repository.go:consumeLegacyOobCode` | `M-REPO-USER-consumeLegacyOobCode` | `PF-17` | `CF-17-01..05` | Deterministic legacy compatibility |
| `internal/repository/user_repository.go:NewRedisRepo` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/repository/user_repository.go:CreateUser` | `M-REPO-USER-CreateUser` | `PF-12` | `CF-12-01..06` | Create/update persistence with propagated errors |
| `internal/repository/user_repository.go:FindByEmail` | `M-REPO-USER-FindByEmail` | `PF-13` | `CF-13-01..05` | Get/List/Ensure with not-found and success paths |
| `internal/services/client_service.go:GetClient` | `M-SVC-CLIENT-GetClient` | `PF-18` | `CF-18-01..07` | Client domain mapping + validations |
| `internal/services/client_service.go:generateSecret` | `M-SVC-CLIENT-generateSecret` | `PF-18` | `CF-18-01..07` | Client domain mapping + validations |
| `internal/services/client_service.go:NewClientService` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/services/client_service.go:Create` | `M-SVC-CLIENT-Create` | `PF-18` | `CF-18-01..07` | Client domain mapping + validations |
| `internal/services/client_service.go:Get` | `M-SVC-CLIENT-Get` | `PF-18` | `CF-18-01..07` | Client domain mapping + validations |
| `internal/services/client_service.go:List` | `M-SVC-CLIENT-List` | `PF-18` | `CF-18-01..07` | Client domain mapping + validations |
| `internal/services/membership_service.go:NewMembershipService` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/services/membership_service.go:Create` | `M-SVC-MEMBERSHIP-Create` | `PF-19` | `CF-19-01..06` | Membership rules and consistency |
| `internal/services/membership_service.go:Remove` | `M-SVC-MEMBERSHIP-Remove` | `PF-19` | `CF-19-01..06` | Membership rules and consistency |
| `internal/services/membership_service.go:ListTenantIDsByUser` | `M-SVC-MEMBERSHIP-ListTenantIDsByUser` | `PF-19` | `CF-19-01..06` | Membership rules and consistency |
| `internal/services/role_service.go:NewRoleService` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/services/role_service.go:Create` | `M-SVC-ROLE-Create` | `PF-20` | `CF-20-01..06` | Role/permission set canonical |
| `internal/services/role_service.go:List` | `M-SVC-ROLE-List` | `PF-20` | `CF-20-01..06` | Role/permission set canonical |
| `internal/services/role_service.go:ResolvePermissions` | `M-SVC-ROLE-ResolvePermissions` | `PF-20` | `CF-20-01..06` | Role/permission set canonical |
| `internal/services/role_service.go:normalizePermissions` | `M-SVC-ROLE-normalizePermissions` | `PF-20` | `CF-20-01..06` | Role/permission set canonical |
| `internal/services/tenant_service.go:NewTenantService` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/services/tenant_service.go:Create` | `M-SVC-TENANT-Create` | `PF-21` | `CF-21-01..05` | Tenant create/get/default according to rules |
| `internal/services/tenant_service.go:Get` | `M-SVC-TENANT-Get` | `PF-21` | `CF-21-01..05` | Tenant create/get/default according to rules |
| `internal/services/tenant_service.go:EnsureDefault` | `M-SVC-TENANT-EnsureDefault` | `PF-21` | `CF-21-01..05` | Tenant create/get/default according to rules |
| `internal/services/user_service.go:SignIn` | `M-SVC-USER-SignIn` | `PF-22` | `CF-22-01..07` | Basic auth and lookup according to SPEC |
| `internal/services/user_service.go:SignInWithOobCode` | `M-SVC-USER-SignInWithOobCode` | `PF-23` | `CF-23-01..08` | OOB email/password flow according to SPEC |
| `internal/services/user_service.go:Lookup` | `M-SVC-USER-Lookup` | `PF-22` | `CF-22-01..07` | Basic auth and lookup according to SPEC |
| `internal/services/user_service.go:TokenExchange` | `M-SVC-USER-TokenExchange` | `PF-24` | `CF-24-01..08` | Tokens/JWKS/claims validated |
| `internal/services/user_service.go:ValidateAccessToken` | `M-SVC-USER-ValidateAccessToken` | `PF-24` | `CF-24-01..08` | Tokens/JWKS/claims validated |
| `internal/services/user_service.go:JWKS` | `M-SVC-USER-JWKS` | `PF-24` | `CF-24-01..08` | Tokens/JWKS/claims validated |
| `internal/services/user_service.go:SetStatus` | `M-SVC-USER-SetStatus` | `PF-25` | `CF-25-01..07` | Admin user operations with audit guarantees |
| `internal/services/user_service.go:RevokeTokens` | `M-SVC-USER-RevokeTokens` | `PF-25` | `CF-25-01..07` | Admin user operations with audit guarantees |
| `internal/services/user_service.go:getRSAPrivateKey` | `M-SVC-USER-getRSAPrivateKey` | `PF-24` | `CF-24-01..08` | Tokens/JWKS/claims validated |
| `internal/services/user_service.go:scopesAllowed` | `M-SVC-USER-scopesAllowed` | `PF-26` | `CF-26-01..06` | Authorization helpers |
| `internal/services/user_service.go:normalizeList` | `M-SVC-USER-normalizeList` | `PF-26` | `CF-26-01..06` | Authorization helpers |
| `internal/services/user_service.go:listTenantIDs` | `M-SVC-USER-listTenantIDs` | `PF-26` | `CF-26-01..06` | Authorization helpers |
| `internal/services/user_service.go:resolveTenantID` | `M-SVC-USER-resolveTenantID` | `PF-26` | `CF-26-01..06` | Authorization helpers |
| `internal/services/user_service.go:containsString` | `M-SVC-USER-containsString` | `PF-26` | `CF-26-01..06` | Authorization helpers |
| `internal/services/user_service.go:subset` | `M-SVC-USER-subset` | `PF-26` | `CF-26-01..06` | Authorization helpers |
| `internal/services/user_service.go:derefString` | `M-SVC-USER-derefString` | `PF-26` | `CF-26-01..06` | Authorization helpers |
| `internal/services/user_service.go:UpdateUser` | `M-SVC-USER-UpdateUser` | `PF-25` | `CF-25-01..07` | Admin user operations with audit guarantees |
| `internal/services/user_service.go:NewUserService` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Valid instance without panic |
| `internal/services/user_service.go:DeleteUser` | `M-SVC-USER-DeleteUser` | `PF-25` | `CF-25-01..07` | Admin user operations with audit guarantees |
| `internal/services/user_service.go:SendOob` | `M-SVC-USER-SendOob` | `PF-23` | `CF-23-01..08` | OOB email/password flow according to SPEC |
| `internal/services/user_service.go:SendOobForTenant` | `M-SVC-USER-SendOobForTenant` | `PF-23` | `CF-23-01..08` | OOB email/password flow according to SPEC |
| `internal/services/user_service.go:ResetPassword` | `M-SVC-USER-ResetPassword` | `PF-23` | `CF-23-01..08` | OOB email/password flow according to SPEC |
| `internal/services/user_service.go:SignUp` | `M-SVC-USER-SignUp` | `PF-22` | `CF-22-01..07` | Basic auth and lookup according to SPEC |
| `internal/services/user_service.go:GetAllUsers` | `M-SVC-USER-GetAllUsers` | `PF-25` | `CF-25-01..07` | Admin user operations with audit guarantees |
| `internal/services/user_service.go:issueIDToken` | `M-SVC-USER-issueIDToken` | `PF-24` | `CF-24-01..08` | Tokens/JWKS/claims validated |
| `internal/utils/api_key.go:ApiKey` | `M-UTIL-APIKEY` | `PF-27` | `CF-27-01..04` | API key middleware accepts/rejects |
| `internal/utils/jwks.go:BuildJWKS` | `M-UTIL-JWKS-BuildJWKS` | `PF-28` | `CF-28-01..06` | JWT/JWKS parse+verify with errors |
| `internal/utils/jwks.go:Marshal` | `M-UTIL-JWKS-Marshal` | `PF-28` | `CF-28-01..06` | JWT/JWKS parse+verify with errors |
| `internal/utils/jwt.go:ParseRSAPrivateKey` | `M-UTIL-PARSERSA` | `PF-28` | `CF-28-01..06` | JWT/JWKS parse+verify with errors |
| `internal/utils/jwt_verify.go:ValidateRS256` | `M-UTIL-VALIDATERS256` | `PF-28` | `CF-28-01..06` | JWT/JWKS parse+verify with errors |
| `internal/utils/utils.go:ParseToken` | `M-UTIL-PARSETOKEN` | `PF-28` | `CF-28-01..06` | JWT/JWKS parse+verify with errors |
| `pkg/config/config.go:LoadConfig` | `M-CONFIG-LOAD` | `PF-29` | `CF-29-01..05` | YAML config loaded with defaults/errors |
| `internal/saml/authn_request.go:BuildAuthnRequest` | `M-SAML-AUTHN-BUILD` | `PF-30` | `CF-30-01..06` | Signed AuthnRequest with deflate+base64 redirect URL |
| `internal/saml/authn_request.go:GenerateRequestID` | `M-SAML-AUTHN-GENID` | `PF-30` | `CF-30-01..06` | 20-byte hex request ID |
| `internal/saml/validator.go:ValidateResponse` | `M-SAML-VALIDATE-RESPONSE` | `PF-31` | `CF-31-01..12` | 10-step validation pipeline, first failure rejects |
| `internal/saml/validator.go:ValidateTimeBounds` | `M-SAML-VALIDATE-TIME` | `PF-37` | `CF-37-01..04` | Accept within 120 s skew, reject outside |
| `internal/saml/jit.go:ProvisionUser` | `M-SAML-JIT-PROVISION` | `PF-32` | `CF-32-01..05` | Create on first login, update on subsequent, assign to tenant from URL |
| `internal/saml/replay.go:CheckReplay` | `M-SAML-REPLAY-CHECK` | `PF-33` | `CF-33-01..04` | Write `saml:seen:{assertionID}` with 3600 s TTL, reject duplicates |
| `internal/saml/session.go:StoreSessionIndex` | `M-SAML-SESSION-STORE` | `PF-34` | `CF-34-01..06` | Write `saml:idx:{NameID}` on ACS |
| `internal/saml/session.go:ProcessLogout` | `M-SAML-SESSION-LOGOUT` | `PF-34` | `CF-34-01..06` | Delete session on SP-initiated or IdP-initiated SLO |
| `internal/saml/metadata.go:GenerateSPMetadata` | `M-SAML-META-SP` | `PF-35` | `CF-35-01..04` | EntityDescriptor XML with ACS+SLO+certificate |
| `internal/saml/metadata.go:ParseIdPMetadata` | `M-SAML-META-IDP` | `PF-36` | `CF-36-01..05` | Extract entityID, ssoURL, signingCerts, attributeMap |

## Assertion Rules

Every assertion must validate output from a functional requirement (SPEC or contract), not control flow alone. For each alternative CFG path, there must be an explicit functional oracle (error, code, message, or state). Structural coverage is accepted only when accompanied by functional output validation. Cases that execute lines without validating business semantics must be removed.

## Acceptance Criteria

The unit phase is accepted when 100% of functions in scope have at least one functional success case and the relevant failure cases. Each function must reach 85% executable-path coverage measured with structural coverage instrumentation. No case may contain empty or tautological assertions. All cases must use identified test data from the equivalence class and boundary analysis.
