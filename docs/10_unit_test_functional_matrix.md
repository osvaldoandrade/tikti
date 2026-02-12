# 10 Unit Functional Test Matrix (All Functions)

## Objetivo

Definir uma matriz funcional exaustiva para testes de unidade do Tikti, cobrindo **todas as funcoes** (exceto `bootstrap/main`), com:

- tecnica funcional (caixa preta) como criterio primario de validacao;
- tecnica estrutural (CFG) como metrica complementar de qualidade;
- meta minima de **>=85% de cobertura de caminhos executaveis por funcao**.

## Escopo

- Incluidas: `internal/controllers`, `internal/services`, `internal/repository`, `internal/providers`, `internal/utils`, `pkg/config`.
- Excluidas: funcoes de bootstrap/main em `internal/app` e `cmd/tikti/main.go`.
- Total mapeado: **133 funcoes**.

## Metodo (funcional + estrutural)

Para cada funcao:

1. Modelar o grafo de fluxo de controle (CFG) e enumerar caminhos independentes (base path set).
2. Derivar classes de equivalencia e limites de entrada a partir da SPEC/contrato funcional.
3. Mapear cada caminho relevante para um caso funcional (entrada -> saida esperada/oraculo).
4. Cobrir todos os caminhos criticos e garantir >=85% de caminhos executaveis.
5. Bloquear asserts sem oraculo (ex.: `assert.True(true)` sem semantica de negocio).

## Dados fake canonicos

- Emails: `valid.user@acme.test`, `unknown@acme.test`, `admin@acme.test`.
- Senhas: `P@ssw0rd!`, `wrong-pass`, `new-pass-123`.
- Tenant IDs: `tenant-1`, `tenant-404`, `tenant-other`.
- Roles: `ADMIN`, `COMPANY_ADMIN`, `COMPANY_EMPLOYEE`, `TENANT_USER`.
- Scopes: `codeq:claim`, `codeq:heartbeat`, `codeq:result`, `codeq:admin`.
- OOB: codigos validos, expirados, consumidos e de `requestType` divergente.
- Tokens: JWT valido, expirado, assinatura invalida, audience/issuer invalidos.

## Perfis funcionais (PF) e pacotes de casos (CF)

| PF | Pacote CF | Particoes funcionais (caixa preta) | Limites principais | Oraculo funcional |
| --- | --- | --- | --- | --- |
| `PF-01` Constructors/factories | `CF-01-01..03` | dependencias validas, nil parcial, nil total | nil vs non-nil em deps | instancia nao nula, sem panic, wiring consistente |
| `PF-02` Admin guard controller | `CF-02-01..05` | sem token, token invalido, role nao-admin, role admin | header vazio, `Bearer`/raw token | `401/403/200` conforme regra ADMIN |
| `PF-03` Async wrapper | `CF-03-01..03` | callback sucesso, callback erro, concorrencia | retorno imediato do channel | channel fecha, entrega resultado/erro correto |
| `PF-04` HTTP create mutation | `CF-04-01..05` | payload valido, JSON invalido, erro de validacao, erro service, sucesso | campos obrigatorios vazios | status code e payload de erro/sucesso conforme contrato |
| `PF-05` HTTP read/list | `CF-05-01..05` | params validos, params invalidos, not found, erro service, sucesso | query/path vazio/ausente | shape de resposta e codigos corretos |
| `PF-06` HTTP auth/oob contract | `CF-06-01..07` | request valida, credencial invalida, token invalido, OOB invalido/expirado, sucesso | email vazio, oob vazio | respostas batem SPEC de auth/OOB |
| `PF-07` HTTP admin mutation | `CF-07-01..06` | autorizado/nao autorizado, payload invalido, erro de dominio, sucesso | status invalido, scope invalido | mutacoes com semantica e codigos corretos |
| `PF-08` Provider string helpers | `CF-08-01..04` | string normal, placeholder, vazia, somente espacos | `""`, whitespace, placeholder token | normalizacao deterministica esperada |
| `PF-09` Provider host:port parser | `CF-09-01..04` | host+porta validos, host sem porta, porta invalida, IPv6 | porta 0, 1, 65535, >65535 | host/porta parseados com fallback seguro |
| `PF-10` Provider redis options | `CF-10-01..06` | cfg completa, cfg parcial, cfg invalida, TLS on/off | timeout zero, db limite, addr vazia | opcoes resultantes coerentes com config |
| `PF-11` Repo key builders | `CF-11-01..03` | tenant/code valido, vazio, caracteres especiais | strings vazias/minimas | chave canonical e estavel |
| `PF-12` Repo create/update | `CF-12-01..06` | entidade valida, duplicata, serializacao invalida, erro redis, sucesso | campos obrigatorios nil/vazios | persistencia correta ou erro propagado |
| `PF-13` Repo get/list/ensure | `CF-13-01..05` | encontrado, nao encontrado, colecao vazia, payload corrompido, erro redis | id vazio, lista 0/1/N | retorno/erro conforme contrato |
| `PF-14` Repo delete | `CF-14-01..04` | delete existente, inexistente, erro redis, id invalido | id vazio | delete idempotente + falhas coerentes |
| `PF-15` Repo status/version | `CF-15-01..05` | status valido, status invalido, usuario ausente, erro redis, sucesso | transicoes de status | status/tokenVersion finais corretos |
| `PF-16` Repo OOB lifecycle | `CF-16-01..06` | salvar, consumir valido, consumir expirado, reqType divergente, reutilizacao, erro store | TTL 0/positivo | single-use + binding por requestType |
| `PF-17` Repo coercion/legacy | `CF-17-01..05` | tipo string, nao-string, nil, payload legado valido/invalido | nil interface, mapa parcial | coercao/compat legado deterministicas |
| `PF-18` Service client | `CF-18-01..07` | create/get/list validos, client inexistente, validacao falha, erro repo, segredo gerado | tamanho segredo 0/1/N | regra de negocio de cliente respeitada |
| `PF-19` Service membership | `CF-19-01..06` | create/remove/list validos, usuario ausente, tenant ausente, erro repo | roles vazias | resposta e efeitos conforme dominio |
| `PF-20` Service role | `CF-20-01..06` | create/list validos, role duplicada, resolve permissions, erro repo | permissoes vazias/duplicadas | conjunto de permissoes canonical |
| `PF-21` Service tenant | `CF-21-01..05` | create/get/default validos, tenant inexistente, erro repo | slug vazio/invalido | tenant output conforme regra |
| `PF-22` Service user auth basico | `CF-22-01..07` | signIn/signUp/lookup validos, credencial invalida, usuario suspenso/inativo, token invalido | email/senha vazios | auth e lookup conforme SPEC |
| `PF-23` Service user OOB | `CF-23-01..08` | sendOob, sendOobForTenant, signInWithOobCode, resetPassword; codigo invalido/expirado/consumido | email inexistente, requestType divergente | fluxo OOB funcional conforme SPEC |
| `PF-24` Service user token/JWKS | `CF-24-01..08` | tokenExchange valido/invalido, validate token, JWKS build, key parse fail, claim mismatch | ttl 0/max, scopes vazios | claims/aud/iss/scope/eventTypes estritos |
| `PF-25` Service user admin ops | `CF-25-01..07` | setStatus/revoke/update/delete/getAll validos, usuario ausente, status/scope invalidos | status fora enum | estado final de usuario correto |
| `PF-26` Service helper authorization | `CF-26-01..06` | contains/subset true/false, listas vazias, tenant resolve fallback, deref nil | listas 0/1/N | auxiliares deterministas e sem ambiguidade |
| `PF-27` API key middleware | `CF-27-01..04` | key correta, incorreta, ausente, esperada vazia | query param vazio | somente requests validas passam |
| `PF-28` JWT/JWKS utils | `CF-28-01..06` | parse/verify validos, assinatura invalida, expirado, issuer/audience invalidos, marshal fail | token malformado | validacao criptografica e claims corretas |
| `PF-29` Config loader | `CF-29-01..05` | arquivo valido, inexistente, YAML invalido, campos faltantes/default, tipos invalidos | path vazio | config final ou erro descritivo coerente |

## Matriz funcional completa por funcao (133)

Legenda:

- `ID Matriz`: identificador unico da funcao no plano de testes.
- `Perfil PF`: pacote funcional aplicavel.
- `Pacote CF`: conjunto de casos funcionais que deve ser instanciado com dados fake para a funcao.

| Funcao | ID Matriz | Perfil PF | Pacote CF | Regra funcional principal |
| --- | --- | --- | --- | --- |
| `internal/controllers/admin_guard.go:requireAdmin` | `M-CTRL-ADMIN-GUARD` | `PF-02` | `CF-02-01..05` | 401/403/200 conforme role ADMIN |
| `internal/controllers/async_runner.go:runCommandAsync` | `M-CTRL-ASYNC-RUNNER` | `PF-03` | `CF-03-01..03` | Canal entrega resultado ou erro e fecha |
| `internal/controllers/client_controller.go:NewClientController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/client_controller.go:Create` | `M-CTRL-CLIENT-CREATE` | `PF-04` | `CF-04-01..05` | HTTP write com bind+validacao+service |
| `internal/controllers/client_controller.go:Get` | `M-CTRL-CLIENT-GET` | `PF-05` | `CF-05-01..05` | HTTP read com parse e contrato de resposta |
| `internal/controllers/client_controller.go:List` | `M-CTRL-CLIENT-LIST` | `PF-05` | `CF-05-01..05` | HTTP read com parse e contrato de resposta |
| `internal/controllers/delete_controller.go:NewDeleteController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/delete_controller.go:Handle` | `M-CTRL-DELETE-HANDLE` | `PF-07` | `CF-07-01..06` | Mutacoes admin com codigos corretos |
| `internal/controllers/jwks_controller.go:NewJWKSController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/jwks_controller.go:Handle` | `M-CTRL-JWKS-HANDLE` | `PF-06` | `CF-06-01..07` | Contrato auth/OOB conforme SPEC |
| `internal/controllers/list_controller.go:NewListController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/list_controller.go:Handle` | `M-CTRL-LIST-HANDLE` | `PF-05` | `CF-05-01..05` | HTTP read com parse e contrato de resposta |
| `internal/controllers/lookup_controller.go:NewLookupController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/lookup_controller.go:Handle` | `M-CTRL-LOOKUP-HANDLE` | `PF-06` | `CF-06-01..07` | Contrato auth/OOB conforme SPEC |
| `internal/controllers/membership_controller.go:NewMembershipController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/membership_controller.go:Create` | `M-CTRL-MEMBERSHIP-CREATE` | `PF-04` | `CF-04-01..05` | HTTP write com bind+validacao+service |
| `internal/controllers/membership_controller.go:Remove` | `M-CTRL-MEMBERSHIP-REMOVE` | `PF-07` | `CF-07-01..06` | Mutacoes admin com codigos corretos |
| `internal/controllers/oob_controller.go:NewOobSendController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/oob_controller.go:NewOobResetController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/oob_controller.go:Handle` | `M-CTRL-OOB-SEND-HANDLE` | `PF-06` | `CF-06-01..07` | Contrato auth/OOB conforme SPEC |
| `internal/controllers/oob_controller.go:Handle` | `M-CTRL-OOB-RESET-HANDLE` | `PF-06` | `CF-06-01..07` | Contrato auth/OOB conforme SPEC |
| `internal/controllers/oob_dispatch_controller.go:NewOobDispatchController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/oob_dispatch_controller.go:Handle` | `M-CTRL-OOB-DISPATCH-HANDLE` | `PF-06` | `CF-06-01..07` | Contrato auth/OOB conforme SPEC |
| `internal/controllers/oob_signin_controller.go:NewOobSignInController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/oob_signin_controller.go:Handle` | `M-CTRL-OOB-SIGNIN-HANDLE` | `PF-06` | `CF-06-01..07` | Contrato auth/OOB conforme SPEC |
| `internal/controllers/role_controller.go:NewRoleController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/role_controller.go:Create` | `M-CTRL-ROLE-CREATE` | `PF-04` | `CF-04-01..05` | HTTP write com bind+validacao+service |
| `internal/controllers/role_controller.go:List` | `M-CTRL-ROLE-LIST` | `PF-05` | `CF-05-01..05` | HTTP read com parse e contrato de resposta |
| `internal/controllers/signup_controller.go:NewSignUpController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/signup_controller.go:Handle` | `M-CTRL-SIGNUP-HANDLE` | `PF-06` | `CF-06-01..07` | Contrato auth/OOB conforme SPEC |
| `internal/controllers/singin_controller.go:NewSignInController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/singin_controller.go:Handle` | `M-CTRL-SIGNIN-HANDLE` | `PF-06` | `CF-06-01..07` | Contrato auth/OOB conforme SPEC |
| `internal/controllers/tenant_controller.go:NewTenantController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/tenant_controller.go:Create` | `M-CTRL-TENANT-CREATE` | `PF-04` | `CF-04-01..05` | HTTP write com bind+validacao+service |
| `internal/controllers/tenant_controller.go:Get` | `M-CTRL-TENANT-GET` | `PF-05` | `CF-05-01..05` | HTTP read com parse e contrato de resposta |
| `internal/controllers/token_exchange_controller.go:NewTokenExchangeController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/token_exchange_controller.go:Handle` | `M-CTRL-TOKEN-EXCHANGE-HANDLE` | `PF-06` | `CF-06-01..07` | Contrato auth/OOB conforme SPEC |
| `internal/controllers/update_controller.go:NewUpdateController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/update_controller.go:Handle` | `M-CTRL-UPDATE-HANDLE` | `PF-07` | `CF-07-01..06` | Mutacoes admin com codigos corretos |
| `internal/controllers/user_admin_controller.go:NewUserAdminController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/user_admin_controller.go:SetStatus` | `M-CTRL-USER-SETSTATUS` | `PF-07` | `CF-07-01..06` | Mutacoes admin com codigos corretos |
| `internal/controllers/user_admin_controller.go:Revoke` | `M-CTRL-USER-REVOKE` | `PF-07` | `CF-07-01..06` | Mutacoes admin com codigos corretos |
| `internal/controllers/validate_controller.go:NewValidateController` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/controllers/validate_controller.go:Handle` | `M-CTRL-VALIDATE-HANDLE` | `PF-06` | `CF-06-01..07` | Contrato auth/OOB conforme SPEC |
| `internal/providers/redis_provider.go:cleanPlaceholder` | `M-PROVIDER-REDIS-cleanPlaceholder` | `PF-08` | `CF-08-01..04` | Normalizacao deterministica de strings |
| `internal/providers/redis_provider.go:firstNonEmpty` | `M-PROVIDER-REDIS-firstNonEmpty` | `PF-08` | `CF-08-01..04` | Normalizacao deterministica de strings |
| `internal/providers/redis_provider.go:hostPortFromAddr` | `M-PROVIDER-REDIS-hostPortFromAddr` | `PF-09` | `CF-09-01..04` | Split host:porta com fallback seguro |
| `internal/providers/redis_provider.go:NewRedisProvider` | `M-PROVIDER-REDIS-NewRedisProvider` | `PF-10` | `CF-10-01..06` | Opcoes Redis coerentes com configuracao |
| `internal/providers/redis_provider.go:buildRedisOptions` | `M-PROVIDER-REDIS-buildRedisOptions` | `PF-10` | `CF-10-01..06` | Opcoes Redis coerentes com configuracao |
| `internal/repository/client_repository.go:NewClientRepo` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/repository/client_repository.go:Create` | `M-REPO-CLIENT-Create` | `PF-12` | `CF-12-01..06` | Persistencia create/update com erro propagado |
| `internal/repository/client_repository.go:Get` | `M-REPO-CLIENT-Get` | `PF-13` | `CF-13-01..05` | Get/List/Ensure com not-found e sucesso |
| `internal/repository/client_repository.go:List` | `M-REPO-CLIENT-List` | `PF-13` | `CF-13-01..05` | Get/List/Ensure com not-found e sucesso |
| `internal/repository/client_repository.go:clientsKey` | `M-REPO-CLIENT-clientsKey` | `PF-11` | `CF-11-01..03` | Chave persistencia canonical |
| `internal/repository/membership_repository.go:NewMembershipRepo` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/repository/membership_repository.go:Create` | `M-REPO-MEMBERSHIP-Create` | `PF-12` | `CF-12-01..06` | Persistencia create/update com erro propagado |
| `internal/repository/membership_repository.go:Get` | `M-REPO-MEMBERSHIP-Get` | `PF-13` | `CF-13-01..05` | Get/List/Ensure com not-found e sucesso |
| `internal/repository/membership_repository.go:ListTenantIDsByUser` | `M-REPO-MEMBERSHIP-ListTenantIDsByUser` | `PF-13` | `CF-13-01..05` | Get/List/Ensure com not-found e sucesso |
| `internal/repository/membership_repository.go:Delete` | `M-REPO-MEMBERSHIP-Delete` | `PF-14` | `CF-14-01..04` | Delete idempotente + falhas |
| `internal/repository/membership_repository.go:membershipsKey` | `M-REPO-MEMBERSHIP-membershipsKey` | `PF-11` | `CF-11-01..03` | Chave persistencia canonical |
| `internal/repository/role_repository.go:NewRoleRepo` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/repository/role_repository.go:Create` | `M-REPO-ROLE-Create` | `PF-12` | `CF-12-01..06` | Persistencia create/update com erro propagado |
| `internal/repository/role_repository.go:Get` | `M-REPO-ROLE-Get` | `PF-13` | `CF-13-01..05` | Get/List/Ensure com not-found e sucesso |
| `internal/repository/role_repository.go:List` | `M-REPO-ROLE-List` | `PF-13` | `CF-13-01..05` | Get/List/Ensure com not-found e sucesso |
| `internal/repository/role_repository.go:rolesKey` | `M-REPO-ROLE-rolesKey` | `PF-11` | `CF-11-01..03` | Chave persistencia canonical |
| `internal/repository/tenant_repository.go:NewTenantRepo` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/repository/tenant_repository.go:Create` | `M-REPO-TENANT-Create` | `PF-12` | `CF-12-01..06` | Persistencia create/update com erro propagado |
| `internal/repository/tenant_repository.go:Get` | `M-REPO-TENANT-Get` | `PF-13` | `CF-13-01..05` | Get/List/Ensure com not-found e sucesso |
| `internal/repository/tenant_repository.go:EnsureDefault` | `M-REPO-TENANT-EnsureDefault` | `PF-13` | `CF-13-01..05` | Get/List/Ensure com not-found e sucesso |
| `internal/repository/user_repository.go:UpdateUser` | `M-REPO-USER-UpdateUser` | `PF-12` | `CF-12-01..06` | Persistencia create/update com erro propagado |
| `internal/repository/user_repository.go:DeleteByEmail` | `M-REPO-USER-DeleteByEmail` | `PF-14` | `CF-14-01..04` | Delete idempotente + falhas |
| `internal/repository/user_repository.go:SetStatus` | `M-REPO-USER-SetStatus` | `PF-15` | `CF-15-01..05` | Status/tokenVersion atualizados corretamente |
| `internal/repository/user_repository.go:IncrementTokenVersion` | `M-REPO-USER-IncrementTokenVersion` | `PF-15` | `CF-15-01..05` | Status/tokenVersion atualizados corretamente |
| `internal/repository/user_repository.go:SaveOobCode` | `M-REPO-USER-SaveOobCode` | `PF-16` | `CF-16-01..06` | OOB single-use + requestType enforcement |
| `internal/repository/user_repository.go:ConsumeOobCode` | `M-REPO-USER-ConsumeOobCode` | `PF-16` | `CF-16-01..06` | OOB single-use + requestType enforcement |
| `internal/repository/user_repository.go:GetAllUsers` | `M-REPO-USER-GetAllUsers` | `PF-13` | `CF-13-01..05` | Get/List/Ensure com not-found e sucesso |
| `internal/repository/user_repository.go:oobKey` | `M-REPO-USER-oobKey` | `PF-11` | `CF-11-01..03` | Chave persistencia canonical |
| `internal/repository/user_repository.go:coerceString` | `M-REPO-USER-coerceString` | `PF-17` | `CF-17-01..05` | Compat legacy deterministica |
| `internal/repository/user_repository.go:consumeLegacyOobCode` | `M-REPO-USER-consumeLegacyOobCode` | `PF-17` | `CF-17-01..05` | Compat legacy deterministica |
| `internal/repository/user_repository.go:NewRedisRepo` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/repository/user_repository.go:CreateUser` | `M-REPO-USER-CreateUser` | `PF-12` | `CF-12-01..06` | Persistencia create/update com erro propagado |
| `internal/repository/user_repository.go:FindByEmail` | `M-REPO-USER-FindByEmail` | `PF-13` | `CF-13-01..05` | Get/List/Ensure com not-found e sucesso |
| `internal/services/client_service.go:GetClient` | `M-SVC-CLIENT-GetClient` | `PF-18` | `CF-18-01..07` | Client domain mapping + validacoes |
| `internal/services/client_service.go:generateSecret` | `M-SVC-CLIENT-generateSecret` | `PF-18` | `CF-18-01..07` | Client domain mapping + validacoes |
| `internal/services/client_service.go:NewClientService` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/services/client_service.go:Create` | `M-SVC-CLIENT-Create` | `PF-18` | `CF-18-01..07` | Client domain mapping + validacoes |
| `internal/services/client_service.go:Get` | `M-SVC-CLIENT-Get` | `PF-18` | `CF-18-01..07` | Client domain mapping + validacoes |
| `internal/services/client_service.go:List` | `M-SVC-CLIENT-List` | `PF-18` | `CF-18-01..07` | Client domain mapping + validacoes |
| `internal/services/membership_service.go:NewMembershipService` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/services/membership_service.go:Create` | `M-SVC-MEMBERSHIP-Create` | `PF-19` | `CF-19-01..06` | Membership rules e consistencia |
| `internal/services/membership_service.go:Remove` | `M-SVC-MEMBERSHIP-Remove` | `PF-19` | `CF-19-01..06` | Membership rules e consistencia |
| `internal/services/membership_service.go:ListTenantIDsByUser` | `M-SVC-MEMBERSHIP-ListTenantIDsByUser` | `PF-19` | `CF-19-01..06` | Membership rules e consistencia |
| `internal/services/role_service.go:NewRoleService` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/services/role_service.go:Create` | `M-SVC-ROLE-Create` | `PF-20` | `CF-20-01..06` | Role/permission set canonical |
| `internal/services/role_service.go:List` | `M-SVC-ROLE-List` | `PF-20` | `CF-20-01..06` | Role/permission set canonical |
| `internal/services/role_service.go:ResolvePermissions` | `M-SVC-ROLE-ResolvePermissions` | `PF-20` | `CF-20-01..06` | Role/permission set canonical |
| `internal/services/role_service.go:normalizePermissions` | `M-SVC-ROLE-normalizePermissions` | `PF-20` | `CF-20-01..06` | Role/permission set canonical |
| `internal/services/tenant_service.go:NewTenantService` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/services/tenant_service.go:Create` | `M-SVC-TENANT-Create` | `PF-21` | `CF-21-01..05` | Tenant create/get/default conforme regra |
| `internal/services/tenant_service.go:Get` | `M-SVC-TENANT-Get` | `PF-21` | `CF-21-01..05` | Tenant create/get/default conforme regra |
| `internal/services/tenant_service.go:EnsureDefault` | `M-SVC-TENANT-EnsureDefault` | `PF-21` | `CF-21-01..05` | Tenant create/get/default conforme regra |
| `internal/services/user_service.go:SignIn` | `M-SVC-USER-SignIn` | `PF-22` | `CF-22-01..07` | Auth basica e lookup conforme SPEC |
| `internal/services/user_service.go:SignInWithOobCode` | `M-SVC-USER-SignInWithOobCode` | `PF-23` | `CF-23-01..08` | Fluxo OOB email/password conforme SPEC |
| `internal/services/user_service.go:Lookup` | `M-SVC-USER-Lookup` | `PF-22` | `CF-22-01..07` | Auth basica e lookup conforme SPEC |
| `internal/services/user_service.go:TokenExchange` | `M-SVC-USER-TokenExchange` | `PF-24` | `CF-24-01..08` | Tokens/JWKS/claims estritamente validos |
| `internal/services/user_service.go:ValidateAccessToken` | `M-SVC-USER-ValidateAccessToken` | `PF-24` | `CF-24-01..08` | Tokens/JWKS/claims estritamente validos |
| `internal/services/user_service.go:JWKS` | `M-SVC-USER-JWKS` | `PF-24` | `CF-24-01..08` | Tokens/JWKS/claims estritamente validos |
| `internal/services/user_service.go:SetStatus` | `M-SVC-USER-SetStatus` | `PF-25` | `CF-25-01..07` | Operacoes admin de usuario com auditoria |
| `internal/services/user_service.go:RevokeTokens` | `M-SVC-USER-RevokeTokens` | `PF-25` | `CF-25-01..07` | Operacoes admin de usuario com auditoria |
| `internal/services/user_service.go:getRSAPrivateKey` | `M-SVC-USER-getRSAPrivateKey` | `PF-24` | `CF-24-01..08` | Tokens/JWKS/claims estritamente validos |
| `internal/services/user_service.go:scopesAllowed` | `M-SVC-USER-scopesAllowed` | `PF-26` | `CF-26-01..06` | Helpers de autorizacao sem ambiguidades |
| `internal/services/user_service.go:normalizeList` | `M-SVC-USER-normalizeList` | `PF-26` | `CF-26-01..06` | Helpers de autorizacao sem ambiguidades |
| `internal/services/user_service.go:listTenantIDs` | `M-SVC-USER-listTenantIDs` | `PF-26` | `CF-26-01..06` | Helpers de autorizacao sem ambiguidades |
| `internal/services/user_service.go:resolveTenantID` | `M-SVC-USER-resolveTenantID` | `PF-26` | `CF-26-01..06` | Helpers de autorizacao sem ambiguidades |
| `internal/services/user_service.go:containsString` | `M-SVC-USER-containsString` | `PF-26` | `CF-26-01..06` | Helpers de autorizacao sem ambiguidades |
| `internal/services/user_service.go:subset` | `M-SVC-USER-subset` | `PF-26` | `CF-26-01..06` | Helpers de autorizacao sem ambiguidades |
| `internal/services/user_service.go:derefString` | `M-SVC-USER-derefString` | `PF-26` | `CF-26-01..06` | Helpers de autorizacao sem ambiguidades |
| `internal/services/user_service.go:UpdateUser` | `M-SVC-USER-UpdateUser` | `PF-25` | `CF-25-01..07` | Operacoes admin de usuario com auditoria |
| `internal/services/user_service.go:NewUserService` | `M-CTOR` | `PF-01` | `CF-01-01..03` | Instancia valida sem panic |
| `internal/services/user_service.go:DeleteUser` | `M-SVC-USER-DeleteUser` | `PF-25` | `CF-25-01..07` | Operacoes admin de usuario com auditoria |
| `internal/services/user_service.go:SendOob` | `M-SVC-USER-SendOob` | `PF-23` | `CF-23-01..08` | Fluxo OOB email/password conforme SPEC |
| `internal/services/user_service.go:SendOobForTenant` | `M-SVC-USER-SendOobForTenant` | `PF-23` | `CF-23-01..08` | Fluxo OOB email/password conforme SPEC |
| `internal/services/user_service.go:ResetPassword` | `M-SVC-USER-ResetPassword` | `PF-23` | `CF-23-01..08` | Fluxo OOB email/password conforme SPEC |
| `internal/services/user_service.go:SignUp` | `M-SVC-USER-SignUp` | `PF-22` | `CF-22-01..07` | Auth basica e lookup conforme SPEC |
| `internal/services/user_service.go:GetAllUsers` | `M-SVC-USER-GetAllUsers` | `PF-25` | `CF-25-01..07` | Operacoes admin de usuario com auditoria |
| `internal/services/user_service.go:issueIDToken` | `M-SVC-USER-issueIDToken` | `PF-24` | `CF-24-01..08` | Tokens/JWKS/claims estritamente validos |
| `internal/utils/api_key.go:ApiKey` | `M-UTIL-APIKEY` | `PF-27` | `CF-27-01..04` | API key middleware aceita/rejeita corretamente |
| `internal/utils/jwks.go:BuildJWKS` | `M-UTIL-JWKS-BuildJWKS` | `PF-28` | `CF-28-01..06` | JWT/JWKS parse+verify com erros claros |
| `internal/utils/jwks.go:Marshal` | `M-UTIL-JWKS-Marshal` | `PF-28` | `CF-28-01..06` | JWT/JWKS parse+verify com erros claros |
| `internal/utils/jwt.go:ParseRSAPrivateKey` | `M-UTIL-PARSERSA` | `PF-28` | `CF-28-01..06` | JWT/JWKS parse+verify com erros claros |
| `internal/utils/jwt_verify.go:ValidateRS256` | `M-UTIL-VALIDATERS256` | `PF-28` | `CF-28-01..06` | JWT/JWKS parse+verify com erros claros |
| `internal/utils/utils.go:ParseToken` | `M-UTIL-PARSETOKEN` | `PF-28` | `CF-28-01..06` | JWT/JWKS parse+verify com erros claros |
| `pkg/config/config.go:LoadConfig` | `M-CONFIG-LOAD` | `PF-29` | `CF-29-01..05` | Config YAML carregada com defaults/erros |

## Regras obrigatorias de assertiva (qualidade)

1. Toda assertiva deve validar resultado esperado por requisito funcional (SPEC/contrato), nunca apenas fluxo.
2. Para cada caminho alternativo do CFG, deve existir um oraculo funcional explicito (erro/codigo/mensagem/estado).
3. Cobertura estrutural so e aceita quando acompanhada de validacao funcional de saida.
4. Casos que apenas executam linhas sem validar semantica de negocio devem ser removidos.

## Criterios de aceite da fase de unidade

- 100% das funcoes no escopo com ao menos 1 caso funcional de sucesso e casos funcionais de falha relevantes.
- >=85% de caminhos executaveis por funcao, medidos por instrumentacao de cobertura estrutural.
- Nenhum caso com assertiva vazia ou tautologica.
- Todos os casos com dados de teste explicitamente identificados (classe de equivalencia e limite).
