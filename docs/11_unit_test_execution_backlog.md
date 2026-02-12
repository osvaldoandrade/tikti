# 11 Unit Test Execution Backlog

## Objetivo

Converter a matriz funcional (`10_unit_test_functional_matrix.md`) em plano de execucao de testes de unidade, com foco em risco de negocio, seguranca e cobertura estrutural.

## Criterios globais

- Base obrigatoria: tecnica funcional (caixa preta) orientada a SPEC.
- Complemento: tecnica estrutural (CFG) para elevar qualidade.
- Meta minima por funcao: >=85% dos caminhos executaveis.
- Proibido: assertiva sem oraculo funcional de negocio.
- Regra de granularidade: unidade = funcao; interacao entre funcoes entra em integracao.

## Ordem de execucao (por risco)

### Fase 1 - Critico (auth e seguranca)

Pacotes:

- `PF-22` (`M-SVC-USER-SignIn`, `M-SVC-USER-SignUp`, `M-SVC-USER-Lookup`)
- `PF-23` (`M-SVC-USER-SendOob`, `M-SVC-USER-SendOobForTenant`, `M-SVC-USER-SignInWithOobCode`, `M-SVC-USER-ResetPassword`)
- `PF-24` (`M-SVC-USER-TokenExchange`, `M-SVC-USER-ValidateAccessToken`, `M-SVC-USER-JWKS`, `M-SVC-USER-issueIDToken`, `M-SVC-USER-getRSAPrivateKey`)
- `PF-28` (`M-UTIL-JWKS-BuildJWKS`, `M-UTIL-JWKS-Marshal`, `M-UTIL-PARSERSA`, `M-UTIL-VALIDATERS256`, `M-UTIL-PARSETOKEN`)
- `PF-27` (`M-UTIL-APIKEY`)
- `PF-02` (`M-CTRL-ADMIN-GUARD`)

Entrega esperada:

- Garantir regras funcionais de autenticacao, emissao/validacao de token e OOB conforme SPEC.
- Cobrir cenarios de erro de seguranca: assinatura invalida, token expirado, issuer/audience incorretos, role/status invalido.

### Fase 2 - Alto (contrato HTTP e operacoes administrativas)

Pacotes:

- `PF-06` (controllers de auth/OOB/JWKS/token exchange)
- `PF-07` (controllers de update/delete/status/revoke/membership remove)
- `PF-25` (servicos admin de usuario)

Entrega esperada:

- Asserts de contrato: status code, payload, shape e mensagens funcionais.
- Validacao de regras administrativas e proibicoes (403/401/400 conforme caso).

### Fase 3 - Medio (dominio multi-tenant e autorizacao)

Pacotes:

- `PF-19` (membership service)
- `PF-20` (role service)
- `PF-21` (tenant service)
- `PF-26` (helpers de autorizacao)

Entrega esperada:

- Cobertura funcional de regras de tenant/role/scope.
- Casos limite de listas, conjuntos e fallback de tenant context.

### Fase 4 - Medio/Baixo (repositorios e providers)

Pacotes:

- `PF-10`, `PF-11`, `PF-12`, `PF-13`, `PF-14`, `PF-15`, `PF-16`, `PF-17`
- `PF-08`, `PF-09`

Entrega esperada:

- Validar CRUD funcional e semantica de persistencia (not found, duplicidade, idempotencia, propagacao de erro).
- OOB no repositorio com enforce de requestType e single-use.

### Fase 5 - Baixo (constructors e auxiliares restantes)

Pacotes:

- `PF-01`, `PF-03`, `PF-04`, `PF-05`, `PF-18`, `PF-29`

Entrega esperada:

- Garantir wiring, contrato de handlers write/read e carga de configuracao com erros/defaults.

## Sprint tecnico por funcao (template obrigatorio)

Para cada funcao da matriz:

1. Identificar pacote `PF/CF`.
2. Derivar classes de equivalencia de entrada e limites.
3. Enumerar caminhos CFG independentes.
4. Definir casos funcionais que cobrem os caminhos.
5. Implementar doubles/mocks/fakes minimos para isolar a funcao.
6. Escrever asserts de oraculo funcional (resultado esperado da SPEC).
7. Medir cobertura de caminhos e ajustar casos ate >=85%.

## Gates de qualidade por PR

- [ ] Nenhum teste com assertiva tautologica (`assert.True(true)` etc.).
- [ ] Cada teste referencia requisito funcional do pacote `CF`.
- [ ] Casos de falha validam erro funcional (codigo/mensagem/estado), nao apenas erro generico.
- [ ] Cobertura por funcao reportada e >=85% dos caminhos executaveis.
- [ ] Casos limite explicitamente documentados no nome da tabela/caso.

## Backlog operacional (checklist)

### Bloco A - Security/Auth Core

- [ ] Implementar/ajustar todos os testes dos pacotes `PF-22`, `PF-23`, `PF-24`.
- [ ] Fechar lacunas em `PF-27`, `PF-28`, `PF-02`.
- [ ] Revisao de oraculos por requisito da SPEC de tokens/OOB.

### Bloco B - HTTP Contract

- [ ] Cobrir `PF-06` e `PF-07` com matriz de request/response valida e invalida.
- [ ] Garantir correspondencia 1:1 com `04_api_spec.md`.

### Bloco C - Multi-tenant Domain

- [ ] Cobrir `PF-19`, `PF-20`, `PF-21`, `PF-26` com limites de roles/scopes/tenant.

### Bloco D - Persistence/Provider

- [ ] Cobrir `PF-10` a `PF-17` com casos de erro de store e compat legada.
- [ ] Garantir casos de idempotencia e requestType binding no OOB.

### Bloco E - Remaining Unit Surface

- [ ] Cobrir `PF-01`, `PF-03`, `PF-04`, `PF-05`, `PF-18`, `PF-29`.
- [ ] Consolidar relatorio final de cobertura por funcao.

## Definicao de pronto da fase de unidade

A fase e considerada concluida quando:

- toda funcao da matriz (133) tem casos funcionais implementados;
- nenhuma funcao no escopo fica abaixo de 85% dos caminhos executaveis;
- relatorio final explicita bugs encontrados por pacote `PF`;
- todos os testes sao rastreaveis a regras funcionais da SPEC.
