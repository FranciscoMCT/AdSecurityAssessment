# Catálogo de regras

Gerado a partir do `RuleCatalog` real (7 regras em C# + regras JSON em `rules/*.rules.json`). Cada regra possui: RuleID, Title, Description,
Category, Module, Severity, Condition, Risk, Recommendation, referências Microsoft e datasets exigidos; em tempo de execução o `Finding`
acrescenta AffectedObjects e Evidence.

> Títulos e textos das regras estão em inglês (idioma dos relatórios técnicos e da documentação oficial referenciada).

## Princípios

1. **Sem evidência, sem finding.** Todo objeto afetado precisa de evidência coletada (fonte, atributo, valor observado, valor esperado, instante). Caso contrário o finding é descartado e a regra fica *Not Evaluated*.
2. **Dado ausente nunca é "Compliant".** Regras cujo dataset não foi coletado (ex.: LDAP signing, SMB signing, SMBv1, NTLM, dnsProperty, modelos do AD CS — não legíveis por LDAP ou ainda não implementados) aparecem como **Not Evaluated**, com o motivo.
3. **Cobertura parcial não aprova.** Dataset parcial + nada encontrado = *Not Evaluated*.
4. **Referências oficiais apenas.** Cada regra só aponta para chaves de `rules/references.json`, que aceita exclusivamente URLs `https://learn.microsoft.com/…`. Uma chave inexistente invalida a regra.
5. **Limiares.** Os valores configuráveis em `config/settings.json` estão rotulados nas regras como "configured baseline/threshold" e a *Condition* mostra o valor efetivo. Origem dos padrões:
   * `MinPasswordLength` = 14, `MinLockoutDurationMinutes` = 15 — valores recomendados na *Windows security baseline* da Microsoft Learn (a própria página ressalta que o comprimento deve ser ajustado às necessidades da organização).
   * `MaxClockSkewMinutes` = 5 — tolerância padrão de sincronismo de relógio do Kerberos (`SkewTime`, padrão 5 minutos).
   * `StaleAccountDays` = 180, `KrbtgtMaxPasswordAgeDays` = 180, `SeamlessSsoKeyRollDays` = 30 — **padrões do projeto**, não números exigidos pela Microsoft nesta ferramenta; ajuste-os à sua política.

## Regras

Total: **51 regras** (7 em C#, 44 em JSON).

### Active Directory Infrastructure (13)

| ID | Severidade | Título | Origem | Datasets exigidos |
|---|---|---|---|---|
| `AD-COMP-002` | Medium | Member server running an operating system past end of support | C# | `computers` |
| `AD-DC-001` | High | Domain controller running an operating system past end of support | C# | `domain-controllers` |
| `AD-DC-002` | Medium | SYSVOL replicated with FRS instead of DFSR | JSON | `domain-controllers` |
| `AD-DNS-001` | High | Domain controller host name does not resolve in DNS | JSON | `dns-checks` |
| `AD-DNS-002` | High | AD-integrated DNS zones allow insecure dynamic updates | JSON | `dns-zone-security` |
| `AD-INFRA-001` | Medium | Domain functional level lower than Windows Server 2012 R2 | JSON | `domains` |
| `AD-INFRA-002` | Low | Active Directory Recycle Bin is not enabled | JSON | `forest` |
| `AD-INFRA-003` | Medium | Domain with fewer than two writable domain controllers | C# | `domains`, `domain-controllers` |
| `AD-INFRA-004` | High | FSMO role owner is not a discovered domain controller | JSON | `fsmo-roles` |
| `AD-INFRA-005` | Low | Active Directory site with domain controllers but no subnets | JSON | `sites` |
| `AD-REPL-001` | High | Inbound replication failures reported by replication metadata | JSON | `replication-links` |
| `AD-REPL-002` | Critical | Replication partner has not replicated successfully within the tombstone lifetime | C# | `replication-links`, `forest` |
| `AD-TRUST-001` | High | External or forest trust without SID filtering | JSON | `trusts` |

### AD CS (1)

| ID | Severidade | Título | Origem | Datasets exigidos |
|---|---|---|---|---|
| `AD-ADCS-001` | High | AD CS certification authority security assessment | C# | `certification-authorities` |

### Authentication (14)

| ID | Severidade | Título | Origem | Datasets exigidos |
|---|---|---|---|---|
| `AD-DC-003` | High | Domain controller clock differs from the PDC Emulator beyond the Kerberos tolerance | C# | `domain-controllers`, `domains` |
| `AD-KRB-001` | High | krbtgt password older than the configured threshold | JSON | `users` |
| `AD-KRB-002` | High | Computer account with unconstrained Kerberos delegation (non-DC) | JSON | `computers` |
| `AD-KRB-003` | High | User account with unconstrained Kerberos delegation | JSON | `users` |
| `AD-KRB-004` | High | Account does not require Kerberos pre-authentication | JSON | `users` |
| `AD-KRB-005` | Medium | Account restricted to DES-only Kerberos encryption | JSON | `users` |
| `AD-LDAP-001` | High | LDAP signing is not required on domain controllers | JSON | `ldap-signing-config` |
| `AD-LDAP-002` | Medium | LDAP channel binding is not enforced on domain controllers | JSON | `ldap-channel-binding-config` |
| `AD-LDAP-003` | High | Anonymous LDAP operations are allowed (dSHeuristics) | JSON | `forest` |
| `AD-NTLM-001` | Medium | NTLM authentication is not restricted | JSON | `ntlm-config` |
| `AD-PWD-004` | Medium | Account lockout threshold is not configured | JSON | `password-policies` |
| `AD-PWD-005` | Low | Account lockout duration shorter than the configured baseline | JSON | `password-policies` |
| `AD-SMB-001` | High | SMB signing is not required on domain controllers | JSON | `smb-signing-config` |
| `AD-SMB-002` | High | SMBv1 is enabled on domain controllers | JSON | `smb1-config` |

### Group Policy (1)

| ID | Severidade | Título | Origem | Datasets exigidos |
|---|---|---|---|---|
| `AD-GPO-001` | Critical | Group Policy Preferences file contains a cpassword | JSON | `gpp-passwords`, `gpos` |

### Hybrid Identity (2)

| ID | Severidade | Título | Origem | Datasets exigidos |
|---|---|---|---|---|
| `AD-HYB-001` | Medium | Seamless SSO computer account password not rotated | JSON | `hybrid-indicators` |
| `AD-HYB-002` | High | Seamless SSO computer account has delegation configured | JSON | `hybrid-indicators` |

### Identity Security (11)

| ID | Severidade | Título | Origem | Datasets exigidos |
|---|---|---|---|---|
| `AD-ATK-001` | Medium | Users can join computers to the domain (ms-DS-MachineAccountQuota > 0) | JSON | `domains` |
| `AD-COMP-003` | Low | Stale enabled computer accounts | JSON | `computers` |
| `AD-LAPS-001` | Medium | LAPS schema extensions not present | JSON | `laps-info` |
| `AD-LAPS-002` | Medium | Computers without Windows LAPS / legacy LAPS password management | C# | `computers`, `laps-info` |
| `AD-PWD-001` | Medium | Minimum password length below the configured baseline | JSON | `password-policies` |
| `AD-PWD-002` | Medium | Password complexity requirement disabled | JSON | `password-policies` |
| `AD-PWD-003` | High | Password policy stores passwords using reversible encryption | JSON | `password-policies` |
| `AD-PWD-006` | High | Enabled account with 'password not required' | JSON | `users` |
| `AD-PWD-007` | High | Enabled account allows reversible password encryption | JSON | `users` |
| `AD-SVC-001` | Low | Non-privileged user accounts with SPNs (Kerberoastable) | JSON | `users` |
| `AD-USER-001` | Low | Stale enabled user accounts | JSON | `users` |

### Privileged Access (9)

| ID | Severidade | Título | Origem | Datasets exigidos |
|---|---|---|---|---|
| `AD-PRIV-001` | High | Privileged account with PasswordNeverExpires | JSON | `users` |
| `AD-PRIV-002` | Low | Disabled account that is still a member of a privileged group | JSON | `users` |
| `AD-PRIV-003` | Medium | Stale privileged account (inactive beyond the configured threshold) | JSON | `users` |
| `AD-PRIV-004` | Medium | Schema Admins group has members | JSON | `privileged-memberships` |
| `AD-PRIV-005` | High | Privileged account used as a service account (has SPNs) | JSON | `users` |
| `AD-PRIV-006` | High | Privileged account configured for Kerberos delegation | JSON | `users` |
| `AD-PRIV-007` | Medium | Privileged user account is not a member of Protected Users | JSON | `users` |
| `AD-PRIV-008` | Medium | Direct members in Account, Server, Print or Backup Operators | JSON | `privileged-memberships` |
| `AD-PRIV-009` | Low | Nested membership in a privileged group | JSON | `privileged-memberships` |


## Como adicionar uma regra JSON

1. Crie ou edite um arquivo `rules/<nome>.rules.json` (não precisa recompilar; a pasta `rules/` é lida na inicialização).
2. Use apenas o esquema fechado (`schemaVersion`, `rules[]` com `ruleId` no formato `AD-XXX-000`, `title`, `description`, `category`, `module`, `severity`, `condition`, `risk`, `recommendation`, `references[]`, `dataset`, `scope`, `where`, `applicableWhen`, `affected`, `evidence[]`, `evidenceSource`, …; veja `rules/identity.rules.json` como modelo). Campos desconhecidos — por exemplo `script`, `code`, `exec` — **invalidam o arquivo inteiro**.
3. `dataset` deve ser um nome do registro fechado (`DatasetCatalog`). Operadores permitidos (lista fechada): `eq, ne, gt, ge, lt, le, contains, startsWith, endsWith, in, notIn, isNull, notNull, hasFlag, notHasFlag, countGt, countEq, countLt, empty, notEmpty`, combinados por `all` / `any` / `not`. Limiares configuráveis são referenciados por nome com `valueSetting` (propriedade numérica de `AssessmentSettings`), nunca por expressão.
4. `references` só aceita chaves existentes em `rules/references.json`. Para uma nova referência, adicione a chave com uma URL de `learn.microsoft.com` realmente existente.
5. Erros de carga aparecem no cabeçalho da aplicação ("regras com erro") e no log; a regra inválida é ignorada, as demais continuam.

> Nada é interpretado como código: o carregador só desserializa dados e o interpretador executa um conjunto finito de operadores. Os testes `JsonRuleTests` incluem tentativas de injeção.

## Como adicionar uma regra em C#

Para lógica que não cabe no modelo declarativo (cruzar datasets, calcular idades, etc.):

1. Crie uma classe em `src/ADSecurityAssessment.Rules/Csharp/` que implemente `IAssessmentRule` (veja `InfrastructureRules.cs`).
2. Defina `Metadata` (com referências resolvidas pelo `ReferenceCatalog`) e `RequiredDatasets`.
3. Em `Evaluate(RuleContext)` leia **apenas** `ctx.Snapshot`; devolva `RuleEvaluation.Passed/Failed/NotApplicable/NotEvaluated`. Para `Failed`, cada `AffectedObject` precisa de ao menos uma `EvidenceItem`.
4. Registre a classe em `RuleCatalog.CSharpRules` e escreva um teste em `tests/ADSecurityAssessment.Tests`.

Regras em C# são compiladas junto com a aplicação — nunca carregadas de arquivos externos.
