# AD Security Assessment — Arquitetura

> Ferramenta **portable**, **somente leitura**, **100 % local** para assessment de segurança do
> Active Directory Domain Services (AD DS). Este documento antecede o código e é a fonte de verdade
> dos contratos entre as camadas. Os trechos de código abaixo são os contratos reais (arquivo indicado).

## 1. Princípios de projeto

| Princípio | Como é garantido |
|---|---|
| **Read-only** | O único acesso ao AD é `SearchRequest` (LDAP) e leitura de metadados de replicação. Não existe código de `ModifyRequest`/`AddRequest`/`DeleteRequest`/`ModifyDNRequest`. O teste `ReadOnlyGuardTests` varre o código-fonte e falha se qualquer um desses tipos (ou APIs de escrita de `System.DirectoryServices`, de rede externa, de execução de processos fora da UI ou de carga dinâmica de código) aparecer. |
| **Sem armazenar senha** | A senha entra como `SecureString`, é copiada para um `NetworkCredential` com vida curta, e nunca é serializada. `ConnectionInfo` tem a senha marcada `[JsonIgnore]` e `ToString()` redigido; o logger remove padrões `password=…`; atributos secretos (`unicodePwd`, `ms-Mcs-AdmPwd`, `msLAPS-Password`, `trustAuthIncoming`…) são **proibidos** no `LdapGateway` e lançam exceção. |
| **Menor privilégio** | Todas as consultas funcionam com um usuário de domínio comum (*Authenticated Users*). Quando um atributo/contêiner exige mais permissão (ex.: PSOs), o collector devolve `Partial`/`Failed` com a causa e as regras dependentes ficam **Not Evaluated** — nunca "Compliant". |
| **Sem IA / determinístico** | Regras são C# ou JSON declarativo (árvore de condições). Não há interpretação de script, `eval`, reflexão em tipos arbitrários nem regex vindos de arquivo. |
| **Sem finding sem evidência** | `Finding` só é criado a partir de objetos coletados; cada `AffectedObject` carrega ≥ 1 `EvidenceItem` (propriedade + valor + fonte + horário). O `RuleEngine` descarta (e registra erro) um `Finding` sem evidência. |
| **Not Evaluated ≠ Compliant** | Resultado de regra é tri-estado + N/A: `Passed / Failed / NotEvaluated / NotApplicable`. A cobertura (*Assessment Coverage*) é calculada separadamente do Risk Score. |
| **Falha parcial não cancela** | Cada collector roda isolado (try/catch + timeout + token de cancelamento ligado), por domínio. A falha de um domínio/collector vira `CollectorRun` com erro; o restante prossegue. |
| **Local** | Nenhum `HttpClient` / socket externo; a única rede usada é LDAP, DNS, replicação (RPC) e SMB (SYSVOL) do próprio AD alvo. O relatório nunca é enviado; exportar exige confirmação do aviso de dados sensíveis. |
| **Portable** | `dotnet publish -r win-x64 --self-contained`; todos os dados ao lado do `.exe` (`config/ rules/ templates/ reports/ logs/ data/`). Se a pasta não for gravável, cai para `%LOCALAPPDATA%\ADSecurityAssessment`. |

## 2. Visão em camadas

```
┌───────────────────────────────────────────────────────────────────────────┐
│  ADSecurityAssessment.App  (WPF · MVVM · Fluent · Dark/Light)             │  UI
└──────────────┬────────────────────────────────────────────────────────────┘
               │ usa
┌──────────────▼────────────────────────────────────────────────────────────┐
│  ADSecurityAssessment.Core                                                │
│   Model (Finding, AssessmentResult, Snapshot…)  ·  Abstractions           │
│   (ICollector, IAssessmentRule, IReportExporter, ILog…)                   │
│   Pipeline: AssessmentOrchestrator → SnapshotNormalizer → RuleEngine →    │
│             ScoringEngine                                                 │
└──────▲───────────────▲───────────────────▲───────────────▲────────────────┘
       │               │                   │               │
┌──────┴──────┐ ┌──────┴────────┐ ┌────────┴──────┐ ┌──────┴──────────────┐
│ Collectors  │ │ Rules         │ │ Reporting     │ │ Infrastructure      │
│ LDAP, DNS,  │ │ C# rules +    │ │ HTML/JSON/CSV │ │ paths, logger,      │
│ replication │ │ JSON engine   │ │ (+ PDF ready) │ │ settings store      │
└─────────────┘ └───────────────┘ └───────────────┘ └─────────────────────┘
```

Dependências permitidas (sem ciclos): `Core` não referencia ninguém. `Collectors`, `Rules`, `Reporting`,
`Infrastructure` referenciam apenas `Core`. `App` referencia todos (composition root). `Tests` referencia todos.

### Mapeamento com as 7 camadas pedidas

| Camada pedida | Onde está |
|---|---|
| 1. Data Collection | `ADSecurityAssessment.Collectors` (+ `ICollector`/`CollectionContext` em Core) |
| 2. Rule Engine | `ADSecurityAssessment.Rules` (regras e interpretador JSON) + `RuleEngine` em Core |
| 3. Risk Assessment | `ScoringEngine` em Core (`scoring.json`, documentado em `docs/SCORING.md`) |
| 4. Findings | `Finding`, `AffectedObject`, `EvidenceItem` (Core.Model) |
| 5. Recommendations | Campos `Risk`, `Recommendation`, `References` da regra → copiados para o `Finding` |
| 6. Reporting | `ADSecurityAssessment.Reporting` |
| 7. User Interface | `ADSecurityAssessment.App` |

## 3. Projetos da solution

```
ADSecurityAssessment.sln
Directory.Build.props                 TFM ($(AdsTfm), padrão net10.0), nullable; -p:AdsStrict=true liga warnings-as-errors
src/
  ADSecurityAssessment.Core/          sem pacotes NuGet
  ADSecurityAssessment.Rules/         sem pacotes NuGet (System.Text.Json do framework)
  ADSecurityAssessment.Reporting/     sem pacotes NuGet
  ADSecurityAssessment.Infrastructure/System.DirectoryServices.Protocols (LDAP), System.DirectoryServices; paths, log, settings
  ADSecurityAssessment.Collectors/    System.DirectoryServices (somente tipos ActiveDirectory de leitura: replicação, trusts)
  ADSecurityAssessment.App/           WPF ($(AdsTfm)-windows), único projeto publicado (AssemblyName = ADSecurityAssessment)
tests/ADSecurityAssessment.Tests/     xunit
rules/                                regras JSON + catálogo (copiado para a pasta final)
config/                               settings.json, scoring.json
templates/                            report-template.html
data/                                 os-lifecycle.json (datas de suporte, com URL oficial)
docs/                                 ARCHITECTURE.md, SCORING.md, RULES.md
build/publish-portable.ps1            gera a pasta PORTABLE
```

Pacotes NuGet de terceiros: **nenhum em runtime**, exceto os pacotes oficiais Microsoft
`System.DirectoryServices` e `System.DirectoryServices.Protocols` (necessários porque não fazem parte do shared framework).
Em testes: `xunit`, `xunit.runner.visualstudio`, `Microsoft.NET.Test.Sdk`.

## 4. Modelo de dados

Todos os tipos ficam em `src/ADSecurityAssessment.Core/Model/`.

### 4.1 Enums
```csharp
public enum Severity { Informational = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }
public enum RuleOutcome { Passed, Failed, NotEvaluated, NotApplicable }
public enum CollectorStatus { Succeeded, Partial, Failed, NotApplicable, Skipped }
public enum ObjectKind { Forest, Domain, DomainController, User, Group, Computer, Trust, Gpo,
                         ServiceAccount, Dns, Policy, CertificationAuthority, Site, Other }
```

### 4.2 Finding (arquivo: `Core/Model/Finding.cs`)
```csharp
public sealed record Finding
{
    public required string FindingId { get; init; }         // "AD-PRIV-001" (único por regra)
    public required string RuleId { get; init; }
    public required string Title { get; init; }
    public required string Description { get; init; }
    public required string Category { get; init; }          // 7 categorias do dashboard
    public required string Module { get; init; }            // 20 módulos de assessment
    public required Severity Severity { get; init; }
    public required string Condition { get; init; }         // condição em texto legível
    public required string Risk { get; init; }
    public required string Recommendation { get; init; }    // orientação; NUNCA executada
    public required IReadOnlyList<MicrosoftReference> References { get; init; }
    public required IReadOnlyList<AffectedObject> AffectedObjects { get; init; }
    public required IReadOnlyList<EvidenceItem> Evidence { get; init; }
    public string? Notes { get; init; }                     // ex.: "avaliado só em 2 de 3 domínios"
    public bool IsDemo { get; init; }
}
public sealed record AffectedObject(string Name, ObjectKind Kind, string? Domain, string? DistinguishedName);
public sealed record EvidenceItem(string Source, string ObjectName, string Property,
                                  string? Value, string? Expected, DateTimeOffset CollectedAt);
public sealed record MicrosoftReference(string Title, string Url);
```

### 4.3 Regra, avaliação e resultado
```csharp
public sealed record RuleMetadata(
    string RuleId, string Title, string Description, string Category, string Module,
    Severity Severity, string Condition, string Risk, string Recommendation,
    IReadOnlyList<MicrosoftReference> References,
    IReadOnlyList<string> RequiredDatasets);

public sealed record RuleEvaluation(
    RuleMetadata Rule, RuleOutcome Outcome,
    Finding? Finding,               // só quando Outcome == Failed
    string? Reason,                 // obrigatório em NotEvaluated / NotApplicable
    int ObjectsEvaluated, int ObjectsAffected);
```

### 4.4 AssessmentSnapshot (dados coletados e normalizados) — `Core/Model/AssessmentSnapshot.cs`
Contém **apenas dados coletados**, nunca conclusões. Cada dataset tem um `DatasetState`:
```csharp
public enum DatasetCoverage { None, Partial, Complete }
public sealed record DatasetState(string Name, string Collector, DatasetCoverage Coverage,
                                  string? Reason, IReadOnlyList<string> ScopesCollected,
                                  IReadOnlyList<string> ScopesFailed);
```
Listas tipadas (`Users`, `Computers`, `PrivilegedMemberships`, `DomainControllers`, `Domains`, `Trusts`, `Gpos`,
`GppPasswords`, `ReplicationLinks`, `DnsChecks`, `PasswordPolicies`, `LapsInfo`, `ManagedServiceAccounts`,
`CertificationAuthorities`, `HybridIndicators`, `FsmoRoles`, `Sites`, `Forest`) e o `DatasetCatalog` — um registro
**fechado** (nome → tipo do item + acessor) usado pelo interpretador JSON, que acessa propriedades por nome via
reflexão restrita a esse registro, sem executar código. Datasets conhecidos mas sem collector (`ldap-signing-config`,
`smb-signing-config`, `ntlm-config`, `dns-zone-security`, `certificate-template-security`…) levam um motivo
(`NotCollectedReason`) e fazem as regras dependentes ficarem **Not Evaluated**.

### 4.5 AssessmentResult — `Core/Model/AssessmentResult.cs`
```csharp
public sealed record AssessmentResult
{
    public required AssessmentMetadata Metadata { get; init; }      // id, versão, início/fim, alvo, modo (Live/Demo)
    public required EnvironmentSummary Environment { get; init; }   // floresta, domínios, DCs, FSMO, contagens
    public required IReadOnlyList<CollectorRun> CollectorRuns { get; init; }
    public required IReadOnlyList<DatasetState> Datasets { get; init; }
    public required IReadOnlyList<RuleEvaluation> Evaluations { get; init; }   // inclui Passed/NotEvaluated/N-A
    public required IReadOnlyList<Finding> Findings { get; init; }
    public required ScoreResult Score { get; init; }                // risco + cobertura, por categoria
    public bool IsDemo { get; init; }
}
```

## 5. Contratos

### 5.1 `ICollector` — `Core/Abstractions/Contracts.cs`
```csharp
public interface ICollector
{
    string Id { get; }                              // "User", "Trust", …
    string DisplayName { get; }
    IReadOnlyList<string> Datasets { get; }         // datasets que este collector produz
    IReadOnlyList<string> DependsOn { get; }        // ids de collectors que devem rodar antes
    Task<CollectorResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken);
}
```
`CollectionContext` entrega: `Connection` (`ConnectionInfo`), `Gateways` (`IDirectoryGatewayFactory`, abstração LDAP
testável sem AD), `Builder` (`SnapshotBuilder`, onde o collector publica datasets), `Settings` (`AssessmentSettings`:
timeouts, limites), `Log` (`IAssessmentLog`), `Clock`/`Now` e `Report` (progresso). O orquestrador resolve dependências, aplica timeout por collector, captura exceções e converte em
`CollectorRun` (`Succeeded/Partial/Failed/NotApplicable`, duração, nº de objetos, erros).

### 5.2 `IAssessmentRule` — `Core/Abstractions/Contracts.cs`
```csharp
public interface IAssessmentRule
{
    RuleMetadata Metadata { get; }
    RuleEvaluation Evaluate(RuleContext context);   // puro e determinístico
}
```
`RuleContext` expõe o `AssessmentSnapshot`, `AssessmentSettings` (limiares) e `Now`.
Fontes de regra: `CSharpRule` (classes em `Rules/Csharp`) e `JsonRule` (arquivos em `rules/*.json`).
O `RuleEngine`:
1. Verifica `RequiredDatasets`: se algum está `None`, devolve **NotEvaluated** com a causa (erro do collector, permissão, "sem collector nesta versão") e **não executa** a regra.
2. Executa a regra; se algum dataset é `Partial` e nada foi encontrado → **NotEvaluated** ("cobertura parcial"), nunca Passed; se há achados, o `Finding` é mantido com uma nota de cobertura parcial.
3. `Passed` com 0 objetos avaliados → **NotApplicable**.
4. Valida a evidência: todo objeto afetado precisa de evidência coletada; senão o finding é descartado (e a regra vira Not Evaluated). Limita `MaxAffectedObjectsPerFinding` mantendo evidência consistente.
5. Isola exceções por regra (a regra vira Not Evaluated; as demais continuam). Marca `IsDemo` nos findings quando o snapshot é demo.

### 5.3 Demais contratos
```csharp
public interface IDirectoryGateway : IDisposable { /* Search paginado, RootDSE, timeout — somente leitura */ }
public interface IReportExporter { string Format { get; } string FileExtension { get; }
    Task ExportAsync(AssessmentResult result, string path, CancellationToken ct); }
public interface IAssessmentLog { void Debug(string m); void Info(string m); void Warn(string m); void Error(string m, Exception? e = null); }
```

## 6. Fluxo completo

```
AD (LDAP/DNS/replicação)
 │  somente leitura · paginado · timeout por requisição e por collector
 ▼
[1] Collection        Collectors (independentes, ordenados por DependsOn, isolados por try/catch)
 │                    → SnapshotBuilder  (+ CollectorRun por collector e por domínio)
 ▼
[2] Normalization     SnapshotNormalizer: marca usuários privilegiados (a expansão recursiva do atributo `member`
 │                    é feita pelo PrivilegedAccountCollector), membros do Protected Users, idade de senha /
 │                    inatividade com o relógio da coleta, produto/ciclo de vida do SO, desvio de relógio dos DCs
 ▼
[3] Rule Engine       RuleEngine → para cada regra: Passed | Failed(+Finding) | NotEvaluated | N/A
 │
 ▼
[4] Findings          Finding(s) com AffectedObjects + Evidence + Risk + Recommendation + References
 │
 ▼
[5] Risk Scoring      ScoringEngine: Risk Score por categoria/global (config) ⟂ Assessment Coverage
 │
 ▼
[6] Dashboard         MainViewModel/DashboardViewModel (score, severidades, categorias, filtros, detalhes)
 │
 ▼
[7] Report            Aviso de dados sensíveis → HTML / JSON / CSV (PDF-ready via IReportExporter)
```

**Modo Demo:** `DemoSnapshotFactory` cria um `AssessmentSnapshot` com `IsDemo = true` e nomes
`*.demo-corp.invalid`, passa pelo **mesmo** pipeline (Normalizer → RuleEngine → Scoring). O flag `IsDemo`
é propagado para `Finding`, `AssessmentResult`, relatórios (marca-d'água "DEMO DATA") e UI (faixa fixa).
Nunca há merge de snapshot demo com real: `AssessmentOrchestrator` tem dois pontos de entrada separados.

## 7. Tratamento de erros, timeouts e multi-domínio

* `LdapGateway`: `SendRequest(request, TimeSpan)` com `ProtocolVersion = 3`, autenticação **Negotiate** com *signing* e *sealing*,
  `ReferralChasing = None` (não segue referrals para fora da floresta alvo) e `PageResultRequestControl` (tamanho configurável).
  Só cria `SearchRequest`. Erros viram `DirectoryQueryException` (código LDAP, permissão negada, timeout).
* Cada collector tem *timeout* total (`CollectorTimeoutSeconds`) e respeita `CancellationToken` do usuário.
* Multi-domínio: `ForestCollector` lê `CN=Partitions,CN=Configuration,…` (crossRef) para listar todos os domínios;
  collectors por-domínio executam em cada domínio com sua própria conexão (DC localizado via DNS do domínio);
  falha em um domínio → `ScopesFailed` no `DatasetState` e `Partial`.
* Logs: `logs/assessment-AAAAMMDD.log` (hora, nível, operação, contagens, duração), com rotação em 10 MB e redação de
  padrões `password/pwd/secret/token = valor`. Nunca registra senha nem valores de atributos secretos.

## 8. Extensibilidade

* **Nova regra JSON:** copiar um `*.rules.json` para `rules/` (validado por esquema **fechado**: campos desconhecidos como
  `script`/`code`/`exec` invalidam o arquivo; operadores de uma lista fechada; datasets de um registro fechado; referências
  somente do catálogo oficial `rules/references.json`). Sem scripts, sem regex, sem expressões livres.
* **Nova regra C#:** classe que implementa `IAssessmentRule`, registrada no `RuleCatalog`.
* **Novo collector:** implementar `ICollector` e registrar em `CollectorCatalog`; declara os `Datasets` que produz.
* **Novo formato de relatório (PDF):** implementar `IReportExporter`.
* Limiares organizacionais (dias de inatividade etc.) ficam em `config/settings.json`.

## 9. O que NÃO é coletado via LDAP (declarado como Not Evaluated)

Registro/serviços/políticas efetivas nos DCs (assinatura LDAP, *channel binding*, assinatura SMB, SMBv1,
`LmCompatibilityLevel`, Print Spooler) **não** são legíveis por LDAP e exigem acesso remoto privilegiado ou leitura
de SYSVOL com resolução de precedência de GPO. As regras correspondentes existem no catálogo, apontam para datasets
ainda sem collector e, portanto, aparecem como **Not Evaluated** (com motivo) — reduzem a *cobertura*, não inflam o score.

## 10. Interface (MVVM)

* `ViewModels/` não referencia WPF (apenas `System.ComponentModel` e `ICommand`): `MainViewModel`, `DashboardViewModel`,
  `FindingsViewModel`, `CoverageViewModel`, `EnvironmentViewModel`. `Infrastructure/Mvvm.cs` traz `ObservableObject`,
  `RelayCommand` e `AsyncRelayCommand` (sem pacote externo). Serviços abstratos (`IAssessmentService`, `IDialogService`,
  `IThemeService`, `IUiContext`) isolam a UI do LDAP e permitem testes.
* `Platform/WpfServices.cs` (única parte com `MessageBox`, `Process.Start`, `Dispatcher`, registro de tema).
  `Process.Start` só abre o Explorer na pasta `reports/` ou um link **learn.microsoft.com** a pedido do usuário.
* Temas: `Themes/Light.xaml` e `Dark.xaml` definem tokens semânticos (`BgBrush`, `SurfaceBrush`, `AccentBrush`…) trocados em
  tempo de execução; em .NET 9+ o tema Fluent do WPF (`Application.ThemeMode`) é aplicado em conjunto. Cores de severidade são fixas
  e legíveis nos dois temas. Botões, cartões e tabelas têm templates próprios (aparência idêntica com ou sem Fluent).
* Senha: `PasswordBox` → `SecurePassword.Copy()` entregue ao ViewModel somente no clique, descartada (`Dispose`) e campo limpo ao
  final da execução. A única preferência gravada é o nome do tema (`data/theme.txt`).

## 11. Testes (`tests/ADSecurityAssessment.Tests`)

Rule Engine (Not Evaluated / N/A / parcial / evidência obrigatória / exceção isolada / limite de objetos), Scoring (cobertura ⟂ risco,
tetos, categorias não avaliadas, pesos configuráveis), regras JSON (esquema fechado, injeção de código rejeitada, operadores, referências
oficiais), catálogo entregue (51 regras, campos obrigatórios, IDs únicos), Normalizer, Demo Mode, pipeline *live* com falhas (collector que
falha / depende de outro / cancelamento / diretório inacessível), relatórios (HTML com CSP e sem script, CSV anti *formula injection*, JSON
válido) e **guardas read-only / local-only** sobre o código-fonte.

## 12. Limitações conhecidas desta versão

* DNS: apenas resolução de nome dos DCs (o atributo binário `dnsProperty` das zonas e os registros SRV não são interpretados).
* NTLM, assinatura/channel binding LDAP e SMB: **Not Evaluated** (configuração de registro/política, não legível por LDAP).
* AD CS: detecção de CAs Enterprise; análise de modelos de certificado (ACL/EKU, ESC1–ESC8) ainda não implementada.
* Kerberos: as verificações usam atributos coletados por Domain/User/PrivilegedAccount (não há collector dedicado).
* Hybrid identity: indicadores (`MSOL_*`, `AZUREADSSOACC`, contas de sincronização) — sem consulta ao Entra ID (100 % local).

## 13. Empacotamento: executável único

`dotnet publish -r win-x64 --self-contained true` produz **um único `ADSecurityAssessment.exe`** (`PublishSingleFile`, compressão, bibliotecas nativas
do WPF incluídas para auto-extração em pasta temporária do usuário). Regras JSON, `references.json`, `os-lifecycle.json` e o modelo HTML estão
**embutidos** como recursos; arquivos ao lado do exe (`rules\`, `config\`) têm prioridade quando presentes e válidos, e são só dados. A raiz portátil é a
pasta do processo (`Environment.ProcessPath`); `config\`, `reports\`, `logs\`, `data\` são criadas na primeira execução (ou em `%LOCALAPPDATA%` se a pasta for
somente leitura). O workflow `.github/workflows/build-portable.yml` reproduz esse build em runner Windows para quem não tem o SDK.
