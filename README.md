# AD Security Assessment

Aplicativo desktop **portátil** (WPF, .NET, Windows x64) que avalia a postura de segurança do Microsoft **Active Directory Domain Services**
de forma **somente leitura**, **100 % local** e **determinística** (sem IA): coleta dados via LDAP, aplica regras com evidência técnica,
calcula um score documentado e gera relatórios HTML / JSON / CSV.

## Garantias de segurança

* **Somente leitura:** o código só cria `SearchRequest` LDAP — nenhuma operação de Add/Modify/Delete/ModifyDN; nenhuma remediação automática; GPOs, usuários, grupos e DCs nunca são alterados.
* **Sem segredos:** atributos como `unicodePwd`, `ms-Mcs-AdmPwd`, `msLAPS-Password`, `msDS-ManagedPassword`, `trustAuth*` são **bloqueados** no gateway LDAP. A senha digitada em *Connect to Domain* vive apenas em `SecureString`, é descartada ao final e nunca é gravada ou registrada.
* **Local:** nenhum dado do AD sai da máquina; não há HTTP/telemetria. O relatório avisa sobre dados sensíveis antes de ser exportado e nunca é transmitido.
* **Menor privilégio:** funciona com um usuário de domínio comum; o que exigir mais permissão aparece como **Not Evaluated** (nunca como "conforme").
* **Regras sem execução de código:** regras JSON seguem um esquema fechado (campos/operadores/datasets fixos); `script`, `code` etc. invalidam o arquivo. Regras complexas são C# compilado.
* Os guardas automáticos em `tests/…/ReadOnlyGuardTests.cs` falham o build se alguém introduzir escrita no AD, rede externa, carga dinâmica de código, etc.

## Estrutura

```
ADSecurityAssessment.sln
src/   Core (modelo, contratos, motor de regras, scoring) · Rules (JSON + C#) · Collectors · Infrastructure (LDAP, log, paths)
       Reporting (HTML/JSON/CSV) · App (WPF/MVVM)
tests/ ADSecurityAssessment.Tests   (xunit; 103 testes)
rules/ regras JSON + references.json (somente learn.microsoft.com; embutidas no .exe)   templates/ modelo do relatório (embutido)
config/ settings.json, scoring.json     data/ ciclo de vida de SO         build/ publish-portable.ps1
docs/  ARCHITECTURE.md · SCORING.md · RULES.md
```

## Como obter o executável (um único arquivo, sem dependências)

O resultado é **`ADSecurityAssessment.exe`**: win-x64, auto-contido (runtime .NET, WPF, regras e modelo do relatório embutidos). Nada é instalado no
destino. Na primeira execução ele cria `config/`, `reports/`, `logs/` e `data/` ao lado dele.

**Opção A — sem instalar nada (GitHub Actions):** envie esta pasta para um repositório GitHub (privado serve). O workflow
`.github/workflows/build-portable.yml` restaura, compila, testa e publica em um runner Windows; baixe o artefato **ADSecurityAssessment-win-x64**
na aba *Actions* (ou dispare manualmente com *Run workflow*).

**Opção B — em um Windows com .NET SDK 10 e acesso ao NuGet:**

```powershell
dotnet restore ADSecurityAssessment.sln
dotnet build   ADSecurityAssessment.sln -c Release
dotnet test    tests/ADSecurityAssessment.Tests/ADSecurityAssessment.Tests.csproj -c Release
dotnet publish src/ADSecurityAssessment.App/ADSecurityAssessment.App.csproj -c Release -r win-x64 --self-contained true -p:PublishReadyToRun=true -o artifacts/ADSecurityAssessment-portable

# ou tudo de uma vez (gera artifacts\ADSecurityAssessment-portable\ADSecurityAssessment.exe, com zip opcional)
powershell -ExecutionPolicy Bypass -File .\build\publish-portable.ps1 -ReadyToRun -Zip
```

Para .NET 8: `-p:AdsTfm=net8.0` (no script: `-TargetFramework net8.0`). Em .NET 8 o tema escuro não aplica o estilo Fluent aos controles padrão.

## Uso

1. Execute **`ADSecurityAssessment.exe`**.
2. Informe domínio, controlador de domínio (opcional), usuário e senha em **Connect to Domain** — ou use **Analyze Current Domain** (login atual do Windows).
3. Em **Report**, escolha a pasta do relatório (*Browse…*). Com a opção marcada, HTML + JSON + CSV são salvos ali automaticamente ao final
   (depois do aviso de dados sensíveis). **Demo Mode** usa dados fictícios marcados "DEMO DATA".
4. Navegue por Dashboard, Findings (filtro, busca, ordenação, detalhes/evidências/recomendações), Coverage, Environment e Log.

## Limitações desta versão (explícitas)

* DNS: só a resolução dos DCs (sem `dnsProperty` das zonas, sem SRV).
* NTLM, LDAP signing/channel binding, SMB signing/SMBv1: não legíveis por LDAP → **Not Evaluated**.
* AD CS: detecta CAs; análise de modelos (ESC1–ESC8) não implementada. Sem collector dedicado de Kerberos.
* Hybrid identity: apenas indicadores locais (sem consulta ao Entra ID).
* Exportação PDF: a arquitetura aceita novos exportadores (`IReportExporter`), mas ainda não há implementação.
