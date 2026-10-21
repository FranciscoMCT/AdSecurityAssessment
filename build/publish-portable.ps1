<#
.SYNOPSIS
    Restaura, compila, testa e publica o AD Security Assessment como UM ÚNICO executável (win-x64, self-contained).

.DESCRIPTION
    Executar em uma máquina de build com o .NET SDK 10 (ou 8, com -TargetFramework net8.0) e acesso ao NuGet.
    Resultado:  <OutputRoot>\ADSecurityAssessment-portable\ADSecurityAssessment.exe  (+ README-PORTABLE.txt)

    O .exe contém o runtime .NET, o WPF, as regras e o modelo do relatório: nada precisa estar instalado no destino.
    Na primeira execução ele cria, AO LADO DELE, config\, reports\, logs\ e data\. Se existir uma pasta rules\ ao lado do exe,
    as regras JSON dela são usadas no lugar das embutidas (somente dados; nunca código).
    Alternativa sem instalar nada: o workflow .github/workflows/build-portable.yml gera o mesmo .exe no GitHub Actions.

.PARAMETER Configuration   Release (padrão) ou Debug.
.PARAMETER OutputRoot      Pasta onde o pacote é gerado (padrão: .\artifacts).
.PARAMETER TargetFramework net10.0 (padrão) ou net8.0.
.PARAMETER SkipTests       Pula "dotnet test".
.PARAMETER ReadyToRun      Compila com ReadyToRun (inicialização mais rápida; arquivo maior).
.PARAMETER Zip             Também gera ADSecurityAssessment-portable.zip.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\build\publish-portable.ps1 -ReadyToRun -Zip
#>
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')] [string] $Configuration = 'Release',
    [string] $OutputRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts'),
    [ValidateSet('net10.0', 'net8.0')] [string] $TargetFramework = 'net10.0',
    [switch] $SkipTests,
    [switch] $ReadyToRun,
    [switch] $Zip
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo     = Split-Path -Parent $PSScriptRoot
$sln      = Join-Path $repo 'ADSecurityAssessment.sln'
$appProj  = Join-Path $repo 'src\ADSecurityAssessment.App\ADSecurityAssessment.App.csproj'
$testProj = Join-Path $repo 'tests\ADSecurityAssessment.Tests\ADSecurityAssessment.Tests.csproj'
$rid      = 'win-x64'
$pkgName  = 'ADSecurityAssessment-portable'
$pkgDir   = Join-Path $OutputRoot $pkgName
$tfmArg   = "-p:AdsTfm=$TargetFramework"

function Invoke-Dotnet {
    param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $Arguments)
    Write-Host ">> dotnet $($Arguments -join ' ')" -ForegroundColor Cyan
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet $($Arguments[0]) falhou (código $LASTEXITCODE)." }
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw '.NET SDK não encontrado no PATH. Instale o SDK (apenas na máquina de build) ou use o workflow do GitHub Actions.'
}
foreach ($p in @($sln, $appProj)) { if (-not (Test-Path $p)) { throw "Arquivo não encontrado: $p" } }

Push-Location $repo
try {
    # 1) Restore (solution + runtime pack win-x64 usado na publicação)
    Invoke-Dotnet restore $sln $tfmArg
    Invoke-Dotnet restore $appProj -r $rid $tfmArg

    # 2) Build
    Invoke-Dotnet build $sln -c $Configuration --no-restore $tfmArg

    # 3) Testes (Rule Engine, scoring, regras JSON, relatórios, guardas read-only)
    if (-not $SkipTests) {
        if (-not (Test-Path $testProj)) { throw "Projeto de testes não encontrado: $testProj" }
        Invoke-Dotnet test $testProj -c $Configuration --no-build $tfmArg
    }
    else { Write-Warning 'Testes ignorados (-SkipTests).' }

    # 4) Publish: single-file + self-contained (as propriedades vêm do .csproj quando há RuntimeIdentifier)
    if (Test-Path $pkgDir) { Remove-Item $pkgDir -Recurse -Force }
    New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null

    $publishArgs = @('publish', $appProj, '-c', $Configuration, '-r', $rid, '--self-contained', 'true', '-o', $pkgDir, $tfmArg)
    if ($ReadyToRun) { $publishArgs += '-p:PublishReadyToRun=true' }
    Invoke-Dotnet @publishArgs

    # 5) Autoverificação: o resultado é UM único executável
    $exe = Join-Path $pkgDir 'ADSecurityAssessment.exe'
    if (-not (Test-Path $exe)) { throw 'ADSecurityAssessment.exe não foi gerado.' }
    Get-ChildItem $pkgDir -Filter '*.pdb' -ErrorAction SilentlyContinue | Remove-Item -Force

    $readme = @"
AD Security Assessment - executável único (Windows x64)

COMO USAR
  1. Copie ADSecurityAssessment.exe para qualquer pasta (ou pendrive) e execute. Não há instalador nem dependências.
  2. Informe o domínio, o controlador de domínio (opcional), usuário e senha (ou use "Analyze Current Domain" com o login atual do Windows).
  3. Escolha a pasta do relatório (botão Procurar) e inicie. O relatório HTML/JSON/CSV é salvo na pasta escolhida ao final.

PRIVACIDADE E SEGURANÇA
  - Operação 100% somente leitura; nada no Active Directory é modificado e nenhuma remediação é executada.
  - Processamento local: nenhum dado do AD é enviado para a Internet. A senha fica só em memória durante a execução.
  - Relatórios e logs podem conter informações sensíveis do seu ambiente: proteja e compartilhe com cuidado.

ARQUIVOS CRIADOS AO LADO DO EXE NA PRIMEIRA EXECUÇÃO
  config\   settings.json e scoring.json (opcional: edite para ajustar limiares e pesos)
  reports\  pasta padrão dos relatórios        logs\  log de operações (sem senhas)        data\  preferência de tema
  (Se a pasta do exe for somente leitura, essas pastas passam para %LOCALAPPDATA%\ADSecurityAssessment.)
  Observação: o .exe auto-contido extrai bibliotecas nativas do WPF para uma pasta temporária do usuário na primeira execução.
"@
    Set-Content -Path (Join-Path $pkgDir 'README-PORTABLE.txt') -Value $readme -Encoding UTF8

    # 6) Zip opcional
    if ($Zip) {
        $zipPath = Join-Path $OutputRoot "$pkgName.zip"
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
        Compress-Archive -Path (Join-Path $pkgDir '*') -DestinationPath $zipPath -CompressionLevel Optimal
        Write-Host "ZIP: $zipPath" -ForegroundColor Green
    }

    $sizeMb = [math]::Round(((Get-Item $exe).Length / 1MB), 1)
    Write-Host ''
    Write-Host "Executável único gerado: $exe ($sizeMb MB)" -ForegroundColor Green
}
finally {
    Pop-Location
}
