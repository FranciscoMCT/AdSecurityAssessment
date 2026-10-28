<#
.SYNOPSIS
    Compila, testa e publica o AD Security Hardening como uma PASTA portátil (win-x64, auto-contida): ADSecurityHardening.exe + config + docs + LEIA-ME.

.DESCRIPTION
    Executar em uma máquina de build com o .NET SDK 10 e acesso ao NuGet (ou use o workflow .github/workflows/build-portable.yml, que faz o mesmo no GitHub).
    Resultado:  <OutputRoot>\ADSecurityHardening\   (copie esta pasta para uma máquina do domínio)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\build\publish-hardening.ps1 -ReadyToRun -Zip
#>
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')] [string] $Configuration = 'Release',
    [string] $OutputRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts'),
    [switch] $SkipTests,
    [switch] $ReadyToRun,
    [switch] $Zip
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo    = Split-Path -Parent $PSScriptRoot
$sln     = Join-Path $repo 'ADSecurityAssessment.sln'
$appProj = Join-Path $repo 'src\ADSecurityAssessment.HardeningApp\ADSecurityAssessment.HardeningApp.csproj'
$tests   = Join-Path $repo 'tests\ADSecurityAssessment.Tests\ADSecurityAssessment.Tests.csproj'
$rid     = 'win-x64'
$pkgDir  = Join-Path $OutputRoot 'ADSecurityHardening'

function Invoke-Dotnet {
    param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $Arguments)
    Write-Host ">> dotnet $($Arguments -join ' ')" -ForegroundColor Cyan
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet $($Arguments[0]) falhou (código $LASTEXITCODE)." }
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw '.NET SDK não encontrado no PATH.' }

Push-Location $repo
try {
    Invoke-Dotnet restore $sln
    Invoke-Dotnet build $sln -c $Configuration --no-restore
    if (-not $SkipTests) { Invoke-Dotnet test $tests -c $Configuration --no-build } else { Write-Warning 'Testes ignorados (-SkipTests).' }

    if (Test-Path $pkgDir) { Remove-Item $pkgDir -Recurse -Force }
    New-Item -ItemType Directory -Path (Join-Path $pkgDir 'config') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $pkgDir 'docs') -Force | Out-Null

    $publishArgs = @('publish', $appProj, '-c', $Configuration, '-r', $rid, '--self-contained', 'true', '-o', $pkgDir)
    if ($ReadyToRun) { $publishArgs += '-p:PublishReadyToRun=true' }
    Invoke-Dotnet @publishArgs

    $exe = Join-Path $pkgDir 'ADSecurityHardening.exe'
    if (-not (Test-Path $exe)) { throw 'ADSecurityHardening.exe não foi gerado.' }
    Get-ChildItem $pkgDir -Filter '*.pdb' -ErrorAction SilentlyContinue | Remove-Item -Force

    Copy-Item (Join-Path $repo 'hardening\catalog.json') (Join-Path $pkgDir 'config\catalog.example.json')
    Copy-Item (Join-Path $repo 'docs\HARDENING.md') (Join-Path $pkgDir 'docs\HARDENING.md')
    Copy-Item (Join-Path $repo 'build\LEIA-ME-HARDENING.txt') (Join-Path $pkgDir 'LEIA-ME.txt')

    if ($Zip) {
        $zipPath = Join-Path $OutputRoot 'ADSecurityHardening-win-x64.zip'
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
        Compress-Archive -Path $pkgDir -DestinationPath $zipPath -CompressionLevel Optimal
        Write-Host "ZIP: $zipPath" -ForegroundColor Green
    }
    $sizeMb = [math]::Round(((Get-Item $exe).Length / 1MB), 1)
    Write-Host "Pasta pronta: $pkgDir  (exe $sizeMb MB)" -ForegroundColor Green
}
finally { Pop-Location }
