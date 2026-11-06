<#
.SYNOPSIS
  Full build + evidence run on a connected Windows/Linux build machine:
  restore (NuGet Audit gate), build (Roslyn security analyzers as errors), tests with coverage,
  dotnet vulnerable-package report, transitive CycloneDX SBOM, then the portable scan suite and report.

.EXAMPLE
  pwsh .\build-and-scan.ps1                # final (02-modern)
  pwsh .\build-and-scan.ps1 -SkipSnyk:$false
#>
param([switch]$SkipSnyk = $true)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$modern = Join-Path $root "02-modern"
$out = Join-Path $root "03-security\reports\final"
$dotnetOut = Join-Path $out "dotnet"; $roslynOut = Join-Path $out "roslyn"
New-Item -ItemType Directory -Force -Path $dotnetOut, $roslynOut | Out-Null

Push-Location $modern
try {
    Write-Host "== Restore (NuGet Audit: NU1901-NU1904 are errors)" -ForegroundColor Cyan
    dotnet restore Indusoft.FieldGateway.sln
    if ($LASTEXITCODE) { throw "restore failed - check NuGet Audit output for vulnerable packages" }

    Write-Host "== Build (AnalysisModeSecurity=All, TreatWarningsAsErrors)" -ForegroundColor Cyan
    foreach ($p in Get-ChildItem -Recurse -Filter *.csproj -Path src, tools) {
        dotnet build $p.FullName -c Release --no-restore "-p:ErrorLog=$roslynOut\$($p.BaseName).sarif%2Cversion=2.1"
        if ($LASTEXITCODE) { throw "build failed: $($p.Name)" }
    }

    Write-Host "== Tests" -ForegroundColor Cyan
    dotnet test tests/FieldGateway.Tests -c Release --logger "trx;LogFileName=$dotnetOut\tests.trx" --collect "XPlat Code Coverage" --results-directory $dotnetOut
    if ($LASTEXITCODE) { throw "tests failed" }

    Write-Host "== Vulnerable packages (direct + transitive)" -ForegroundColor Cyan
    dotnet list Indusoft.FieldGateway.sln package --vulnerable --include-transitive --format json | Out-File -Encoding utf8 "$dotnetOut\vulnerable-packages.json"
    dotnet list Indusoft.FieldGateway.sln package --deprecated --include-transitive --format json | Out-File -Encoding utf8 "$dotnetOut\deprecated-packages.json"
    dotnet list Indusoft.FieldGateway.sln package --outdated --format json | Out-File -Encoding utf8 "$dotnetOut\outdated-packages.json"

    $vuln = Get-Content "$dotnetOut\vulnerable-packages.json" -Raw | ConvertFrom-Json
    $count = @($vuln.projects.frameworks.topLevelPackages.vulnerabilities).Count + @($vuln.projects.frameworks.transitivePackages.vulnerabilities).Count
    @{ vulnerablePackages = $count; generated = (Get-Date).ToUniversalTime().ToString("o") } | ConvertTo-Json | Out-File -Encoding utf8 "$dotnetOut\summary.json"

    Write-Host "== Transitive SBOM (CycloneDX .NET tool)" -ForegroundColor Cyan
    dotnet tool update --global CycloneDX | Out-Null
    dotnet CycloneDX Indusoft.FieldGateway.sln --output $dotnetOut --filename sbom-transitive.cdx.json --output-format Json --exclude-test-projects
}
finally { Pop-Location }

if (-not $SkipSnyk) { & (Join-Path $PSScriptRoot "run-snyk.ps1") -Phase final }

Write-Host "== Portable scan suite + report" -ForegroundColor Cyan
python (Join-Path $PSScriptRoot "run_scans.py") final $modern 3.0.0
python (Join-Path $PSScriptRoot "make_report.py")
