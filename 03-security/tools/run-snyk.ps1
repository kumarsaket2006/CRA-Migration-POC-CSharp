<#
.SYNOPSIS
  Runs Snyk Open Source + Snyk Code against the legacy (baseline) or migrated (final) code and stores
  JSON/SARIF/HTML evidence in 03-security/reports/<phase>/snyk/. The compliance report picks them up.

.EXAMPLE
  $env:SNYK_TOKEN = "<your token>"     # or run: snyk auth
  .\run-snyk.ps1 -Phase baseline
  .\run-snyk.ps1 -Phase final
  python .\run_scans.py baseline ..\..\01-legacy 2.3.0 ; python .\run_scans.py final ..\..\02-modern 3.0.0
  python .\make_report.py

.NOTES
  Requires: Node.js 18+, `npm i -g snyk snyk-to-html`, and for the final phase the .NET 10 SDK
  (Snyk reads obj/project.assets.json, so the solution is restored first).
  For the legacy packages.config projects, `nuget restore` is run if nuget.exe is on PATH.
#>
param(
    [Parameter(Mandatory)][ValidateSet("baseline", "final")][string]$Phase,
    [string]$Org = $env:SNYK_ORG,
    [ValidateSet("low", "medium", "high", "critical")][string]$SeverityThreshold = "low"
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$src = if ($Phase -eq "baseline") { Join-Path $root "01-legacy" } else { Join-Path $root "02-modern" }
$out = Join-Path $root "03-security\reports\$Phase\snyk"
New-Item -ItemType Directory -Force -Path $out | Out-Null

if (-not (Get-Command snyk -ErrorAction SilentlyContinue)) { throw "Snyk CLI not found. Install with: npm i -g snyk snyk-to-html" }
snyk whoami --experimental | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Not authenticated. Set SNYK_TOKEN or run 'snyk auth'." }

Push-Location $src
try {
    if ($Phase -eq "final") {
        dotnet restore Indusoft.FieldGateway.sln
    } elseif (Get-Command nuget -ErrorAction SilentlyContinue) {
        nuget restore Indusoft.FieldGateway.sln -PackagesDirectory packages
    }

    $orgArg = @(); if ($Org) { $orgArg = @("--org=$Org") }

    Write-Host "== Snyk Open Source ($Phase)" -ForegroundColor Cyan
    snyk test --all-projects --detection-depth=6 --severity-threshold=$SeverityThreshold @orgArg `
        --json-file-output="$out\snyk-open-source.json" --sarif-file-output="$out\snyk-open-source.sarif"
    # exit code 1 = vulnerabilities found (expected for the baseline); >1 = error
    if ($LASTEXITCODE -gt 1) { throw "snyk test failed ($LASTEXITCODE)" }

    Write-Host "== Snyk Code / SAST ($Phase)" -ForegroundColor Cyan
    snyk code test --severity-threshold=$SeverityThreshold @orgArg `
        --json-file-output="$out\snyk-code.json" --sarif-file-output="$out\snyk-code.sarif"
    if ($LASTEXITCODE -gt 1) { Write-Warning "snyk code test returned $LASTEXITCODE (Snyk Code may not be enabled for your org)" }

    Write-Host "== Snyk SBOM ($Phase)" -ForegroundColor Cyan
    snyk sbom --all-projects --format=cyclonedx1.5+json @orgArg | Out-File -Encoding utf8 "$out\snyk-sbom.cdx.json"
    if ($LASTEXITCODE -ne 0) { Write-Warning "snyk sbom not available on this plan - skipped"; Remove-Item "$out\snyk-sbom.cdx.json" -ErrorAction SilentlyContinue }

    if (Get-Command snyk-to-html -ErrorAction SilentlyContinue) {
        snyk-to-html -i "$out\snyk-open-source.json" -o "$out\snyk-open-source.html"
        if (Test-Path "$out\snyk-code.json") { snyk-to-html -i "$out\snyk-code.json" -o "$out\snyk-code.html" }
    }

    # Optional: continuous monitoring in the Snyk UI (CRA Annex I Part II (1)/(2): track components after release)
    if ($Phase -eq "final") { snyk monitor --all-projects --project-tags="product=FieldGateway,version=3.0.0" @orgArg | Out-Null }
}
finally { Pop-Location }

# snyk-sbom is CycloneDX, not a findings file: keep it out of the findings summary
Get-ChildItem $out -Filter "*.json" | Where-Object Name -like "snyk-sbom*" | Rename-Item -NewName { $_.Name -replace '\.json$', '.sbom' } -ErrorAction SilentlyContinue
Write-Host "Snyk evidence written to $out" -ForegroundColor Green
