# CRA migration POC: Indusoft FieldGateway (.NET Framework 4.x → .NET 10)

This proof of concept shows how a legacy industrial-automation .NET library is brought into line with the **EU Cyber Resilience Act** (Regulation (EU) 2024/2847) as part of a migration to **.NET 10 LTS**. Scan evidence is kept for both the starting point and the result.

| Folder | What it contains |
|---|---|
| `01-legacy/` | v2.3 baseline: .NET Framework 4.0/4.5, WCF, Windows Service, Modbus/TCP. Contains intentional, labelled weaknesses ([LEGACY-ISSUES.md](01-legacy/LEGACY-ISSUES.md)). |
| `02-modern/` | v3.0: .NET 10 LTS, ASP.NET Core minimal API with mTLS/RBAC, signed firmware, hardened parsing, 43 security regression tests. |
| `03-security/tools/` | Scan toolchain: CycloneDX SBOM, SCA against the GitHub Advisory Database, Semgrep CRA rule pack, detect-secrets, Snyk and dotnet scripts, report generator. |
| `03-security/reports/baseline/` | **Initial** evidence: SBOM, VEX, SCA, SAST (JSON/SARIF/MD), secrets, summary. |
| `03-security/reports/final/` | **Final** evidence for the same scans, plus Roslyn security-analyzer SARIF. |
| `03-security/manual-review/` | Architecture review findings (baseline) and residual risks (final). |
| `04-compliance/` | **CRA-Compliance-Report.html**, traceability matrix, SECURITY.md (CVD and Art. 14 runbook), threat model, secure configuration guide. |
| `.github/workflows/cra-pipeline.yml` | CI: NuGet Audit gate, analyzers, tests, SBOM, scans, Snyk, signing, provenance. |

## Results at a glance

| | Baseline v2.3 | Final v3.0 |
|---|---|---|
| Known-vulnerable components / EOL runtimes (SCA) | 8 (1 critical, 5 high) | 0 |
| SAST findings (Semgrep CRA pack) | 39 (20 high) | 1 medium, triaged (developer simulator) |
| Secrets in source/config | 10 | 0 |
| Roslyn .NET security analyzers (91 rules) | n/a | 0 |
| Architecture review | 9 (1 critical, 5 high) | 4 residual (1 medium, 3 low) |
| CRA Annex I Part I requirements met | - | 11 / 13 (2 partly met) |

## Reproduce

```powershell
pip install -r 03-security/tools/requirements.txt
git clone --depth 1 --filter=blob:none --sparse https://github.com/github/advisory-database .cache/advisory-database
git -C .cache/advisory-database sparse-checkout set advisories/github-reviewed

python 03-security/tools/run_scans.py baseline 01-legacy 2.3.0
python 03-security/tools/run_scans.py final    02-modern 3.0.0

# on a connected build machine (.NET 10 SDK):
pwsh 03-security/tools/build-and-scan.ps1                         # restore/build/test + dotnet vuln report + transitive SBOM
$env:SNYK_TOKEN="..."; pwsh 03-security/tools/run-snyk.ps1 -Phase baseline
pwsh 03-security/tools/run-snyk.ps1 -Phase final

python 03-security/tools/make_report.py                            # regenerates 04-compliance/CRA-Compliance-Report.html
```

## How the evidence was produced (honesty notes)

* All baseline and final scan outputs in `03-security/reports` were produced by actually running the tools listed above. Nothing in them was written by hand. Advisory snapshot: GitHub Advisory Database, 2026-11-06.
* **Snyk reports are not included yet.** Snyk needs your organisation's token and network access. Run `run-snyk.ps1`; the report picks the results up automatically.
* v3.0 was compiled and the tests run with .NET SDK 10.0.114. Two packages (`Microsoft.AspNetCore.Authentication.Certificate`, `Microsoft.Data.SqlClient`) could only be type-checked against API stubs in the offline sandbox. Run `build-and-scan.ps1` for the authoritative build.
* The legacy solution was not compiled in the sandbox (no .NET Framework targeting packs on Linux).
"# CRA-Migration-POC-CSharp" 
