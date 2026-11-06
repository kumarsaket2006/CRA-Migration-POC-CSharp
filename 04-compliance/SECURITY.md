# Security policy – Indusoft FieldGateway

This policy covers CRA Annex I Part II (4)-(8) and the Article 13(8) support period. It also contains the Article 14 reporting runbook.

## Supported versions and support period

| Version | Runtime | Security updates until | Status |
|---|---|---|---|
| 3.0.x | .NET 10 LTS | at least 5 years from first placing on the market (Art. 13(8)); runtime servicing to 2028-11-14, then re-targeted to the next .NET LTS | Supported |
| 2.3.x | .NET Framework 4.0/4.5 (end of support 2016) | **No new security updates.** Customers are notified and given a migration path to 3.0. Article 14 reporting still applies to installed units. | End of life |

The support period and its end date are printed on the product information sheet and in the EU declaration of conformity (Annex II, point 7).

## Reporting a vulnerability (coordinated vulnerability disclosure)

* Email **security@indusoft.example** (PGP key: `https://indusoft.example/.well-known/pgp-key.txt`). The contact is also published in `https://indusoft.example/.well-known/security.txt` (RFC 9116).
* Please include the affected version, the steps to reproduce, the impact, and whether you know of active exploitation.
* We confirm receipt within **2 business days** and give a triage result (CVSS v3.1/v4 plus the CRA "actively exploited" assessment) within **5 business days**.
* Target remediation: **critical within 14 days, high within 30 days, medium within 90 days**. Security fixes ship separately from feature releases where technically feasible (Annex I Part II (2)).
* We credit reporters in the advisory unless they ask us not to. We do not take legal action against good-faith research that follows this policy.

## Publishing fixes

When a fix is available we publish a security advisory with the CVE, affected and fixed versions, CVSS score, CWE, workaround, and a CycloneDX VEX statement. It goes out through the customer portal, as a GitHub Security Advisory, and to registered customers by email (Annex I Part II (4), (8)). Security updates are free of charge for the whole support period.

Updates are distributed as **signed artefacts only**: Authenticode-signed binaries with SLSA build provenance, and ECDSA-P256-signed firmware bundles with anti-rollback protection (Annex I Part II (7)).

## Article 14 reporting runbook (in force since 11 September 2026)

This applies to every product on the EU market, including 2.3.x installations.

| Trigger | Deadline from awareness | Content | Channel |
|---|---|---|---|
| Actively exploited vulnerability, or severe incident affecting product security | **24 h** early warning | Product, affected Member States, suspected malicious act (incidents) | ENISA Single Reporting Platform (routed to the coordinating CSIRT) |
| same | **72 h** notification | General nature, initial assessment, corrective/mitigating measures, sensitivity | SRP |
| Vulnerability | **14 days** after a corrective measure is available | Final report: description, severity, impact, root cause, the fix | SRP |
| Incident | **1 month** after the 72 h notification | Final report | SRP |
| Users | Without undue delay | Impact and mitigations, in machine-readable form where possible | Advisory and customer portal |

**PSIRT roles:**
* Duty officer, 24/7 rota: decides whether a case counts as "actively exploited".
* Product security lead: owns the technical assessment.
* Legal/compliance: submits to the SRP.
* Communications: handles user notification.

Every decision and timestamp is recorded in the PSIRT ticket. These records are the audit trail.

## Evidence produced for every release

* `sbom.cdx.json` / transitive CycloneDX SBOM (Annex I Part II (1))
* `sca.json`, `sca.vex.cdx.json`: known-vulnerability status
* SAST (Semgrep SARIF, Roslyn SARIF), secrets scan, and Snyk reports when available
* `04-compliance/CRA-Compliance-Report.html`, regenerated from the above
