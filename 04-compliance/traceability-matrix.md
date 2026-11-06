# Traceability matrix - legacy issue -> fix -> test -> evidence

Generated 2026-11-06 19:37 UTC from `04-compliance/traceability.json` and scan evidence.

| ID | Issue | CWE | CRA | Baseline hits | Remediation | Tests | Final evidence | Status |
|---|---|---|---|---|---|---|---|---|
| L01 | Insecure deserialization (BinaryFormatter, TypeNameHandling.All) | CWE-502 | I.1(2)(f) | 3 | System.Text.Json with closed source-generated type set (GatewayJsonContext), size cap, fail-safe load (`Core/Storage/DataCache.cs`) | DataCache_RoundTrip; DataCache_TypeNamePayload_RejectedNotExecuted | Semgrep 0; Roslyn CA2300-CA2330 enabled, 0 | Closed |
| L02 | XXE / entity expansion in device config parser | CWE-611, CWE-776 | I.1(2)(j) | 1 | XmlReader with DtdProcessing.Prohibit, XmlResolver=null, size cap; schema-style validation with line numbers (`Core/Config/DeviceConfigLoader.cs`) | Load_ExternalEntity_Rejected; Load_BillionLaughs_Rejected; Load_InvalidValues_Rejected x5 | Semgrep 0; Roslyn CA3075/CA3077 enabled, 0 | Closed |
| L03 | Broken crypto (MD5, SHA1, DES); unauthenticated firmware & license | CWE-327, CWE-328, CWE-494 | I.1(2)(c)(e)(f) | 4 | ECDSA P-256/SHA-256 signed firmware manifest with key rotation, model binding, anti-rollback; ECDSA-signed license; DES helper removed (`Core/Firmware/FirmwarePackageVerifier.cs, Core/Licensing/LicenseValidator.cs, tools/FieldGateway.FirmwareSigner`) | Verify_GenuineNewerBundle_Accepted; Verify_SignedByUntrustedKey_Rejected; Verify_TamperedImage_Rejected; Verify_Downgrade_Rejected; Verify_WrongModel_Rejected; License_SignedByVendor_Valid_TamperedRejected | Semgrep 0; Roslyn CA5350/CA5351 enabled, 0; e2e signed bundle accepted | Closed |
| L04 | Hard-coded secrets, plaintext credentials, default passwords | CWE-798, CWE-321, CWE-256 | I.1(2)(b)(d)(e) | 9 | Validated options; secrets only via environment / user-secrets / Key Vault; config loader rejects password attributes; no default accounts (`Service/GatewayOptions.cs, Service/appsettings.json, Core/Config/DeviceConfigLoader.cs`) | Load_PasswordAttribute_Rejected | detect-secrets 0; Semgrep secret rules 0 | Closed |
| L05 | Unauthenticated cleartext WCF API; TLS validation disabled | CWE-306, CWE-862, CWE-295, CWE-319 | I.1(2)(d)(e) | 9 | Kestrel HTTPS-only, mandatory client certificates, SHA-256 thumbprint allow-list, RBAC policies (Operator/Engineer/Maintainer), rate limiting, loopback/management-interface binding, OS-negotiated TLS (`Service/Program.cs, Service/Security/CertificateIdentityMapper.cs, Service/Cloud/CloudUplink.cs`) | (follow-up) WebApplicationFactory integration tests for 401/403 paths | Semgrep 0; Roslyn CA5359/CA5398 enabled (CA5398 raised and fixed during migration) | Closed (integration tests pending) |
| L06 | Modbus frame parsing trusts device length fields | CWE-125, CWE-20 | I.1(2)(f)(h) | 1 | MBAP/PDU length validation, ReadExactlyAsync framing, transaction/unit-id matching, spec quantity limits, reconnect on protocol error (`Core/Modbus/ModbusFrame.cs, Core/Modbus/ModbusTcpClient.cs`) | ParseReadResponse_* x6; ParseHeader_Invalid_Rejected x4; BuildReadRequest_QuantityOutOfSpec_Rejected x2; BuildWriteMultiple_TooManyRegisters_Rejected | 13 negative tests pass; e2e poll against simulator | Closed |
| L07 | SQL injection in historian | CWE-89 | I.1(2)(f) | 2 | Parameterised commands with typed SqlParameters, TOP limit, Microsoft.Data.SqlClient (Encrypt=Mandatory) (`Service/Historian/HistorianRepository.cs`) | (follow-up) SQL container integration test | Semgrep 0; Roslyn CA2100 enabled, 0 | Closed |
| L08 | Credentials, API keys and raw frames in logs / API contract | CWE-532, CWE-200, CWE-209 | I.1(2)(e)(j) | 4 | Source-generated LoggerMessage templates without secrets; DTOs exclude credentials; ProblemDetails without stack traces (`Core/Diagnostics/GatewayLog.cs, Service/Endpoints/GatewayEndpoints.cs`) | - | Semgrep 0 | Closed |
| L09 | Vulnerable / end-of-life third-party components and runtime | CWE-1104, CWE-1395 | I.1(2)(a), I.2(1)(2) | 8 | Dependencies removed or replaced by in-box APIs; .NET 10 LTS; Central Package Management; NuGetAudit as build error (NU1901-NU1904) (`Directory.Packages.props, Directory.Build.props`) | - | SCA 0 findings | Closed |
| L10 | Path traversal (Zip-Slip, file name) and unvalidated setpoint writes | CWE-22, CWE-20, CWE-284 | I.1(2)(d)(f) | 3 | Allow-listed archive entries, server-generated staging paths, zip-bomb limits; TagWriteValidator (writable flag, engineering limits, register range) (`Core/Firmware/FirmwarePackageVerifier.cs, Core/Devices/TagWriteValidator.cs, Service/Endpoints/GatewayEndpoints.cs`) | Verify_ZipSlipEntry_Rejected x3; TagWrite_* x7 | Semgrep 0 | Closed |
| L11 | Swallowed exceptions; no security audit trail | CWE-390, CWE-778 | I.1(2)(l) | 5 | Security event ids 5000-5999 (authn/authz, tag writes, firmware, config, cache, license); failures logged with context; cooperative cancellation (`Core/Diagnostics/GatewayLog.cs, Service/Workers/GatewayWorkers.cs`) | - | Semgrep empty-catch 6 -> 1 (simulator dev tool, triaged) | Closed |
| L12 | Windows/.NET Framework-only APIs (WCF, ServiceBase, Registry, Thread.Abort) | - | Migration blocker | 4 | Generic Host (UseWindowsService + UseSystemd), ASP.NET Core minimal APIs, file-based signed license, PeriodicTimer + CancellationToken (`Service/Program.cs, Core/Polling/TagPoller.cs`) | - | Semgrep 0; builds on Linux (net10.0) | Closed |
| L13 | Unsigned binaries | CWE-353 | I.1(2)(f) | 1 | Strong-name hook in Directory.Build.props; Authenticode signing + build provenance in CI release job (`Directory.Build.props, .github/workflows/cra-pipeline.yml`) | - | Pipeline step present; signing key provisioning pending | Open (key provisioning) |
| PROC | No vulnerability-handling process artefacts | - | I.2(1)-(8), Art. 13(8), Art. 14 | 1 | CycloneDX SBOM + VEX per build, SECURITY.md (CVD, contact, support period), CI security gates, Art. 14 reporting runbook (`04-compliance/SECURITY.md, .github/workflows/cra-pipeline.yml, 03-security/reports`) | - | Artefacts generated; process must be operated by PSIRT | Partially met (organisational) |

## CRA Annex I Part I

| Ref | Requirement | Status | Evidence |
|---|---|---|---|
| (2)(a) | No known exploitable vulnerabilities at release | Met | SCA 0, SAST 0 high, secrets 0 (final) |
| (2)(b) | Secure-by-default configuration, reset to original state | Met | Cloud uplink off, loopback binding, mandatory mTLS, no default accounts; reset = delete cache + restore devices.xml (guide) |
| (2)(c) | Vulnerabilities addressable through security updates | Met | Signed, rollback-protected firmware path; .NET 10 LTS servicing; NuGet Audit gate |
| (2)(d) | Protection from unauthorised access; report possible unauthorised access | Met | mTLS + allow-list + RBAC; events 5010/5011 |
| (2)(e) | Confidentiality of stored/transmitted data | Met | TLS 1.2/1.3 (OS), secrets out of config, SQL Encrypt=Mandatory |
| (2)(f) | Integrity of data, commands, programs, configuration | Partially met | Signed firmware/licence, validated config & writes; southbound Modbus unauthenticated (MR-F01) |
| (2)(g) | Data minimisation | Met | DTOs expose no credentials; logs carry no secrets or raw frames |
| (2)(h) | Availability, resilience against DoS | Met | Rate limiting, request size caps, bounded channels, backoff, zip-bomb limits |
| (2)(i) | Minimise negative impact on other devices/networks | Met | Spec-limited Modbus requests, exponential backoff, single connection per device |
| (2)(j) | Limit attack surfaces incl. external interfaces | Met | WCF/mex removed, minimal API only, no Server header, binding to management interface |
| (2)(k) | Exploitation mitigation mechanisms | Met | .NET 10 memory safety, nullable analysis, Roslyn security analyzers as errors |
| (2)(l) | Record and monitor security-relevant activity | Met | Security event ids 5000-5999 -> SIEM |
| (2)(m) | Secure removal of data and settings | Partially met | Documented procedure; no in-product wipe command yet |

## CRA Annex I Part II

| Ref | Requirement | Status | Evidence |
|---|---|---|---|
| (1) | Identify & document components (SBOM) | Met | sbom.cdx.json per build (direct) + dotnet-CycloneDX transitive in CI |
| (2) | Remediate without delay; separate security updates | Partially met | NuGet Audit/Snyk gates; release policy in SECURITY.md |
| (3) | Regular security testing and review | Met | CI SAST/SCA/secrets on every PR; 43 security regression tests |
| (4) | Public disclosure of fixed vulnerabilities | Partially met | Advisory process defined; publication channel to be set up |
| (5) | Coordinated vulnerability disclosure policy | Met | SECURITY.md |
| (6) | Contact address for vulnerability reports | Met | SECURITY.md (security@ contact, security.txt) |
| (7) | Secure distribution of updates | Met | Signed bundles, signed release artefacts (CI) |
| (8) | Updates without delay, free of charge, with advisories | Partially met | Commercial policy decision required |
