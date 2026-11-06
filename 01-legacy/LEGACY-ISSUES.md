# Legacy issue register: FieldGateway v2.3 (.NET Framework 4.0/4.5)

Each issue is marked in code with `// LEGACY-ISSUE: <ID>` (or `<!-- LEGACY-ISSUE -->` in config files). These weaknesses are **intentional**, so the POC has realistic findings for the CRA assessment. Do not deploy this code.

| ID | Weakness | CWE | CRA Annex I | Where | .NET 10 migration impact |
|---|---|---|---|---|---|
| L01 | BinaryFormatter cache; Newtonsoft `TypeNameHandling.All` | CWE-502 | I(2)(f) | Storage/DataCache.cs, Storage/TagSnapshotSerializer.cs | BinaryFormatter is removed in .NET 9+: hard blocker |
| L02 | XmlDocument with XmlUrlResolver (XXE, entity expansion) | CWE-611/776 | I(2)(j) | Config/DeviceConfigLoader.cs | Behaviour differs on .NET Core; must be made explicit |
| L03 | MD5 firmware check (no signature), SHA1 license, DES | CWE-327/328/494 | I(2)(c)(e)(f) | Firmware/, Licensing/, Security/CredentialProtector.cs | `*CryptoServiceProvider` types are obsolete (SYSLIB0021) |
| L04 | Hard-coded license secret, DES key/IV, plaintext passwords, default admin/sa | CWE-798/321/256/1392 | I(2)(b)(d)(e) | LicenseManager.cs, CredentialProtector.cs, App.config, devices.xml | `System.Configuration` → Options + secret store |
| L05 | WCF BasicHttpBinding without security; TLS 1.0 forced; certificate validation off; API key in URL | CWE-306/862/295/326/598 | I(2)(d)(e) | App.config, GatewayWcfService.cs, CloudUplink.cs | WCF server is not in .NET 10 → CoreWCF or REST |
| L06 | Modbus parser trusts device byte count; single Read(); no transaction-id match | CWE-125/20 | I(2)(f)(h) | Modbus/ModbusFrame.cs, ModbusTcpClient.cs | APM Begin/End → async/await |
| L07 | String-concatenated SQL | CWE-89 | I(2)(f) | Service/HistorianRepository.cs | System.Data.SqlClient → Microsoft.Data.SqlClient |
| L08 | Passwords, API key, raw frames logged; password in API contract; exception details in faults | CWE-532/200/209 | I(2)(e)(j) | multiple | log4net → Microsoft.Extensions.Logging |
| L09 | log4net 1.2.10, Newtonsoft.Json 9.0.1, SharpZipLib 0.86.0, System.Net.Http 4.3.0 | CWE-1104/1395 | I(2)(a), II(1)(2) | packages.config | See `03-security/reports/baseline/sca.md` |
| L10 | Zip-Slip in firmware extraction; caller-controlled upload file name; `Writable` flag not enforced | CWE-22/20/284 | I(2)(d)(f) | Firmware/FirmwarePackageVerifier.cs, GatewayWcfService.cs | - |
| L11 | Swallowed exceptions; no security audit events | CWE-390/778 | I(2)(l) | multiple | - |
| L12 | Registry, ServiceBase, WCF ServiceHost, Thread.Abort | - | migration blocker | LicenseManager.cs, GatewayService.cs, TagPoller.cs | Thread.Abort throws PlatformNotSupportedException on .NET 5+ |
| L13 | Assemblies not strong-named or Authenticode-signed | CWE-353 | I(2)(f) | *.csproj | - |

The register maps to the automated findings in `03-security/reports/baseline/` and to the architecture review in `03-security/manual-review/baseline.json`.
