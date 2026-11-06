# SAST report (Semgrep, CRA .NET rule pack)

Rules: `03-security/tools/semgrep/cra-dotnet-rules.yml`  |  Findings: 39

| Severity | Rule | CWE | File:Line | Message |
|---|---|---|---|---|
| HIGH | config.plaintext-password | CWE-256 | `samples/devices.xml:4` | Plaintext password / key in configuration file. |
| HIGH | csharp.xxe-resolver | CWE-611 | `src/FieldGateway.Core/Config/DeviceConfigLoader.cs:29` | XML parser configured with an XmlUrlResolver / DTD parsing - XXE and entity-expansion DoS. |
| HIGH | csharp.path-traversal-combine | CWE-22 | `src/FieldGateway.Core/Firmware/FirmwarePackageVerifier.cs:31` | Path.Combine with an archive entry name or caller-supplied file name without canonicalisation check (Zip-Slip / traversal). |
| HIGH | csharp.hardcoded-secret | CWE-798 | `src/FieldGateway.Core/Licensing/LicenseManager.cs:11` | Secret/password literal embedded in source code. |
| HIGH | csharp.hardcoded-crypto-key | CWE-321 | `src/FieldGateway.Core/Security/CredentialProtector.cs:12` | Cryptographic key/IV derived from a string literal in source. |
| HIGH | csharp.hardcoded-crypto-key | CWE-321 | `src/FieldGateway.Core/Security/CredentialProtector.cs:13` | Cryptographic key/IV derived from a string literal in source. |
| HIGH | csharp.weak-cipher | CWE-327 | `src/FieldGateway.Core/Security/CredentialProtector.cs:18` | DES/3DES/RC2 are obsolete ciphers. Use AES-GCM (AesGcm) or DPAPI/Data Protection for secrets at rest. |
| HIGH | csharp.weak-cipher | CWE-327 | `src/FieldGateway.Core/Security/CredentialProtector.cs:32` | DES/3DES/RC2 are obsolete ciphers. Use AES-GCM (AesGcm) or DPAPI/Data Protection for secrets at rest. |
| HIGH | csharp.binaryformatter | CWE-502 | `src/FieldGateway.Core/Storage/DataCache.cs:22` | BinaryFormatter is unsafe for any input and removed in .NET 9+. Use System.Text.Json with explicit types. |
| HIGH | csharp.binaryformatter | CWE-502 | `src/FieldGateway.Core/Storage/DataCache.cs:34` | BinaryFormatter is unsafe for any input and removed in .NET 9+. Use System.Text.Json with explicit types. |
| HIGH | csharp.json-typenamehandling | CWE-502 | `src/FieldGateway.Core/Storage/TagSnapshotSerializer.cs:14` | Newtonsoft TypeNameHandling other than None lets the payload choose CLR types (deserialization gadget RCE). |
| HIGH | config.plaintext-password | CWE-256 | `src/FieldGateway.Service/App.config:13` | Plaintext password / key in configuration file. |
| HIGH | config.plaintext-password | CWE-256 | `src/FieldGateway.Service/App.config:14` | Plaintext password / key in configuration file. |
| HIGH | config.plaintext-password | CWE-256 | `src/FieldGateway.Service/App.config:19` | Plaintext password / key in configuration file. |
| HIGH | config.wcf-security-none | CWE-306 | `src/FieldGateway.Service/App.config:34` | WCF binding with security mode None - no transport security or client authentication. |
| HIGH | csharp.legacy-tls | CWE-326 | `src/FieldGateway.Service/CloudUplink.cs:22` | SSL3/TLS1.0/TLS1.1 forced. Leave protocol selection to the OS (TLS 1.2/1.3). |
| HIGH | csharp.cert-validation-disabled | CWE-295 | `src/FieldGateway.Service/CloudUplink.cs:23` | TLS certificate validation disabled. |
| HIGH | csharp.path-traversal-combine | CWE-22 | `src/FieldGateway.Service/GatewayWcfService.cs:59` | Path.Combine with an archive entry name or caller-supplied file name without canonicalisation check (Zip-Slip / traversal). |
| HIGH | csharp.sql-concat | CWE-89 | `src/FieldGateway.Service/HistorianRepository.cs:19` | SQL statement built by string concatenation - use parameterized commands. |
| HIGH | csharp.sql-concat | CWE-89 | `src/FieldGateway.Service/HistorianRepository.cs:35` | SQL statement built by string concatenation - use parameterized commands. |
| MEDIUM | csharp.sensitive-log | CWE-532 | `src/FieldGateway.Core/Config/DeviceConfigLoader.cs:58` | Log message appears to contain credentials or keys. |
| MEDIUM | csharp.weak-hash | CWE-328 | `src/FieldGateway.Core/Firmware/FirmwarePackageVerifier.cs:51` | MD5/SHA1 are broken for integrity/authenticity. Use SHA-256+ and a digital signature for authenticity. |
| MEDIUM | csharp.weak-hash | CWE-328 | `src/FieldGateway.Core/Licensing/LicenseManager.cs:29` | MD5/SHA1 are broken for integrity/authenticity. Use SHA-256+ and a digital signature for authenticity. |
| MEDIUM | csharp.empty-catch | CWE-390 | `src/FieldGateway.Core/Modbus/ModbusTcpClient.cs:116` | Exception swallowed without logging - security-relevant failures become invisible. |
| MEDIUM | config.cleartext-endpoint | CWE-319 | `src/FieldGateway.Service/App.config:15` | Cleartext HTTP endpoint (non-loopback) configured. |
| MEDIUM | config.cleartext-endpoint | CWE-319 | `src/FieldGateway.Service/App.config:26` | Cleartext HTTP endpoint (non-loopback) configured. |
| MEDIUM | config.wildcard-bind | CWE-1327 | `src/FieldGateway.Service/App.config:26` | Service bound to all interfaces (0.0.0.0) - restrict to the OT management interface. |
| MEDIUM | config.cleartext-endpoint | CWE-319 | `src/FieldGateway.Service/App.config:28` | Cleartext HTTP endpoint (non-loopback) configured. |
| MEDIUM | config.wildcard-bind | CWE-1327 | `src/FieldGateway.Service/App.config:28` | Service bound to all interfaces (0.0.0.0) - restrict to the OT management interface. |
| MEDIUM | config.exception-detail | CWE-209 | `src/FieldGateway.Service/App.config:43` | Exception details returned to remote callers. |
| MEDIUM | csharp.sensitive-log | CWE-532 | `src/FieldGateway.Service/CloudUplink.cs:36` | Log message appears to contain credentials or keys. |
| MEDIUM | csharp.secret-in-url | CWE-598 | `src/FieldGateway.Service/CloudUplink.cs:39` | Credential passed in a URL query string (ends up in proxy/server logs). |
| MEDIUM | csharp.empty-catch | CWE-390 | `src/FieldGateway.Service/GatewayService.cs:50` | Exception swallowed without logging - security-relevant failures become invisible. |
| MEDIUM | csharp.empty-catch | CWE-390 | `src/FieldGateway.Service/GatewayService.cs:56` | Exception swallowed without logging - security-relevant failures become invisible. |
| MEDIUM | csharp.empty-catch | CWE-390 | `src/FieldGateway.Simulator/ModbusSlaveSimulator.cs:54` | Exception swallowed without logging - security-relevant failures become invisible. |
| LOW | csharp.windows-only-api |  | `src/FieldGateway.Core/Licensing/LicenseManager.cs:16` | Windows/.NET Framework-only API (Registry, ServiceBase, WCF ServiceHost) - blocks cross-platform .NET 10. |
| LOW | csharp.thread-abort | CWE-404 | `src/FieldGateway.Core/Polling/TagPoller.cs:46` | Thread.Abort throws PlatformNotSupportedException on .NET 5+. Use CancellationToken. |
| LOW | csharp.windows-only-api |  | `src/FieldGateway.Service/GatewayService.cs:58` | Windows/.NET Framework-only API (Registry, ServiceBase, WCF ServiceHost) - blocks cross-platform .NET 10. |
| LOW | csharp.windows-only-api |  | `src/FieldGateway.Service/Program.cs:20` | Windows/.NET Framework-only API (Registry, ServiceBase, WCF ServiceHost) - blocks cross-platform .NET 10. |
