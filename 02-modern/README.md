# FieldGateway v3.0: .NET 10 LTS, CRA-remediated

This is the migrated version of the legacy gateway. All issues L01-L12 from the legacy issue register are fixed. L13 (binary signing) is wired into CI and waits for signing-key provisioning.

```
Indusoft.FieldGateway.sln
├─ Directory.Build.props        net10.0, nullable, AnalysisModeSecurity=All, warnings-as-errors, NuGet Audit gate, lock files
├─ Directory.Packages.props     Central Package Management (7 runtime packages)
├─ nuget.config                 single source + package source mapping
├─ src/FieldGateway.Core        Modbus framing (bounds-checked, async), hardened XML config, PeriodicTimer poller,
│                               System.Text.Json cache, ECDSA-signed firmware & licence, security event log
├─ src/FieldGateway.Service     ASP.NET Core minimal API (HTTPS + mTLS + RBAC + rate limiting), Windows Service/systemd,
│                               parameterised historian, opt-in HTTPS cloud uplink
├─ src/FieldGateway.Simulator   Modbus TCP slave simulator (loopback by default)
├─ tools/FieldGateway.FirmwareSigner   `fg-sign`: key generation, firmware bundle and licence signing
└─ tests/FieldGateway.Tests     xUnit: 43 security regression tests
```

## Legacy → modern mapping

| Legacy (.NET Framework) | .NET 10 |
|---|---|
| WCF `ServiceHost`, BasicHttpBinding | ASP.NET Core minimal APIs `/api/v1/...`, Kestrel HTTPS + client certificates |
| `ServiceBase` | Generic Host `UseWindowsService()` + `UseSystemd()` |
| `app.config` / `ConfigurationManager` | `appsettings.json` + validated `IOptions<T>` + secret store |
| APM `BeginRead/EndRead`, `Thread`, `Thread.Abort` | `async/await`, `ReadExactlyAsync`, `PeriodicTimer`, `CancellationToken`, `Channel<T>` |
| `BinaryFormatter`, Newtonsoft `TypeNameHandling.All` | `System.Text.Json` source generation |
| `XmlDocument` + `XmlUrlResolver` | `XmlReader` with `DtdProcessing.Prohibit` → `XDocument` |
| MD5 / SHA1 / DES | SHA-256 + ECDSA P-256 signatures, no home-grown encryption |
| Registry licensing | Signed licence file |
| log4net 1.2.10 | `Microsoft.Extensions.Logging` + `[LoggerMessage]` security events |
| SharpZipLib 0.86 | `System.IO.Compression` (in-box) |
| `System.Data.SqlClient` string SQL | `Microsoft.Data.SqlClient` parameterised |

## Build, test, run

```powershell
dotnet build Indusoft.FieldGateway.sln -c Release
dotnet test  Indusoft.FieldGateway.sln

# demo
dotnet run --project src/FieldGateway.Simulator -- 1502
dotnet run --project tools/FieldGateway.FirmwareSigner -- keygen vendor.key.pem vendor.pub.pem
dotnet run --project tools/FieldGateway.FirmwareSigner -- firmware fw.bin IND-BOILER-CTRL-2 4.2.0 vendor.key.pem bundle.zip
dotnet run --project tools/FieldGateway.FirmwareSigner -- license ACME Pro 50 2030-01-01 vendor.key.pem license.json
```

To run the service, set the paths, public keys, client thumbprints and the server certificate in `appsettings.json`. Set `ConnectionStrings__Historian` as an environment variable. See [`../04-compliance/secure-configuration-guide.md`](../04-compliance/secure-configuration-guide.md).

## API (all routes need a client certificate on the allow-list)

| Method | Route | Policy |
|---|---|---|
| GET | `/api/v1/devices` | Operator / Engineer / Maintainer |
| GET | `/api/v1/devices/{id}/tags/{tag}` | Operator / Engineer / Maintainer |
| PUT | `/api/v1/devices/{id}/tags/{tag}` `{"value": 72.5}` | Engineer |
| POST | `/api/v1/devices/{id}/firmware` (application/octet-stream, signed bundle) | Maintainer |
| GET | `/api/v1/history?deviceId=&tag=&from=&to=` (31 days max) | Operator / Engineer / Maintainer |
