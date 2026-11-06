# FieldGateway v2.3: legacy baseline (.NET Framework 4.0 / 4.5)

A realistic 2012-era industrial gateway library. It polls PLCs over **Modbus/TCP**, exposes tags through a **WCF** service hosted in a **Windows Service**, writes to a SQL historian, pushes snapshots to a vendor cloud, and stages firmware for field devices.

> ⚠️ This code intentionally contains the weaknesses listed in [LEGACY-ISSUES.md](LEGACY-ISSUES.md). It is the **baseline** for the CRA assessment. Do not deploy it.

```
Indusoft.FieldGateway.sln
├─ src/FieldGateway.Core        net40  Modbus TCP master (APM), device registry, XML config, poller threads,
│                                      BinaryFormatter cache, MD5 firmware check, registry licensing
├─ src/FieldGateway.Service     net45  Windows Service + WCF (BasicHttpBinding), SQL historian, cloud uplink
├─ src/FieldGateway.Simulator   net45  Modbus TCP slave simulator (port 1502)
├─ tests/FieldGateway.Tests     net45  NUnit 2.6.4
└─ samples/devices.xml
```

## Build

You need Visual Studio 2022 (or Build Tools) with the .NET Framework 4.0/4.5 targeting packs. Recent VS versions no longer install them, so add them first, for example by extracting `Microsoft.NETFramework.ReferenceAssemblies.net40` / `.net45` from NuGet into `C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\`.

```powershell
nuget restore Indusoft.FieldGateway.sln -PackagesDirectory packages
msbuild Indusoft.FieldGateway.sln /p:Configuration=Release
```

## Run the demo

```powershell
src\FieldGateway.Simulator\bin\Release\Indusoft.FieldGateway.Simulator.exe 1502
# copy samples\devices.xml to C:\ProgramData\Indusoft\FieldGateway\devices.xml
src\FieldGateway.Service\bin\Release\Indusoft.FieldGateway.Service.exe /console
# WSDL: http://localhost:8080/FieldGateway?wsdl  (no authentication - finding L05)
```
