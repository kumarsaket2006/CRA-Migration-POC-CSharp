# SAST report (Semgrep, CRA .NET rule pack)

Rules: `03-security/tools/semgrep/cra-dotnet-rules.yml`  |  Findings: 1

| Severity | Rule | CWE | File:Line | Message |
|---|---|---|---|---|
| MEDIUM | csharp.empty-catch | CWE-390 | `src/FieldGateway.Simulator/Program.cs:53` | Exception swallowed without logging - security-relevant failures become invisible. |
