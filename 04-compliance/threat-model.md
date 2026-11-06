# Threat model (STRIDE): FieldGateway v3.0

Scope: the gateway service, its REST management API, the Modbus/TCP southbound link, the historian, the cloud uplink, and the firmware update path. This is the Article 13(2) cybersecurity risk assessment input for the POC.

```
 [Engineering WS / HMI] --mTLS--> (1) REST API :8443 ──┐
 [Maintenance laptop] ---mTLS--> (1)                    │      ┌──> (4) SQL historian (TLS, Encrypt=Mandatory)
                                                        ├─ FieldGateway service ──┤
 [Vendor cloud] <--HTTPS (5)-- uplink (opt-in) ─────────┘      └──> (2) Modbus/TCP :502  ──> [PLC / RTU]  (cell zone)
                 (3) signed firmware bundle --> staging --> device bootloader
 Trust boundaries: IT/OT DMZ ↔ gateway (1,5); gateway ↔ cell zone (2); gateway ↔ historian (4)
```

| # | Element | Threat (STRIDE) | Legacy exposure | v3.0 control | Residual |
|---|---|---|---|---|---|
| T1 | REST API (1) | **S**poofing an engineer | Anonymous WCF over HTTP | mTLS, thumbprint allow-list, revocation check | Low |
| T2 | REST API (1) | **E**levation: operator writes setpoints | No authorisation | RBAC policies: Read / Write (Engineer) / Firmware (Maintainer) | Low |
| T3 | Tag write | **T**ampering: unsafe setpoint | Any value, any tag | Writable flag plus engineering min/max, register range check, audit event 5020/5021 | Low |
| T4 | Firmware (3) | **T**ampering: malicious image | MD5 file in the same bundle | ECDSA signature, model binding, anti-rollback, allow-listed entries, size caps | Low (device secure boot: MR-F02) |
| T5 | Firmware upload | **E**levation through path traversal / Zip-Slip | Caller file name, entry names | Server-generated paths, entry allow-list | Low |
| T6 | Config file | **I**nfo disclosure / DoS through XXE | DTD + resolver enabled | DTD prohibited, no resolver, size cap | Low |
| T7 | Cache file | **E**levation through deserialization gadget | BinaryFormatter | Typed System.Text.Json, closed type set | Low |
| T8 | Historian (4) | **T**ampering / **I**nfo disclosure through SQLi | String-concatenated SQL, `sa` | Parameters, least-privilege login, TLS | Low |
| T9 | Cloud uplink (5) | **I**nfo disclosure through MITM | TLS 1.0, any certificate, key in URL | OS TLS defaults, full validation, key in header from secret store, off by default | Low |
| T10 | Modbus (2) | **S**poofing / **T**ampering of process frames | Unchecked lengths, no txn match | Strict framing, transaction/unit-id match. The protocol itself has no authentication. | **Medium (MR-F01)**: network segmentation (IEC 62443 zones/conduits), roadmap Modbus/TCP Security |
| T11 | Whole service | **D**oS | Unbounded threads/buffers | Rate limiting, request size caps, bounded channel, backoff | Low |
| T12 | Logs | **I**nfo disclosure | Passwords, API key, raw frames | Templated events without secrets | Low |
| T13 | Operations | **R**epudiation | No audit trail | Security events 5000-5999 with client identity, sent to the SIEM | Low |
| T14 | Supply chain | **T**ampering with dependencies | 4 vulnerable packages, no SBOM | CPM + lock files, source mapping, NuGet Audit gate, signature verification, SBOM/VEX, Snyk | Low |
