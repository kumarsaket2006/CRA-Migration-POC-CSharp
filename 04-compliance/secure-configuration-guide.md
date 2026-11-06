# Secure configuration guide: FieldGateway v3.0

This guide covers the user information required by Annex II and the secure-by-default and reset expectations of Annex I Part I (2)(b) and (m).

## 1. Defaults (secure by default)

* The management API listens on **https://127.0.0.1:8443** only. Bind it to the dedicated management interface (`Kestrel:Endpoints:Management:Url`). Never bind to `0.0.0.0` on an IT-facing NIC.
* Every request needs a **client certificate**. The client allow-list (`Gateway:Clients`) ships **empty**, so nobody can connect until you add an entry.
* The cloud uplink is **disabled**.
* There are no default accounts or passwords.

## 2. Secrets (never in appsettings.json or devices.xml)

| Secret | Key | Provide via |
|---|---|---|
| Historian connection string | `ConnectionStrings__Historian` | Environment variable on the service account, systemd `LoadCredential=`, or Azure Key Vault configuration provider |
| Cloud API key (if enabled) | `CloudUplink__ApiKey` | as above (minimum 32 characters) |
| TLS server certificate | `Kestrel:Endpoints:Management:Certificate` | Windows certificate store (LocalMachine\My, private key ACL'd to the service account) or a PEM file readable only by the service account |

Use a **least-privilege SQL login**: INSERT/SELECT on `dbo.TagHistory` only. Include `Encrypt=Mandatory;TrustServerCertificate=False` in the connection string.

## 3. Client certificates and roles

```json
"Clients": [
  { "Sha256Thumbprint": "<64 hex>", "Name": "eng-ws-01", "Roles": ["Engineer"] },
  { "Sha256Thumbprint": "<64 hex>", "Name": "hmi-line2",  "Roles": ["Operator"] },
  { "Sha256Thumbprint": "<64 hex>", "Name": "svc-laptop", "Roles": ["Maintainer"] }
]
```
* Issue certificates from your OT PKI with a validity of 1 year or less. CRL/OCSP endpoints must be reachable from the gateway, otherwise revocation checks fail closed.
* To rotate a certificate: add the new thumbprint, deploy, then remove the old one.

## 4. TLS

The gateway does not hard-code protocol versions (CA5398). Enforce **TLS 1.2 and 1.3 only** at OS level:
* Windows: disable SSL 3.0, TLS 1.0 and TLS 1.1 under `SCHANNEL\Protocols`.
* Linux: set `MinProtocol = TLSv1.2` in the OpenSSL system policy.

## 5. Firmware updates

* Deploy only the vendor **public** keys (`Gateway:FirmwarePublicKeysPem`). Two keys may be active during a key rotation.
* Keep `Gateway:InstalledFirmware` current. It is the anti-rollback baseline.
* Upload with `curl --cert maint.pem --key maint.key -H "Content-Type: application/octet-stream" --data-binary @bundle.zip https://gw:8443/api/v1/devices/PLC1/firmware`

## 6. Network placement (IEC 62443-3-3)

Put the gateway in the conduit between the cell zone (Modbus/TCP, port 502) and the site operations zone (port 8443 only). Use firewall rules that allow only these flows. Modbus/TCP has no authentication, so the cell zone must not be reachable from anywhere else (residual risk MR-F01).

## 7. Monitoring

Forward events **5000-5999** (category `Indusoft.FieldGateway.*`) to the SIEM. Alert on:
* 5010/5011: authentication or authorisation failures, more than 5 per minute
* 5021: rejected writes
* 5031: rejected firmware
* 5002: rejected configuration
* 5040: cache integrity failure

## 8. Reset and secure removal (Annex I Part I (2)(m))

1. Stop the service.
2. Delete `cache.json`, the `firmware/` staging folder, and logs.
3. Remove the client allow-list and the secrets (environment variables and credentials).
4. Remove the TLS certificate from the store.
5. Restore the factory `devices.xml` and `appsettings.json`.

An in-product wipe command is on the roadmap.
