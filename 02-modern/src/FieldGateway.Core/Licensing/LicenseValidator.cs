using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Indusoft.FieldGateway.Core.Licensing;

/// <summary>
/// Offline license check based on an ECDSA-signed license file (replaces the registry + hardcoded
/// SHA1 secret, fixes L03/L04/L12). Only the vendor PUBLIC key ships with the product; it is not a secret.
/// License file format: {"payload": "base64(license JSON bytes)", "signature": "base64(P1363 ECDSA-P256-SHA256 over those bytes)"}
/// Signing the exact payload bytes avoids any JSON canonicalisation ambiguity.
/// </summary>
public sealed class LicenseValidator(string vendorPublicKeyPem, TimeProvider time)
{
    public LicenseCheckResult Validate(string licenseFilePath)
    {
        if (!File.Exists(licenseFilePath))
            return LicenseCheckResult.Invalid("license file not found");
        try
        {
            var envelope = JsonSerializer.Deserialize(File.ReadAllBytes(licenseFilePath), LicenseJsonContext.Default.LicenseEnvelope);
            if (envelope is null)
                return LicenseCheckResult.Invalid("empty license file");

            byte[] payload = Convert.FromBase64String(envelope.Payload);
            using var key = ECDsa.Create();
            key.ImportFromPem(vendorPublicKeyPem);
            if (!key.VerifyData(payload, Convert.FromBase64String(envelope.Signature), HashAlgorithmName.SHA256))
                return LicenseCheckResult.Invalid("signature invalid");
            var license = JsonSerializer.Deserialize(payload, LicenseJsonContext.Default.LicenseInfo);
            if (license is null)
                return LicenseCheckResult.Invalid("license payload empty");
            if (license.ExpiresUtc < time.GetUtcNow())
                return LicenseCheckResult.Invalid("license expired");
            return new LicenseCheckResult(true, null, license);
        }
        catch (Exception ex) when (ex is JsonException or FormatException or CryptographicException)
        {
            return LicenseCheckResult.Invalid("license file malformed");
        }
    }
}

public sealed record LicenseInfo(string Customer, string Edition, int MaxDevices, DateTimeOffset ExpiresUtc);

public sealed record LicenseEnvelope(string Payload, string Signature);

public sealed record LicenseCheckResult(bool IsValid, string? Reason, LicenseInfo? License)
{
    public static LicenseCheckResult Invalid(string reason) => new(false, reason, null);
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(LicenseEnvelope))]
[JsonSerializable(typeof(LicenseInfo))]
internal sealed partial class LicenseJsonContext : JsonSerializerContext;
