using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Indusoft.FieldGateway.Core.Firmware;

/// <summary>
/// Signed firmware bundle (fixes L03/L10, MR-04; CRA Annex I Part I (2)(c) secure updates, (2)(f) integrity).
///
/// Bundle = zip with exactly three entries:
///   manifest.json  {"model","version","sha256","size"}
///   manifest.sig   ECDSA P-256 / SHA-256 signature (IEEE P1363) over the exact manifest.json bytes
///   firmware.bin   image whose SHA-256 must equal manifest.sha256
///
/// Entry names are allow-listed, sizes are capped, nothing is written to disk until every check
/// passes, and versions must be strictly newer than the installed one (anti-rollback).
/// </summary>
public sealed class FirmwarePackageVerifier
{
    public const long MaxImageBytes = 64L * 1024 * 1024;
    private const long MaxMetaBytes = 64 * 1024;
    private static readonly string[] AllowedEntries = ["manifest.json", "manifest.sig", "firmware.bin"];

    private readonly IReadOnlyList<ECDsa> _trustedKeys;

    /// <param name="trustedPublicKeysPem">Vendor signing public keys (SubjectPublicKeyInfo PEM). Supports key rotation.</param>
    public FirmwarePackageVerifier(IEnumerable<string> trustedPublicKeysPem)
    {
        _trustedKeys = trustedPublicKeysPem.Select(pem =>
        {
            var key = ECDsa.Create();
            key.ImportFromPem(pem);
            if (key.KeySize < 256)
                throw new CryptographicException("Firmware signing keys must be at least P-256");
            return key;
        }).ToArray();
        if (_trustedKeys.Count == 0)
            throw new ArgumentException("At least one trusted firmware signing key is required", nameof(trustedPublicKeysPem));
    }

    public FirmwareVerificationResult Verify(Stream bundle, string expectedModel, Version installedVersion)
    {
        Dictionary<string, byte[]> entries;
        try
        {
            entries = ReadEntries(bundle);
        }
        catch (InvalidDataException ex)
        {
            return FirmwareVerificationResult.Reject("bundle rejected: " + ex.Message);
        }

        byte[] manifestBytes = entries["manifest.json"];
        if (!_trustedKeys.Any(k => k.VerifyData(manifestBytes, entries["manifest.sig"], HashAlgorithmName.SHA256)))
            return FirmwareVerificationResult.Reject("signature not valid for any trusted key");

        FirmwareManifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize(manifestBytes, FirmwareJsonContext.Default.FirmwareManifest);
        }
        catch (JsonException)
        {
            return FirmwareVerificationResult.Reject("manifest is not valid JSON");
        }
        if (manifest is null || !Version.TryParse(manifest.Version, out var version))
            return FirmwareVerificationResult.Reject("manifest incomplete");
        if (!string.Equals(manifest.Model, expectedModel, StringComparison.Ordinal))
            return FirmwareVerificationResult.Reject($"image is for model '{manifest.Model}', device is '{expectedModel}'");
        if (version <= installedVersion)
            return FirmwareVerificationResult.Reject($"rollback/downgrade blocked ({version} <= installed {installedVersion})");

        byte[] image = entries["firmware.bin"];
        byte[] actual = SHA256.HashData(image);
        byte[] expected;
        try
        {
            expected = Convert.FromHexString(manifest.Sha256);
        }
        catch (FormatException)
        {
            return FirmwareVerificationResult.Reject("manifest hash malformed");
        }
        if (image.LongLength != manifest.Size || !CryptographicOperations.FixedTimeEquals(actual, expected))
            return FirmwareVerificationResult.Reject("image hash/size does not match signed manifest");

        return FirmwareVerificationResult.Accept(manifest, image);
    }

    private static Dictionary<string, byte[]> ReadEntries(Stream bundle)
    {
        using var zip = new ZipArchive(bundle, ZipArchiveMode.Read, leaveOpen: true);
        if (zip.Entries.Count != AllowedEntries.Length)
            throw new InvalidDataException($"expected {AllowedEntries.Length} entries, found {zip.Entries.Count}");

        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var entry in zip.Entries)
        {
            // Allow-list by exact name: rejects "../", absolute paths, sub-folders (Zip-Slip, CWE-22)
            if (!AllowedEntries.Contains(entry.FullName, StringComparer.Ordinal) || result.ContainsKey(entry.FullName))
                throw new InvalidDataException($"unexpected entry '{entry.FullName}'");
            long limit = entry.FullName == "firmware.bin" ? MaxImageBytes : MaxMetaBytes;
            if (entry.Length > limit)
                throw new InvalidDataException($"entry '{entry.FullName}' too large");

            using var s = entry.Open();
            using var ms = new MemoryStream();
            var buffer = new byte[81920];
            int n;
            while ((n = s.Read(buffer, 0, buffer.Length)) > 0)
            {
                ms.Write(buffer, 0, n);
                if (ms.Length > limit) // do not trust the declared length (zip bombs)
                    throw new InvalidDataException($"entry '{entry.FullName}' too large");
            }
            result[entry.FullName] = ms.ToArray();
        }
        return result;
    }
}

public sealed record FirmwareManifest(string Model, string Version, string Sha256, long Size);

public sealed record FirmwareVerificationResult(bool Accepted, string? Reason, FirmwareManifest? Manifest, byte[]? Image)
{
    public static FirmwareVerificationResult Reject(string reason) => new(false, reason, null, null);
    public static FirmwareVerificationResult Accept(FirmwareManifest m, byte[] image) => new(true, null, m, image);
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(FirmwareManifest))]
internal sealed partial class FirmwareJsonContext : JsonSerializerContext;
