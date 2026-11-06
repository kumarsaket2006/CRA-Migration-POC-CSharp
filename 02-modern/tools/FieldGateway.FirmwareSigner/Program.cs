using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// Release-engineering tool for signed firmware bundles and license files.
// PRODUCTION: keep the private key in an HSM / Azure Key Vault (sign via its API); the PEM path is for the POC only.
//
//   fg-sign keygen   <private.pem> <public.pem>
//   fg-sign firmware <firmware.bin> <model> <version> <private.pem> <bundle.zip>
//   fg-sign license  <customer> <edition> <maxDevices> <expiresUtc yyyy-MM-dd> <private.pem> <license.json>
if (args.Length == 0)
{
    Console.Error.WriteLine("usage: fg-sign keygen|firmware|license ...");
    return 2;
}

switch (args[0])
{
    case "keygen" when args.Length == 3:
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(args[1], key.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(args[2], key.ExportSubjectPublicKeyInfoPem());
        Console.WriteLine("P-256 key pair written");
        return 0;
    }
    case "firmware" when args.Length == 6:
    {
        byte[] image = File.ReadAllBytes(args[1]);
        var manifest = new Dictionary<string, object>
        {
            ["model"] = args[2],
            ["version"] = args[3],
            ["sha256"] = Convert.ToHexString(SHA256.HashData(image)),
            ["size"] = image.LongLength,
        };
        byte[] manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest);
        using var key = LoadKey(args[4]);
        byte[] sig = key.SignData(manifestBytes, HashAlgorithmName.SHA256);

        using var zip = ZipFile.Open(args[5], ZipArchiveMode.Create);
        Add(zip, "manifest.json", manifestBytes);
        Add(zip, "manifest.sig", sig);
        Add(zip, "firmware.bin", image);
        Console.WriteLine($"Signed bundle {args[5]} ({args[2]} {args[3]})");
        return 0;
    }
    case "license" when args.Length == 7:
    {
        var info = new Dictionary<string, object>
        {
            ["customer"] = args[1],
            ["edition"] = args[2],
            ["maxDevices"] = int.Parse(args[3], CultureInfo.InvariantCulture),
            ["expiresUtc"] = DateTimeOffset.ParseExact(args[4], "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal),
        };
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(info);
        using var key = LoadKey(args[5]);
        var envelope = new { payload = Convert.ToBase64String(payload), signature = Convert.ToBase64String(key.SignData(payload, HashAlgorithmName.SHA256)) };
        File.WriteAllText(args[6], JsonSerializer.Serialize(envelope), Encoding.UTF8);
        Console.WriteLine($"License written to {args[6]}");
        return 0;
    }
    default:
        Console.Error.WriteLine("invalid arguments");
        return 2;
}

static ECDsa LoadKey(string pemPath)
{
    var key = ECDsa.Create();
    key.ImportFromPem(File.ReadAllText(pemPath));
    return key;
}

static void Add(ZipArchive zip, string name, byte[] data)
{
    using var s = zip.CreateEntry(name, CompressionLevel.Optimal).Open();
    s.Write(data);
}
