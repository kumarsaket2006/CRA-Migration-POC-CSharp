using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Indusoft.FieldGateway.Core.Firmware;

namespace Indusoft.FieldGateway.Tests;

/// <summary>Regression tests for L03/L10/MR-04: authenticated, rollback-protected, traversal-proof updates.</summary>
public sealed class FirmwarePackageVerifierTests : IDisposable
{
    private readonly ECDsa _vendorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly byte[] _image = RandomNumberGenerator.GetBytes(4096);

    private FirmwarePackageVerifier Verifier() => new([_vendorKey.ExportSubjectPublicKeyInfoPem()]);

    private MemoryStream Bundle(ECDsa signer, string version = "4.2.0", string model = "IND-BOILER-CTRL-2",
        byte[]? image = null, string? extraEntry = null, byte[]? manifestOverride = null)
    {
        var img = image ?? _image;
        byte[] manifest = manifestOverride ?? Encoding.UTF8.GetBytes(
            $"{{\"model\":\"{model}\",\"version\":\"{version}\",\"sha256\":\"{Convert.ToHexString(SHA256.HashData(_image))}\",\"size\":{_image.Length}}}");
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            Add(zip, "manifest.json", manifest);
            Add(zip, "manifest.sig", signer.SignData(manifest, HashAlgorithmName.SHA256));
            Add(zip, extraEntry ?? "firmware.bin", img);
        }
        ms.Position = 0;
        return ms;
    }

    private static void Add(ZipArchive zip, string name, byte[] data)
    {
        using var s = zip.CreateEntry(name).Open();
        s.Write(data);
    }

    [Fact]
    public void Verify_GenuineNewerBundle_Accepted()
    {
        var r = Verifier().Verify(Bundle(_vendorKey), "IND-BOILER-CTRL-2", new Version(4, 1, 0));
        Assert.True(r.Accepted, r.Reason);
        Assert.Equal(_image, r.Image);
    }

    [Fact]
    public void Verify_SignedByUntrustedKey_Rejected()
    {
        var r = Verifier().Verify(Bundle(_attackerKey), "IND-BOILER-CTRL-2", new Version(4, 1, 0));
        Assert.False(r.Accepted);
        Assert.Contains("signature", r.Reason);
    }

    [Fact]
    public void Verify_TamperedImage_Rejected()
    {
        var tampered = (byte[])_image.Clone();
        tampered[100] ^= 0xFF;
        var r = Verifier().Verify(Bundle(_vendorKey, image: tampered), "IND-BOILER-CTRL-2", new Version(4, 1, 0));
        Assert.False(r.Accepted);
        Assert.Contains("hash", r.Reason);
    }

    [Fact]
    public void Verify_Downgrade_Rejected()
    {
        var r = Verifier().Verify(Bundle(_vendorKey, version: "4.0.9"), "IND-BOILER-CTRL-2", new Version(4, 1, 0));
        Assert.False(r.Accepted);
        Assert.Contains("rollback", r.Reason);
    }

    [Fact]
    public void Verify_WrongModel_Rejected()
    {
        var r = Verifier().Verify(Bundle(_vendorKey, model: "OTHER"), "IND-BOILER-CTRL-2", new Version(4, 1, 0));
        Assert.False(r.Accepted);
    }

    [Theory]
    [InlineData("../../evil.dll")]
    [InlineData("/etc/cron.d/x")]
    [InlineData("sub/firmware.bin")]
    public void Verify_ZipSlipEntry_Rejected(string entry)
    {
        var r = Verifier().Verify(Bundle(_vendorKey, extraEntry: entry), "IND-BOILER-CTRL-2", new Version(4, 1, 0));
        Assert.False(r.Accepted);
        Assert.Contains("unexpected entry", r.Reason);
    }

    [Fact]
    public void Verify_MalformedManifestWithValidSignature_Rejected()
    {
        var r = Verifier().Verify(Bundle(_vendorKey, manifestOverride: Encoding.UTF8.GetBytes("{\"model\":1}")), "IND-BOILER-CTRL-2", new Version(4, 1, 0));
        Assert.False(r.Accepted);
    }

    [Fact]
    public void Constructor_NoTrustedKeys_Throws() =>
        Assert.Throws<ArgumentException>(() => new FirmwarePackageVerifier([]));

    public void Dispose()
    {
        _vendorKey.Dispose();
        _attackerKey.Dispose();
    }
}
