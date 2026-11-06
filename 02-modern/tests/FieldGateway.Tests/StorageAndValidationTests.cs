using System.Security.Cryptography;
using System.Text;
using Indusoft.FieldGateway.Core.Devices;
using Indusoft.FieldGateway.Core.Licensing;
using Indusoft.FieldGateway.Core.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace Indusoft.FieldGateway.Tests;

/// <summary>Regression tests for L01 (deserialization), L10 (write validation), L03/L04 (licensing).</summary>
public sealed class StorageAndValidationTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("fg-tests-").FullName;

    [Fact]
    public async Task DataCache_RoundTrip()
    {
        var cache = new DataCache(Path.Combine(_dir, "cache.json"), NullLogger<DataCache>.Instance);
        var values = new Dictionary<string, TagValue>
        {
            ["PLC1.Temp"] = new("PLC1", "Temp", 65.3, DateTimeOffset.UnixEpoch, TagQuality.Good),
        };
        await cache.SaveAsync(values, CancellationToken.None);
        var loaded = await cache.LoadAsync(CancellationToken.None);
        Assert.Equal(values["PLC1.Temp"], loaded["PLC1.Temp"]);
    }

    [Fact]
    public async Task DataCache_TypeNamePayload_RejectedNotExecuted()
    {
        string path = Path.Combine(_dir, "evil.json");
        await File.WriteAllTextAsync(path,
            "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\",\"MethodName\":\"Start\"}");
        var loaded = await new DataCache(path, NullLogger<DataCache>.Instance).LoadAsync(CancellationToken.None);
        Assert.Empty(loaded);
    }

    private static readonly TagDefinition Setpoint = new("Setpoint", 10, false, true, 0.1, "degC", 20, 90);

    [Fact]
    public void TagWrite_InRange_ConvertsToRaw() => Assert.Equal(655, TagWriteValidator.ToRawValue(Setpoint, 65.5));

    [Theory]
    [InlineData(19.9)]
    [InlineData(90.1)]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    public void TagWrite_OutOfRange_Rejected(double v) =>
        Assert.Throws<TagWriteRejectedException>(() => TagWriteValidator.ToRawValue(Setpoint, v));

    [Fact]
    public void TagWrite_ReadOnlyTag_Rejected() =>
        Assert.Throws<TagWriteRejectedException>(() => TagWriteValidator.ToRawValue(Setpoint with { Writable = false }, 50));

    [Fact]
    public void TagWrite_RegisterOverflow_Rejected() =>
        Assert.Throws<TagWriteRejectedException>(() =>
            TagWriteValidator.ToRawValue(Setpoint with { MinValue = null, MaxValue = null }, 10_000));

    [Fact]
    public void License_SignedByVendor_Valid_TamperedRejected()
    {
        using var vendor = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] payload = Encoding.UTF8.GetBytes("{\"customer\":\"ACME\",\"edition\":\"Pro\",\"maxDevices\":50,\"expiresUtc\":\"2030-01-01T00:00:00+00:00\"}");
        string path = Path.Combine(_dir, "license.json");
        File.WriteAllText(path, $"{{\"payload\":\"{Convert.ToBase64String(payload)}\",\"signature\":\"{Convert.ToBase64String(vendor.SignData(payload, HashAlgorithmName.SHA256))}\"}}");

        var validator = new LicenseValidator(vendor.ExportSubjectPublicKeyInfoPem(), TimeProvider.System);
        var ok = validator.Validate(path);
        Assert.True(ok.IsValid, ok.Reason);
        Assert.Equal(50, ok.License!.MaxDevices);

        byte[] forged = Encoding.UTF8.GetBytes("{\"customer\":\"ACME\",\"edition\":\"Pro\",\"maxDevices\":5000,\"expiresUtc\":\"2030-01-01T00:00:00+00:00\"}");
        File.WriteAllText(path, $"{{\"payload\":\"{Convert.ToBase64String(forged)}\",\"signature\":\"{Convert.ToBase64String(vendor.SignData(payload, HashAlgorithmName.SHA256))}\"}}");
        Assert.False(validator.Validate(path).IsValid);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);
}
