using System.Security.Cryptography;
using Indusoft.FieldGateway.Core.Devices;
using Indusoft.FieldGateway.Core.Diagnostics;
using Indusoft.FieldGateway.Core.Firmware;
using Indusoft.FieldGateway.Core.Modbus;
using Indusoft.FieldGateway.Core.Polling;
using Indusoft.FieldGateway.Service.Historian;
using Indusoft.FieldGateway.Service.Security;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Options;

namespace Indusoft.FieldGateway.Service.Endpoints;

/// <summary>
/// Versioned REST API replacing the WCF contract (fixes L12). Every route requires an authenticated
/// client certificate and a role-based policy; inputs are typed and validated (fixes L05/L07/L10).
/// </summary>
public static class GatewayEndpoints
{
    public sealed record DeviceDto(string Id, string Name, string Host, int Port, IEnumerable<TagDto> Tags);
    public sealed record TagDto(string Name, bool Writable, string? Unit, double? Min, double? Max);
    public sealed record TagValueDto(string Device, string Tag, double Value, DateTimeOffset Timestamp, string Quality);
    public sealed record WriteTagRequest(double Value);
    public sealed record FirmwareResult(string Status, string? Version, string? Sha256);

    private static readonly TimeSpan MaxHistoryWindow = TimeSpan.FromDays(31);

    public static IEndpointRouteBuilder MapGatewayApi(this IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api/v1").RequireAuthorization(Policies.Read).RequireRateLimiting("per-client");

        api.MapGet("/devices", (DeviceRegistry registry) =>
            registry.All().Select(d => new DeviceDto(d.Id, d.Name, d.Host, d.Port,
                d.Tags.Select(t => new TagDto(t.Name, t.Writable, t.Unit, t.MinValue, t.MaxValue)))));

        api.MapGet("/devices/{deviceId}/tags/{tag}", Results<Ok<TagValueDto>, NotFound> (string deviceId, string tag, TagPoller poller) =>
            poller.Snapshot().TryGetValue(deviceId + "." + tag, out var v)
                ? TypedResults.Ok(new TagValueDto(v.DeviceId, v.TagName, v.Value, v.Timestamp, v.Quality.ToString()))
                : TypedResults.NotFound());

        api.MapPut("/devices/{deviceId}/tags/{tag}", WriteTagAsync).RequireAuthorization(Policies.Write);

        api.MapPost("/devices/{deviceId}/firmware", UploadFirmwareAsync)
           .RequireAuthorization(Policies.Firmware)
           .WithMetadata(new RequestSizeLimitAttributeMetadata(FirmwarePackageVerifier.MaxImageBytes + 1024 * 1024));

        api.MapGet("/history", QueryHistoryAsync);
        return app;
    }

    private static async Task<Results<NoContent, NotFound, ValidationProblem>> WriteTagAsync(
        string deviceId, string tag, WriteTagRequest body, HttpContext http, DeviceRegistry registry,
        IModbusClientFactory clients, ILogger<TagPoller> log, CancellationToken ct)
    {
        string client = CertificateIdentityMapper.ClientName(http.User);
        var device = registry.Find(deviceId);
        var def = device?.FindTag(tag);
        if (device is null || def is null)
            return TypedResults.NotFound();

        ushort raw;
        try
        {
            raw = TagWriteValidator.ToRawValue(def, body.Value);
        }
        catch (TagWriteRejectedException ex)
        {
            GatewayLog.TagWriteRejected(log, client, deviceId, tag, ex.Message);
            return TypedResults.ValidationProblem(new Dictionary<string, string[]> { ["value"] = [ex.Message] });
        }

        await using var modbus = clients.Create(device.Host, device.Port);
        await modbus.WriteSingleRegisterAsync(device.UnitId, def.Address, raw, ct);
        GatewayLog.TagWritten(log, client, deviceId, tag, body.Value);
        return TypedResults.NoContent();
    }

    /// <summary>Body: application/octet-stream signed bundle. The caller never chooses a file name (fixes L10 / CWE-22).</summary>
    private static async Task<Results<Ok<FirmwareResult>, NotFound, UnprocessableEntity<FirmwareResult>, BadRequest>> UploadFirmwareAsync(
        string deviceId, HttpRequest request, DeviceRegistry registry, FirmwarePackageVerifier verifier,
        IOptions<GatewayOptions> options, ILogger<FirmwarePackageVerifier> log, CancellationToken ct)
    {
        string client = CertificateIdentityMapper.ClientName(request.HttpContext.User);
        var opts = options.Value;
        if (registry.Find(deviceId) is null || !opts.DeviceModels.TryGetValue(deviceId, out var model))
            return TypedResults.NotFound();
        if (!string.Equals(request.ContentType, "application/octet-stream", StringComparison.OrdinalIgnoreCase))
            return TypedResults.BadRequest();

        using var buffer = new MemoryStream();
        await request.Body.CopyToAsync(buffer, ct);
        buffer.Position = 0;

        var installed = Version.TryParse(opts.InstalledFirmware.GetValueOrDefault(deviceId), out var v) ? v : new Version(0, 0);
        var result = verifier.Verify(buffer, model, installed);
        if (!result.Accepted)
        {
            GatewayLog.FirmwareRejected(log, client, deviceId, result.Reason!);
            return TypedResults.UnprocessableEntity(new FirmwareResult("rejected", null, null));
        }

        // Server-generated path inside the staging root only
        string dir = Path.Combine(Path.GetFullPath(opts.FirmwareStagingPath), deviceId);
        Directory.CreateDirectory(dir);
        string target = Path.Combine(dir, $"{result.Manifest!.Version}-{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(target, result.Image!, ct);

        string sha = Convert.ToHexString(SHA256.HashData(result.Image!));
        GatewayLog.FirmwareStaged(log, client, deviceId, result.Manifest.Version, sha);
        return TypedResults.Ok(new FirmwareResult("staged", result.Manifest.Version, sha));
    }

    private static async Task<Results<Ok<IReadOnlyList<HistoryPoint>>, ValidationProblem>> QueryHistoryAsync(
        string deviceId, string tag, DateTimeOffset from, DateTimeOffset to, HistorianRepository historian, CancellationToken ct)
    {
        if (to <= from || to - from > MaxHistoryWindow)
            return TypedResults.ValidationProblem(new Dictionary<string, string[]> { ["to"] = ["range must be positive and at most 31 days"] });
        return TypedResults.Ok(await historian.QueryAsync(deviceId, tag, from, to, ct));
    }

    private sealed class RequestSizeLimitAttributeMetadata(long limit) : Microsoft.AspNetCore.Http.Metadata.IRequestSizeLimitMetadata
    {
        public long? MaxRequestBodySize => limit;
    }
}
