using System.Text.Json;
using System.Text.Json.Serialization;
using Indusoft.FieldGateway.Core.Devices;
using Indusoft.FieldGateway.Core.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Indusoft.FieldGateway.Core.Storage;

/// <summary>
/// Last-known-value cache. System.Text.Json with a closed, source-generated type set replaces
/// BinaryFormatter (fixes L01 / CWE-502). Writes are atomic; a corrupt or oversized file is
/// rejected and logged as a security event instead of crashing the service.
/// </summary>
public sealed class DataCache(string path, ILogger<DataCache> logger)
{
    private const long MaxCacheBytes = 16 * 1024 * 1024;

    public async Task SaveAsync(IReadOnlyDictionary<string, TagValue> values, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        string temp = path + ".tmp";
        await using (var fs = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await JsonSerializer.SerializeAsync(fs, values.ToDictionary(kv => kv.Key, kv => kv.Value),
                GatewayJsonContext.Default.DictionaryStringTagValue, ct).ConfigureAwait(false);
        }
        File.Move(temp, path, overwrite: true);
    }

    public async Task<IReadOnlyDictionary<string, TagValue>> LoadAsync(CancellationToken ct)
    {
        var empty = new Dictionary<string, TagValue>();
        if (!File.Exists(path))
            return empty;
        try
        {
            var info = new FileInfo(path);
            if (info.Length > MaxCacheBytes)
                throw new InvalidDataException($"cache file exceeds {MaxCacheBytes} bytes");
            await using var fs = File.OpenRead(path);
            return await JsonSerializer.DeserializeAsync(fs, GatewayJsonContext.Default.DictionaryStringTagValue, ct)
                       .ConfigureAwait(false) ?? empty;
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException or NotSupportedException)
        {
            GatewayLog.CacheRejected(logger, path, ex);
            return empty;
        }
    }
}

/// <summary>Closed set of serializable types: no polymorphic/type-name handling possible.</summary>
[JsonSourceGenerationOptions(WriteIndented = false, UseStringEnumConverter = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(Dictionary<string, TagValue>))]
[JsonSerializable(typeof(TagValue[]))]
public sealed partial class GatewayJsonContext : JsonSerializerContext;
