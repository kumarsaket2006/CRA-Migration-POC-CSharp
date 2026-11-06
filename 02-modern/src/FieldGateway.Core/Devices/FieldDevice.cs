using System.Collections.Concurrent;

namespace Indusoft.FieldGateway.Core.Devices;

/// <summary>Immutable device definition. Credentials are deliberately NOT part of the model (fixes L04/L08).</summary>
public sealed record FieldDevice(
    string Id,
    string Name,
    string Host,
    int Port,
    byte UnitId,
    TimeSpan PollInterval,
    IReadOnlyList<TagDefinition> Tags)
{
    public TagDefinition? FindTag(string name) => Tags.FirstOrDefault(t => string.Equals(t.Name, name, StringComparison.Ordinal));
}

public sealed record TagDefinition(
    string Name,
    ushort Address,
    bool IsInput,
    bool Writable,
    double Scale,
    string? Unit,
    double? MinValue = null,
    double? MaxValue = null);

public enum TagQuality { Good, Uncertain, Bad }

public sealed record TagValue(string DeviceId, string TagName, double Value, DateTimeOffset Timestamp, TagQuality Quality)
{
    public string Key => DeviceId + "." + TagName;
}

/// <summary>Thread-safe registry of configured devices (DI singleton instead of a static singleton).</summary>
public sealed class DeviceRegistry
{
    private readonly ConcurrentDictionary<string, FieldDevice> _devices = new(StringComparer.Ordinal);

    public void ReplaceAll(IEnumerable<FieldDevice> devices)
    {
        _devices.Clear();
        foreach (var d in devices)
            _devices[d.Id] = d;
    }

    public FieldDevice? Find(string id) => _devices.TryGetValue(id, out var d) ? d : null;

    public IReadOnlyCollection<FieldDevice> All() => _devices.Values.ToArray();
}
