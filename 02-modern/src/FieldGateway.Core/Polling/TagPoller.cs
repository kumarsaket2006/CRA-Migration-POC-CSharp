using System.Collections.Concurrent;
using System.Threading.Channels;
using Indusoft.FieldGateway.Core.Devices;
using Indusoft.FieldGateway.Core.Diagnostics;
using Indusoft.FieldGateway.Core.Modbus;
using Microsoft.Extensions.Logging;

namespace Indusoft.FieldGateway.Core.Polling;

/// <summary>
/// Polls every registered device on its own async loop with cooperative cancellation
/// (replaces Thread/Thread.Abort, fixes L11/L12). Changed values are published on a bounded channel.
/// </summary>
public sealed class TagPoller(DeviceRegistry registry, IModbusClientFactory clients, ILogger<TagPoller> logger)
{
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(30);
    private readonly ConcurrentDictionary<string, TagValue> _last = new(StringComparer.Ordinal);
    private readonly Channel<TagValue> _changes = Channel.CreateBounded<TagValue>(
        new BoundedChannelOptions(10_000) { FullMode = BoundedChannelFullMode.DropOldest, SingleWriter = false });

    public ChannelReader<TagValue> Changes => _changes.Reader;

    public IReadOnlyDictionary<string, TagValue> Snapshot() => new Dictionary<string, TagValue>(_last, StringComparer.Ordinal);

    public void Seed(IReadOnlyDictionary<string, TagValue> values)
    {
        foreach (var kv in values)
            _last.TryAdd(kv.Key, kv.Value with { Quality = TagQuality.Uncertain });
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var devices = registry.All();
        GatewayLog.PollingStarted(logger, devices.Count);
        await Task.WhenAll(devices.Select(d => PollDeviceAsync(d, ct))).ConfigureAwait(false);
        _changes.Writer.TryComplete();
    }

    private async Task PollDeviceAsync(FieldDevice device, CancellationToken ct)
    {
        await using var client = clients.Create(device.Host, device.Port);
        using var timer = new PeriodicTimer(device.PollInterval);
        var backoff = device.PollInterval;
        try
        {
            do
            {
                try
                {
                    foreach (var tag in device.Tags)
                    {
                        byte fc = tag.IsInput ? ModbusFrame.ReadInputRegisters : ModbusFrame.ReadHoldingRegisters;
                        var regs = await client.ReadRegistersAsync(device.UnitId, fc, tag.Address, 1, ct).ConfigureAwait(false);
                        Publish(new TagValue(device.Id, tag.Name, regs[0] * tag.Scale, DateTimeOffset.UtcNow, TagQuality.Good));
                    }
                    backoff = device.PollInterval;
                }
                catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
                {
                    MarkBad(device);
                    backoff = TimeSpan.FromTicks(Math.Min(backoff.Ticks * 2, MaxBackoff.Ticks));
                    GatewayLog.PollFailed(logger, device.Id, (int)backoff.TotalMilliseconds, ex);
                    await Task.Delay(backoff, ct).ConfigureAwait(false);
                }
            }
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // normal shutdown
        }
    }

    private void Publish(TagValue value)
    {
        bool changed = !_last.TryGetValue(value.Key, out var old) || old.Value != value.Value || old.Quality != value.Quality;
        _last[value.Key] = value;
        if (changed)
            _changes.Writer.TryWrite(value);
    }

    private void MarkBad(FieldDevice device)
    {
        foreach (var tag in device.Tags)
        {
            string key = device.Id + "." + tag.Name;
            if (_last.TryGetValue(key, out var v) && v.Quality != TagQuality.Bad)
                Publish(v with { Quality = TagQuality.Bad, Timestamp = DateTimeOffset.UtcNow });
        }
    }
}
