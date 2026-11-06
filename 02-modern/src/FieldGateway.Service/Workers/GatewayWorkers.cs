using Indusoft.FieldGateway.Core.Diagnostics;
using Indusoft.FieldGateway.Core.Polling;
using Indusoft.FieldGateway.Core.Storage;
using Indusoft.FieldGateway.Service.Historian;
using Microsoft.Extensions.Options;

namespace Indusoft.FieldGateway.Service.Workers;

/// <summary>Seeds from the cache, then runs the poller until shutdown.</summary>
public sealed class PollingWorker(TagPoller poller, DataCache cache) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        poller.Seed(await cache.LoadAsync(stoppingToken));
        await poller.RunAsync(stoppingToken);
    }
}

/// <summary>Periodically persists last-known values; final flush on shutdown.</summary>
public sealed class CacheWorker(TagPoller poller, DataCache cache, IOptions<GatewayOptions> options) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(options.Value.CacheFlushSeconds));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
                await cache.SaveAsync(poller.Snapshot(), stoppingToken);
        }
        finally
        {
            await cache.SaveAsync(poller.Snapshot(), CancellationToken.None);
        }
    }
}

/// <summary>Drains value changes into the historian; failures are logged, never swallowed (fixes L11).</summary>
public sealed class HistorianWorker(TagPoller poller, HistorianRepository historian, ILogger<HistorianWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var value in poller.Changes.ReadAllAsync(stoppingToken))
        {
            try
            {
                await historian.InsertAsync(value, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                GatewayLog.HistorianWriteFailed(logger, ex);
            }
        }
    }
}
