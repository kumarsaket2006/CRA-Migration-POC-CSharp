using System.Net.Http.Json;
using Indusoft.FieldGateway.Core.Diagnostics;
using Indusoft.FieldGateway.Core.Polling;
using Indusoft.FieldGateway.Core.Storage;
using Microsoft.Extensions.Options;

namespace Indusoft.FieldGateway.Service.Cloud;

/// <summary>
/// Pushes snapshots to the vendor cloud. Uses the platform TLS defaults (TLS 1.2/1.3, full certificate
/// validation), HTTPS-only endpoint enforced by options validation, API key in a header taken from the
/// secret store, typed JSON without type names (fixes L01/L05/L08). Disabled by default (secure by default).
/// </summary>
public sealed class CloudUplink(IHttpClientFactory httpFactory, TagPoller poller, IOptions<CloudUplinkOptions> options, ILogger<CloudUplink> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var o = options.Value;
        if (!o.Enabled)
            return;
        var http = httpFactory.CreateClient(nameof(CloudUplink));
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(o.IntervalSeconds));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, o.Endpoint)
            {
                Content = JsonContent.Create(poller.Snapshot().Values.ToArray(), GatewayJsonContext.Default.TagValueArray),
            };
            request.Headers.Add("X-Api-Key", o.ApiKey);
            try
            {
                using var response = await http.SendAsync(request, stoppingToken);
                if (!response.IsSuccessStatusCode)
                    GatewayLog.CloudUplinkFailed(logger, (int)response.StatusCode);
            }
            catch (HttpRequestException ex)
            {
                GatewayLog.CloudUplinkFailed(logger, (int?)ex.StatusCode ?? 0);
            }
        }
    }
}
