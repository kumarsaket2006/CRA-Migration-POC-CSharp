using Microsoft.Extensions.Logging;

namespace Indusoft.FieldGateway.Core.Diagnostics;

/// <summary>
/// Structured, source-generated log events. Event ids 5000-5999 are SECURITY events and are routed
/// to the audit sink / SIEM (CRA Annex I Part I (2)(l): record and monitor relevant internal activity).
/// No message template contains credentials or raw process frames (fixes L08).
/// </summary>
public static partial class GatewayLog
{
    // ---- Operational (1000-1999) ----
    [LoggerMessage(1001, LogLevel.Information, "Connected to device {Host}:{Port}")]
    public static partial void DeviceConnected(ILogger logger, string host, int port);

    [LoggerMessage(1002, LogLevel.Warning, "Communication with {Host}:{Port} failed ({Reason}); connection reset")]
    public static partial void DeviceCommunicationFailed(ILogger logger, string host, int port, string reason);

    [LoggerMessage(1003, LogLevel.Information, "Polling started for {DeviceCount} devices")]
    public static partial void PollingStarted(ILogger logger, int deviceCount);

    [LoggerMessage(1004, LogLevel.Warning, "Poll of {DeviceId} failed; retry in {DelayMs} ms")]
    public static partial void PollFailed(ILogger logger, string deviceId, int delayMs, Exception exception);

    [LoggerMessage(1005, LogLevel.Warning, "Historian write failed")]
    public static partial void HistorianWriteFailed(ILogger logger, Exception exception);

    [LoggerMessage(1006, LogLevel.Warning, "Cloud uplink failed with status {StatusCode}")]
    public static partial void CloudUplinkFailed(ILogger logger, int statusCode);

    // ---- Security (5000-5999) ----
    [LoggerMessage(5001, LogLevel.Information, "SECURITY config-loaded devices={DeviceCount} source={Source}")]
    public static partial void ConfigLoaded(ILogger logger, int deviceCount, string source);

    [LoggerMessage(5002, LogLevel.Error, "SECURITY config-rejected source={Source} errors={Errors}")]
    public static partial void ConfigRejected(ILogger logger, string source, string errors);

    [LoggerMessage(5010, LogLevel.Warning, "SECURITY authn-failed remote={RemoteIp} reason={Reason}")]
    public static partial void AuthenticationFailed(ILogger logger, string remoteIp, string reason);

    [LoggerMessage(5011, LogLevel.Warning, "SECURITY authz-denied client={Client} remote={RemoteIp} policy={Policy}")]
    public static partial void AuthorizationDenied(ILogger logger, string client, string remoteIp, string policy);

    [LoggerMessage(5020, LogLevel.Information, "SECURITY tag-write client={Client} tag={DeviceId}.{Tag} value={Value}")]
    public static partial void TagWritten(ILogger logger, string client, string deviceId, string tag, double value);

    [LoggerMessage(5021, LogLevel.Warning, "SECURITY tag-write-rejected client={Client} tag={DeviceId}.{Tag} reason={Reason}")]
    public static partial void TagWriteRejected(ILogger logger, string client, string deviceId, string tag, string reason);

    [LoggerMessage(5030, LogLevel.Information, "SECURITY firmware-staged client={Client} device={DeviceId} version={Version} sha256={Sha256}")]
    public static partial void FirmwareStaged(ILogger logger, string client, string deviceId, string version, string sha256);

    [LoggerMessage(5031, LogLevel.Warning, "SECURITY firmware-rejected client={Client} device={DeviceId} reason={Reason}")]
    public static partial void FirmwareRejected(ILogger logger, string client, string deviceId, string reason);

    [LoggerMessage(5040, LogLevel.Warning, "SECURITY cache-integrity-failed path={Path}; starting with empty cache")]
    public static partial void CacheRejected(ILogger logger, string path, Exception exception);

    [LoggerMessage(5050, LogLevel.Warning, "SECURITY license-invalid reason={Reason}; running in restricted mode")]
    public static partial void LicenseInvalid(ILogger logger, string reason);
}
