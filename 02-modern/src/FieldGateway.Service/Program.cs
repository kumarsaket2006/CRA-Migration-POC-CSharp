using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Indusoft.FieldGateway.Core.Config;
using Indusoft.FieldGateway.Core.Devices;
using Indusoft.FieldGateway.Core.Diagnostics;
using Indusoft.FieldGateway.Core.Firmware;
using Indusoft.FieldGateway.Core.Licensing;
using Indusoft.FieldGateway.Core.Modbus;
using Indusoft.FieldGateway.Core.Polling;
using Indusoft.FieldGateway.Core.Storage;
using Indusoft.FieldGateway.Service;
using Indusoft.FieldGateway.Service.Cloud;
using Indusoft.FieldGateway.Service.Endpoints;
using Indusoft.FieldGateway.Service.Historian;
using Indusoft.FieldGateway.Service.Security;
using Indusoft.FieldGateway.Service.Workers;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Runs as a Windows Service or a systemd unit (replaces ServiceBase, fixes L12)
builder.Host.UseWindowsService(o => o.ServiceName = "IndusoftFieldGateway");
builder.Host.UseSystemd();

// ---- Configuration (secrets come from environment / user-secrets / Key Vault, never appsettings.json) ----
builder.Services.AddOptions<GatewayOptions>().Bind(builder.Configuration.GetSection(GatewayOptions.Section))
    .ValidateDataAnnotations().ValidateOnStart();
builder.Services.AddOptions<CloudUplinkOptions>().Bind(builder.Configuration.GetSection(CloudUplinkOptions.Section))
    .ValidateDataAnnotations()
    .Validate(o => !o.Enabled || o.ApiKey.Length >= 32, "CloudUplink:ApiKey must be provided via the secret store when enabled")
    .ValidateOnStart();

// ---- Transport security: HTTPS only, client certificate mandatory (fixes L05) ----
// TLS version is deliberately NOT hard-coded (CA5398): the OS policy negotiates TLS 1.2/1.3 and
// legacy protocols are disabled at OS level (see 04-compliance/secure-configuration-guide.md).
builder.WebHost.ConfigureKestrel(k =>
{
    k.AddServerHeader = false;
    k.ConfigureHttpsDefaults(https =>
    {
        https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        https.CheckCertificateRevocation = true;
    });
});

builder.Services.AddSingleton<CertificateIdentityMapper>();
builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(o =>
    {
        o.AllowedCertificateTypes = CertificateTypes.Chained;
        o.RevocationMode = X509RevocationMode.Online;
        o.ValidateValidityPeriod = true;
        o.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = ctx => ctx.HttpContext.RequestServices.GetRequiredService<CertificateIdentityMapper>().OnCertificateValidated(ctx),
            OnAuthenticationFailed = ctx => ctx.HttpContext.RequestServices.GetRequiredService<CertificateIdentityMapper>().OnAuthenticationFailed(ctx),
        };
    });

// Role-based access control: least privilege per operation (IEC 62443-4-2 CR 2.1)
builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
    .AddPolicy(Policies.Read, p => p.RequireRole(Roles.Operator, Roles.Engineer, Roles.Maintainer))
    .AddPolicy(Policies.Write, p => p.RequireRole(Roles.Engineer))
    .AddPolicy(Policies.Firmware, p => p.RequireRole(Roles.Maintainer));

// Abuse resistance (CRA Annex I Part I (2)(h): availability, resilience against denial of service)
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("per-client", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.User.Identity?.Name ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 120, Window = TimeSpan.FromMinutes(1) }));
});

// RFC 7807 errors without stack traces (fixes includeExceptionDetailInFaults, CWE-209)
builder.Services.AddProblemDetails();

// ---- Domain services ----
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<DeviceRegistry>();
builder.Services.AddSingleton<IModbusClientFactory, ModbusTcpClientFactory>();
builder.Services.AddSingleton<TagPoller>();
builder.Services.AddSingleton(sp => new DataCache(sp.GetRequiredService<IOptions<GatewayOptions>>().Value.CachePath,
    sp.GetRequiredService<ILogger<DataCache>>()));
builder.Services.AddSingleton(sp => new FirmwarePackageVerifier(sp.GetRequiredService<IOptions<GatewayOptions>>().Value.FirmwarePublicKeysPem));
builder.Services.AddSingleton(sp => new HistorianRepository(
    builder.Configuration.GetConnectionString("Historian")
    ?? throw new InvalidOperationException("ConnectionStrings:Historian must be provided via the secret store")));
builder.Services.AddHostedService<PollingWorker>();
builder.Services.AddHostedService<CacheWorker>();
builder.Services.AddHostedService<HistorianWorker>();
builder.Services.AddHttpClient(nameof(CloudUplink), c => c.Timeout = TimeSpan.FromSeconds(15));
builder.Services.AddHostedService<CloudUplink>();

var app = builder.Build();

// ---- Start-up checks: fail closed on invalid configuration ----
var gw = app.Services.GetRequiredService<IOptions<GatewayOptions>>().Value;
var startupLog = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
try
{
    var devices = DeviceConfigLoader.LoadFromFile(gw.DeviceConfigPath);
    app.Services.GetRequiredService<DeviceRegistry>().ReplaceAll(devices);
    GatewayLog.ConfigLoaded(startupLog, devices.Count, gw.DeviceConfigPath);
}
catch (ConfigValidationException ex)
{
    GatewayLog.ConfigRejected(startupLog, gw.DeviceConfigPath, string.Join(" | ", ex.Errors));
    throw;
}

var license = new LicenseValidator(gw.LicensePublicKeyPem, app.Services.GetRequiredService<TimeProvider>()).Validate(gw.LicensePath);
if (!license.IsValid)
    GatewayLog.LicenseInvalid(startupLog, license.Reason!);

app.UseExceptionHandler();
app.UseHsts();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.MapGatewayApi();

await app.RunAsync();
