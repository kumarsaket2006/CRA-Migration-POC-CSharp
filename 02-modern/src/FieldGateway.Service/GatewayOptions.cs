using System.ComponentModel.DataAnnotations;

namespace Indusoft.FieldGateway.Service;

/// <summary>Strongly-typed, validated configuration (validated at start-up: fail closed).</summary>
public sealed class GatewayOptions
{
    public const string Section = "Gateway";

    [Required] public string DeviceConfigPath { get; set; } = "";
    [Required] public string CachePath { get; set; } = "";
    [Required] public string FirmwareStagingPath { get; set; } = "";
    [Required] public string LicensePath { get; set; } = "";

    /// <summary>Vendor public key (PEM) used to verify the license file.</summary>
    [Required] public string LicensePublicKeyPem { get; set; } = "";

    /// <summary>Firmware signing public keys (PEM). More than one allows key rotation.</summary>
    [MinLength(1)] public List<string> FirmwarePublicKeysPem { get; set; } = [];

    /// <summary>Device model per device id, used to bind firmware to the right hardware.</summary>
    public Dictionary<string, string> DeviceModels { get; set; } = [];

    /// <summary>Installed firmware version per device id (anti-rollback baseline).</summary>
    public Dictionary<string, string> InstalledFirmware { get; set; } = [];

    /// <summary>Client certificate allow-list (thumbprint -> identity + roles).</summary>
    [MinLength(1)] public List<ClientIdentity> Clients { get; set; } = [];

    [Range(1, 600)] public int CacheFlushSeconds { get; set; } = 10;
}

public sealed class ClientIdentity
{
    [Required, RegularExpression("^[0-9A-Fa-f]{64}$", ErrorMessage = "Use the SHA-256 certificate thumbprint")]
    public string Sha256Thumbprint { get; set; } = "";

    [Required] public string Name { get; set; } = "";

    /// <summary>Operator (read), Engineer (read + write setpoints), Maintainer (read + firmware).</summary>
    [MinLength(1)] public List<string> Roles { get; set; } = [];
}

public sealed class CloudUplinkOptions
{
    public const string Section = "CloudUplink";

    public bool Enabled { get; set; }

    [RegularExpression("^https://.+", ErrorMessage = "Cloud endpoint must use HTTPS")]
    public string Endpoint { get; set; } = "https://localhost/";

    /// <summary>Supplied via secret store / environment (CloudUplink__ApiKey), never appsettings.json.</summary>
    public string ApiKey { get; set; } = "";

    [Range(5, 3600)] public int IntervalSeconds { get; set; } = 30;
}

public static class Roles
{
    public const string Operator = "Operator";
    public const string Engineer = "Engineer";
    public const string Maintainer = "Maintainer";
}

public static class Policies
{
    public const string Read = "fg.read";
    public const string Write = "fg.write";
    public const string Firmware = "fg.firmware";
}
