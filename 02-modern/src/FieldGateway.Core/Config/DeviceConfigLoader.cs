using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Indusoft.FieldGateway.Core.Devices;

namespace Indusoft.FieldGateway.Core.Config;

/// <summary>
/// Loads and validates the device configuration XML (format kept compatible with v2.x).
/// Hardened parser: DTDs prohibited, no resolver, size-capped (fixes L02 / CWE-611, CWE-776).
/// Secrets are rejected in this file; they come from the secret store (fixes L04).
/// </summary>
public static partial class DeviceConfigLoader
{
    private const long MaxDocumentChars = 1_000_000;

    public static IReadOnlyList<FieldDevice> LoadFromFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Load(stream);
    }

    public static IReadOnlyList<FieldDevice> LoadFromXml(string xml)
    {
        using var reader = new StringReader(xml);
        return Load(XmlReader.Create(reader, SecureSettings()));
    }

    public static IReadOnlyList<FieldDevice> Load(Stream stream) => Load(XmlReader.Create(stream, SecureSettings()));

    internal static XmlReaderSettings SecureSettings() => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersInDocument = MaxDocumentChars,
        MaxCharactersFromEntities = 0,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
    };

    private static List<FieldDevice> Load(XmlReader reader)
    {
        XDocument doc;
        using (reader)
        {
            try
            {
                doc = XDocument.Load(reader, LoadOptions.SetLineInfo);
            }
            catch (XmlException ex)
            {
                throw new ConfigValidationException([$"XML rejected: {ex.Message}"]);
            }
        }

        var errors = new List<string>();
        var devices = new List<FieldDevice>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        if (doc.Root?.Name.LocalName != "Gateway")
            throw new ConfigValidationException(["Root element must be <Gateway>"]);

        foreach (var d in doc.Root.Elements("Device"))
        {
            string where = $"Device line {((IXmlLineInfo)d).LineNumber}";
            if (d.Attribute("password") is not null)
                errors.Add($"{where}: 'password' attribute is not allowed - store device credentials in the secret store");

            string id = Req(d, "id", where, errors);
            if (id.Length > 0 && !IdPattern().IsMatch(id))
                errors.Add($"{where}: id '{id}' must match {IdPattern()}");
            if (!ids.Add(id))
                errors.Add($"{where}: duplicate device id '{id}'");

            string host = Req(d, "ip", where, errors);
            int port = Int(d, "port", 502, 1, 65535, where, errors);
            int unit = Int(d, "unit", 1, 0, 247, where, errors);
            int poll = Int(d, "poll", 1000, 100, 3_600_000, where, errors);

            var tags = new List<TagDefinition>();
            foreach (var t in d.Elements("Tag"))
            {
                string tw = $"Tag line {((IXmlLineInfo)t).LineNumber}";
                string name = Req(t, "name", tw, errors);
                int addr = Int(t, "address", -1, 0, 65535, tw, errors);
                double scale = Dbl(t, "scale", 1.0, tw, errors);
                if (scale == 0) errors.Add($"{tw}: scale must not be 0");
                double? min = t.Attribute("min") is null ? null : Dbl(t, "min", 0, tw, errors);
                double? max = t.Attribute("max") is null ? null : Dbl(t, "max", 0, tw, errors);
                bool writable = Bool(t, "writable");
                if (writable && (min is null || max is null))
                    errors.Add($"{tw}: writable tag '{name}' requires min and max engineering limits");
                tags.Add(new TagDefinition(name, (ushort)Math.Max(addr, 0), Bool(t, "input"), writable, scale,
                    (string?)t.Attribute("unit"), min, max));
            }

            devices.Add(new FieldDevice(id, (string?)d.Attribute("name") ?? id, host, port, (byte)Math.Max(unit, 0),
                TimeSpan.FromMilliseconds(poll), tags));
        }

        if (errors.Count > 0)
            throw new ConfigValidationException(errors);
        return devices;
    }

    private static string Req(XElement e, string name, string where, List<string> errors)
    {
        var v = (string?)e.Attribute(name);
        if (string.IsNullOrWhiteSpace(v))
        {
            errors.Add($"{where}: attribute '{name}' is required");
            return string.Empty;
        }
        return v.Trim();
    }

    private static int Int(XElement e, string name, int def, int min, int max, string where, List<string> errors)
    {
        var a = (string?)e.Attribute(name);
        if (a is null)
        {
            if (def < min) errors.Add($"{where}: attribute '{name}' is required");
            return def;
        }
        if (!int.TryParse(a, NumberStyles.Integer, CultureInfo.InvariantCulture, out int v) || v < min || v > max)
        {
            errors.Add($"{where}: '{name}' must be an integer {min}..{max}");
            return def;
        }
        return v;
    }

    private static double Dbl(XElement e, string name, double def, string where, List<string> errors)
    {
        var a = (string?)e.Attribute(name);
        if (a is null) return def;
        if (!double.TryParse(a, NumberStyles.Float, CultureInfo.InvariantCulture, out double v) || !double.IsFinite(v))
        {
            errors.Add($"{where}: '{name}' must be a number");
            return def;
        }
        return v;
    }

    private static bool Bool(XElement e, string name) =>
        string.Equals((string?)e.Attribute(name), "true", StringComparison.OrdinalIgnoreCase);

    [GeneratedRegex("^[A-Za-z0-9_-]{1,32}$")]
    private static partial Regex IdPattern();
}

public sealed class ConfigValidationException(IReadOnlyList<string> errors)
    : Exception("Device configuration invalid: " + string.Join("; ", errors))
{
    public IReadOnlyList<string> Errors { get; } = errors;
}
