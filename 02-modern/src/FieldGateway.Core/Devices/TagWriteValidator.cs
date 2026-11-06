namespace Indusoft.FieldGateway.Core.Devices;

/// <summary>
/// Enforces the engineering contract for remote writes (fixes L10 / CWE-20, CWE-284):
/// only tags marked writable, within configured engineering limits, representable as a 16-bit register.
/// </summary>
public static class TagWriteValidator
{
    public static ushort ToRawValue(TagDefinition tag, double value)
    {
        if (!tag.Writable)
            throw new TagWriteRejectedException("tag is read-only");
        if (double.IsNaN(value) || double.IsInfinity(value))
            throw new TagWriteRejectedException("value is not a finite number");
        if (tag.MinValue is { } min && value < min)
            throw new TagWriteRejectedException($"value below engineering minimum {min}");
        if (tag.MaxValue is { } max && value > max)
            throw new TagWriteRejectedException($"value above engineering maximum {max}");

        double raw = Math.Round(value / tag.Scale, MidpointRounding.AwayFromZero);
        if (raw < ushort.MinValue || raw > ushort.MaxValue)
            throw new TagWriteRejectedException("value outside 16-bit register range");
        return (ushort)raw;
    }
}

public sealed class TagWriteRejectedException(string reason) : Exception(reason);
