namespace Indusoft.FieldGateway.Core.Modbus;

/// <summary>The device answered with a Modbus exception response.</summary>
public sealed class ModbusException(byte functionCode, byte exceptionCode)
    : Exception($"Modbus exception: function 0x{functionCode:X2}, code 0x{exceptionCode:X2}")
{
    public byte FunctionCode { get; } = functionCode;
    public byte ExceptionCode { get; } = exceptionCode;
}

/// <summary>A frame violated the Modbus TCP specification (malformed, truncated, mismatched).</summary>
public sealed class ModbusProtocolException(string message) : Exception(message);
