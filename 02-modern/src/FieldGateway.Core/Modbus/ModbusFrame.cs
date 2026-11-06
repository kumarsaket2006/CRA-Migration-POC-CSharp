using System.Buffers.Binary;

namespace Indusoft.FieldGateway.Core.Modbus;

/// <summary>
/// Modbus TCP (MBAP) framing per "MODBUS Messaging on TCP/IP Implementation Guide V1.0b".
/// Every length field received from the network is validated before use (fixes L06 / CWE-125).
/// </summary>
public static class ModbusFrame
{
    public const byte ReadHoldingRegisters = 0x03;
    public const byte ReadInputRegisters = 0x04;
    public const byte WriteSingleRegister = 0x06;
    public const byte WriteMultipleRegisters = 0x10;

    public const int MbapHeaderLength = 7;
    public const int MaxAduLength = 260;
    public const int MaxReadRegisters = 125;
    public const int MaxWriteRegisters = 123;

    public readonly record struct MbapHeader(ushort TransactionId, ushort ProtocolId, ushort Length, byte UnitId)
    {
        /// <summary>Number of PDU bytes that follow the 7-byte header.</summary>
        public int PduLength => Length - 1;
    }

    public static byte[] BuildReadRequest(ushort transactionId, byte unitId, byte functionCode, ushort startAddress, ushort quantity)
    {
        if (functionCode is not (ReadHoldingRegisters or ReadInputRegisters))
            throw new ArgumentOutOfRangeException(nameof(functionCode));
        ValidateRange(startAddress, quantity, MaxReadRegisters);

        var frame = new byte[12];
        WriteHeader(frame, transactionId, 6, unitId);
        frame[7] = functionCode;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(8), startAddress);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(10), quantity);
        return frame;
    }

    public static byte[] BuildWriteSingleRequest(ushort transactionId, byte unitId, ushort address, ushort value)
    {
        var frame = new byte[12];
        WriteHeader(frame, transactionId, 6, unitId);
        frame[7] = WriteSingleRegister;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(8), address);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(10), value);
        return frame;
    }

    public static byte[] BuildWriteMultipleRequest(ushort transactionId, byte unitId, ushort startAddress, ReadOnlySpan<ushort> values)
    {
        ValidateRange(startAddress, values.Length, MaxWriteRegisters);
        int byteCount = values.Length * 2;
        var frame = new byte[13 + byteCount];
        WriteHeader(frame, transactionId, (ushort)(7 + byteCount), unitId);
        frame[7] = WriteMultipleRegisters;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(8), startAddress);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(10), (ushort)values.Length);
        frame[12] = (byte)byteCount;
        for (int i = 0; i < values.Length; i++)
            BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(13 + i * 2), values[i]);
        return frame;
    }

    /// <summary>Parses and validates the 7-byte MBAP header.</summary>
    public static MbapHeader ParseHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length < MbapHeaderLength)
            throw new ModbusProtocolException("Truncated MBAP header");
        var h = new MbapHeader(
            BinaryPrimitives.ReadUInt16BigEndian(header),
            BinaryPrimitives.ReadUInt16BigEndian(header[2..]),
            BinaryPrimitives.ReadUInt16BigEndian(header[4..]),
            header[6]);
        if (h.ProtocolId != 0)
            throw new ModbusProtocolException($"Unexpected protocol id {h.ProtocolId}");
        // Length counts unit id + PDU; a PDU is 1..253 bytes
        if (h.Length < 2 || h.Length > MaxAduLength - 6)
            throw new ModbusProtocolException($"MBAP length {h.Length} out of range");
        return h;
    }

    /// <summary>Parses a read-registers response PDU (function code onwards).</summary>
    public static ushort[] ParseReadResponse(ReadOnlySpan<byte> pdu, byte expectedFunction, ushort expectedQuantity)
    {
        ThrowIfException(pdu, expectedFunction);
        if (pdu.Length < 2)
            throw new ModbusProtocolException("Truncated read response");
        int byteCount = pdu[1];
        if (byteCount != expectedQuantity * 2)
            throw new ModbusProtocolException($"Byte count {byteCount} does not match requested quantity {expectedQuantity}");
        if (pdu.Length != 2 + byteCount)
            throw new ModbusProtocolException($"PDU length {pdu.Length} inconsistent with byte count {byteCount}");

        var registers = new ushort[expectedQuantity];
        for (int i = 0; i < registers.Length; i++)
            registers[i] = BinaryPrimitives.ReadUInt16BigEndian(pdu.Slice(2 + i * 2, 2));
        return registers;
    }

    /// <summary>Validates the echo returned for FC06/FC16.</summary>
    public static void ValidateWriteResponse(ReadOnlySpan<byte> pdu, ReadOnlySpan<byte> requestPdu)
    {
        ThrowIfException(pdu, requestPdu[0]);
        if (pdu.Length != 5 || !pdu[..5].SequenceEqual(requestPdu[..5]))
            throw new ModbusProtocolException("Write response does not echo the request");
    }

    private static void ThrowIfException(ReadOnlySpan<byte> pdu, byte expectedFunction)
    {
        if (pdu.IsEmpty)
            throw new ModbusProtocolException("Empty PDU");
        if (pdu[0] == (expectedFunction | 0x80))
            throw new ModbusException(expectedFunction, pdu.Length > 1 ? pdu[1] : (byte)0);
        if (pdu[0] != expectedFunction)
            throw new ModbusProtocolException($"Unexpected function code 0x{pdu[0]:X2}");
    }

    private static void ValidateRange(ushort start, int quantity, int max)
    {
        if (quantity < 1 || quantity > max)
            throw new ArgumentOutOfRangeException(nameof(quantity), $"Quantity must be 1..{max}");
        if (start + quantity > 0x10000)
            throw new ArgumentOutOfRangeException(nameof(start), "Address range exceeds 65535");
    }

    private static void WriteHeader(Span<byte> frame, ushort transactionId, ushort length, byte unitId)
    {
        BinaryPrimitives.WriteUInt16BigEndian(frame, transactionId);
        BinaryPrimitives.WriteUInt16BigEndian(frame[2..], 0);
        BinaryPrimitives.WriteUInt16BigEndian(frame[4..], length);
        frame[6] = unitId;
    }
}
