using Indusoft.FieldGateway.Core.Modbus;

namespace Indusoft.FieldGateway.Tests;

/// <summary>Regression tests for L06 (CWE-125): every malformed frame must be rejected, never over-read.</summary>
public class ModbusFrameTests
{
    [Fact]
    public void BuildReadRequest_ProducesMbapHeaderAndPdu()
    {
        var f = ModbusFrame.BuildReadRequest(0x0102, 0x11, ModbusFrame.ReadHoldingRegisters, 100, 2);
        Assert.Equal(new byte[] { 0x01, 0x02, 0, 0, 0, 6, 0x11, 0x03, 0, 100, 0, 2 }, f);
    }

    [Fact]
    public void ParseReadResponse_ValidFrame_ReturnsRegisters()
    {
        var regs = ModbusFrame.ParseReadResponse(new byte[] { 0x03, 4, 0x01, 0x02, 0x03, 0x04 }, 0x03, 2);
        Assert.Equal(new ushort[] { 0x0102, 0x0304 }, regs);
    }

    [Fact]
    public void ParseReadResponse_ByteCountLargerThanPayload_Rejected()
    {
        // legacy code read 250 bytes past the end of this frame
        Assert.Throws<ModbusProtocolException>(() => ModbusFrame.ParseReadResponse(new byte[] { 0x03, 250, 0x01, 0x02 }, 0x03, 1));
    }

    [Fact]
    public void ParseReadResponse_QuantityMismatch_Rejected() =>
        Assert.Throws<ModbusProtocolException>(() => ModbusFrame.ParseReadResponse(new byte[] { 0x03, 2, 0x01, 0x02 }, 0x03, 2));

    [Fact]
    public void ParseReadResponse_Truncated_Rejected() =>
        Assert.Throws<ModbusProtocolException>(() => ModbusFrame.ParseReadResponse(new byte[] { 0x03 }, 0x03, 1));

    [Fact]
    public void ParseReadResponse_ExceptionResponse_ThrowsModbusException()
    {
        var ex = Assert.Throws<ModbusException>(() => ModbusFrame.ParseReadResponse(new byte[] { 0x83, 0x02 }, 0x03, 1));
        Assert.Equal(0x02, ex.ExceptionCode);
    }

    [Fact]
    public void ParseReadResponse_WrongFunction_Rejected() =>
        Assert.Throws<ModbusProtocolException>(() => ModbusFrame.ParseReadResponse(new byte[] { 0x04, 2, 0, 1 }, 0x03, 1));

    [Theory]
    [InlineData(new byte[] { 0, 1, 0, 1, 0, 6, 1 })]   // protocol id != 0
    [InlineData(new byte[] { 0, 1, 0, 0, 0, 1, 1 })]   // length too small
    [InlineData(new byte[] { 0, 1, 0, 0, 0xFF, 0, 1 })] // length too large
    [InlineData(new byte[] { 0, 1, 0, 0 })]            // truncated
    public void ParseHeader_Invalid_Rejected(byte[] header) =>
        Assert.Throws<ModbusProtocolException>(() => ModbusFrame.ParseHeader(header));

    [Theory]
    [InlineData(0)]
    [InlineData(126)]
    public void BuildReadRequest_QuantityOutOfSpec_Rejected(int qty) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => ModbusFrame.BuildReadRequest(1, 1, 0x03, 0, (ushort)qty));

    [Fact]
    public void BuildWriteMultiple_TooManyRegisters_Rejected() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => ModbusFrame.BuildWriteMultipleRequest(1, 1, 0, new ushort[124]));
}
