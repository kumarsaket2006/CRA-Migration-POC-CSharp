using Indusoft.FieldGateway.Core.Modbus;
using NUnit.Framework;

namespace Indusoft.FieldGateway.Tests
{
    [TestFixture]
    public class ModbusFrameTests
    {
        [Test]
        public void BuildReadRequest_ProducesMbapHeaderAndPdu()
        {
            byte[] f = ModbusFrame.BuildReadRequest(0x0102, 0x11, ModbusFrame.ReadHoldingRegisters, 100, 2);
            CollectionAssert.AreEqual(new byte[] { 0x01, 0x02, 0, 0, 0, 6, 0x11, 0x03, 0, 100, 0, 2 }, f);
        }

        [Test]
        public void ParseReadResponse_ReturnsRegisters()
        {
            byte[] resp = { 0, 1, 0, 0, 0, 7, 1, 0x03, 4, 0x01, 0x02, 0x03, 0x04 };
            ushort[] regs = ModbusFrame.ParseReadResponse(resp, ModbusFrame.ReadHoldingRegisters);
            Assert.AreEqual(0x0102, regs[0]);
            Assert.AreEqual(0x0304, regs[1]);
        }

        [Test]
        public void ParseReadResponse_ExceptionResponse_Throws()
        {
            byte[] resp = { 0, 1, 0, 0, 0, 3, 1, 0x83, 0x02 };
            Assert.Throws<ModbusException>(() => ModbusFrame.ParseReadResponse(resp, ModbusFrame.ReadHoldingRegisters));
        }
    }
}
