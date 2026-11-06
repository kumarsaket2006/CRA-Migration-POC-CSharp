using System;

namespace Indusoft.FieldGateway.Core.Modbus
{
    [Serializable]
    public class ModbusException : Exception
    {
        public byte FunctionCode { get; private set; }
        public byte ExceptionCode { get; private set; }

        public ModbusException(string message) : base(message) { }

        public ModbusException(byte functionCode, byte exceptionCode)
            : base(string.Format("Modbus exception: function 0x{0:X2}, code 0x{1:X2}", functionCode, exceptionCode))
        {
            FunctionCode = functionCode;
            ExceptionCode = exceptionCode;
        }
    }
}
