using System;

namespace Indusoft.FieldGateway.Core.Modbus
{
    /// <summary>
    /// Builds and parses Modbus TCP (MBAP) frames.
    /// MBAP: TransactionId(2) ProtocolId(2) Length(2) UnitId(1) | PDU: FunctionCode(1) Data(n)
    /// </summary>
    public static class ModbusFrame
    {
        public const byte ReadHoldingRegisters = 0x03;
        public const byte ReadInputRegisters = 0x04;
        public const byte WriteSingleRegister = 0x06;
        public const byte WriteMultipleRegisters = 0x10;

        public static byte[] BuildReadRequest(ushort transactionId, byte unitId, byte functionCode, ushort startAddress, ushort quantity)
        {
            byte[] frame = new byte[12];
            WriteHeader(frame, transactionId, 6, unitId);
            frame[7] = functionCode;
            frame[8] = (byte)(startAddress >> 8);
            frame[9] = (byte)(startAddress & 0xFF);
            frame[10] = (byte)(quantity >> 8);
            frame[11] = (byte)(quantity & 0xFF);
            return frame;
        }

        public static byte[] BuildWriteSingleRequest(ushort transactionId, byte unitId, ushort address, ushort value)
        {
            byte[] frame = new byte[12];
            WriteHeader(frame, transactionId, 6, unitId);
            frame[7] = WriteSingleRegister;
            frame[8] = (byte)(address >> 8);
            frame[9] = (byte)(address & 0xFF);
            frame[10] = (byte)(value >> 8);
            frame[11] = (byte)(value & 0xFF);
            return frame;
        }

        public static byte[] BuildWriteMultipleRequest(ushort transactionId, byte unitId, ushort startAddress, ushort[] values)
        {
            // LEGACY-ISSUE: L06 No validation of quantity (spec max 123 registers); oversize arrays silently truncate the length byte
            int byteCount = values.Length * 2;
            byte[] frame = new byte[13 + byteCount];
            WriteHeader(frame, transactionId, (ushort)(7 + byteCount), unitId);
            frame[7] = WriteMultipleRegisters;
            frame[8] = (byte)(startAddress >> 8);
            frame[9] = (byte)(startAddress & 0xFF);
            frame[10] = (byte)(values.Length >> 8);
            frame[11] = (byte)(values.Length & 0xFF);
            frame[12] = (byte)byteCount;
            for (int i = 0; i < values.Length; i++)
            {
                frame[13 + i * 2] = (byte)(values[i] >> 8);
                frame[14 + i * 2] = (byte)(values[i] & 0xFF);
            }
            return frame;
        }

        /// <summary>Parses a read response and returns register values.</summary>
        public static ushort[] ParseReadResponse(byte[] response, byte expectedFunction)
        {
            byte function = response[7];
            if ((function & 0x80) != 0)
            {
                throw new ModbusException(expectedFunction, response[8]);
            }

            // LEGACY-ISSUE: L06 Byte count is taken from the device and trusted; no check against the
            // received buffer length or MBAP length -> IndexOutOfRange / over-read on malformed frames (CWE-125)
            int byteCount = response[8];
            ushort[] registers = new ushort[byteCount / 2];
            for (int i = 0; i < registers.Length; i++)
            {
                registers[i] = (ushort)((response[9 + i * 2] << 8) | response[10 + i * 2]);
            }
            return registers;
        }

        public static ushort GetTransactionId(byte[] frame)
        {
            return (ushort)((frame[0] << 8) | frame[1]);
        }

        public static ushort GetLength(byte[] frame)
        {
            return (ushort)((frame[4] << 8) | frame[5]);
        }

        private static void WriteHeader(byte[] frame, ushort transactionId, ushort length, byte unitId)
        {
            frame[0] = (byte)(transactionId >> 8);
            frame[1] = (byte)(transactionId & 0xFF);
            frame[2] = 0;
            frame[3] = 0;
            frame[4] = (byte)(length >> 8);
            frame[5] = (byte)(length & 0xFF);
            frame[6] = unitId;
        }
    }
}
