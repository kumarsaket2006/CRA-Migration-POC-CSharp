using System;
using System.Net.Sockets;
using System.Threading;
using log4net;

namespace Indusoft.FieldGateway.Core.Modbus
{
    /// <summary>
    /// Modbus TCP master using the APM (Begin/End) pattern. Not thread-safe across transactions.
    /// </summary>
    public class ModbusTcpClient : IDisposable
    {
        private static readonly ILog Log = LogManager.GetLogger(typeof(ModbusTcpClient));

        private readonly string _host;
        private readonly int _port;
        private TcpClient _client;
        private NetworkStream _stream;
        private int _transactionId;
        private readonly object _sync = new object();

        public int TimeoutMs { get; set; }

        public ModbusTcpClient(string host, int port)
        {
            _host = host;
            _port = port;
            TimeoutMs = 3000;
        }

        public bool IsConnected
        {
            get { return _client != null && _client.Connected; }
        }

        public void Connect()
        {
            _client = new TcpClient();
            IAsyncResult ar = _client.BeginConnect(_host, _port, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(TimeoutMs))
            {
                _client.Close();
                throw new TimeoutException("Connect timeout to " + _host);
            }
            _client.EndConnect(ar);
            _stream = _client.GetStream();
            Log.Info("Connected to PLC " + _host + ":" + _port);
        }

        public ushort[] ReadHoldingRegisters(byte unitId, ushort start, ushort count)
        {
            return ReadRegisters(unitId, ModbusFrame.ReadHoldingRegisters, start, count);
        }

        public ushort[] ReadInputRegisters(byte unitId, ushort start, ushort count)
        {
            return ReadRegisters(unitId, ModbusFrame.ReadInputRegisters, start, count);
        }

        public void WriteSingleRegister(byte unitId, ushort address, ushort value)
        {
            lock (_sync)
            {
                byte[] request = ModbusFrame.BuildWriteSingleRequest(NextTransactionId(), unitId, address, value);
                Transact(request);
            }
        }

        public void WriteMultipleRegisters(byte unitId, ushort start, ushort[] values)
        {
            lock (_sync)
            {
                byte[] request = ModbusFrame.BuildWriteMultipleRequest(NextTransactionId(), unitId, start, values);
                Transact(request);
            }
        }

        private ushort[] ReadRegisters(byte unitId, byte function, ushort start, ushort count)
        {
            lock (_sync)
            {
                byte[] request = ModbusFrame.BuildReadRequest(NextTransactionId(), unitId, function, start, count);
                byte[] response = Transact(request);
                return ModbusFrame.ParseReadResponse(response, function);
            }
        }

        private byte[] Transact(byte[] request)
        {
            // LEGACY-ISSUE: L08 Raw frames written to the log at INFO level (process data disclosure)
            Log.Info("TX " + BitConverter.ToString(request));

            IAsyncResult w = _stream.BeginWrite(request, 0, request.Length, null, null);
            _stream.EndWrite(w);

            // LEGACY-ISSUE: L06 Fixed 260-byte buffer, single Read() call assumes a whole frame arrives at once;
            // transaction id of the response is never compared to the request
            byte[] buffer = new byte[260];
            IAsyncResult r = _stream.BeginRead(buffer, 0, buffer.Length, null, null);
            if (!r.AsyncWaitHandle.WaitOne(TimeoutMs))
            {
                throw new TimeoutException("Read timeout");
            }
            int read = _stream.EndRead(r);
            Log.Info("RX " + BitConverter.ToString(buffer, 0, read));
            return buffer;
        }

        private ushort NextTransactionId()
        {
            return (ushort)Interlocked.Increment(ref _transactionId);
        }

        public void Dispose()
        {
            try
            {
                if (_stream != null) _stream.Close();
                if (_client != null) _client.Close();
            }
            catch
            {
                // LEGACY-ISSUE: L11 Exceptions swallowed silently
            }
        }
    }
}
