using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Indusoft.FieldGateway.Simulator
{
    /// <summary>Minimal Modbus TCP slave (FC 03/04/06/16) with a simulated process.</summary>
    public class ModbusSlaveSimulator
    {
        private readonly ushort[] _holding = new ushort[1000];
        private readonly ushort[] _input = new ushort[1000];
        private readonly TcpListener _listener;
        private readonly Random _rnd = new Random();
        private volatile bool _running;

        public ModbusSlaveSimulator(int port)
        {
            _listener = new TcpListener(IPAddress.Any, port);
        }

        public void Start()
        {
            _running = true;
            _listener.Start();
            new Thread(SimulateProcess) { IsBackground = true }.Start();
            new Thread(AcceptLoop) { IsBackground = true }.Start();
        }

        public void Stop()
        {
            _running = false;
            _listener.Stop();
        }

        private void SimulateProcess()
        {
            while (_running)
            {
                lock (_holding)
                {
                    _input[100] = (ushort)(650 + _rnd.Next(-20, 20));   // temperature x0.1 degC
                    _input[101] = (ushort)(1013 + _rnd.Next(-5, 5));    // pressure mbar
                    _input[102] = (ushort)(_rnd.Next(1400, 1500));      // motor rpm
                }
                Thread.Sleep(500);
            }
        }

        private void AcceptLoop()
        {
            while (_running)
            {
                try
                {
                    TcpClient c = _listener.AcceptTcpClient();
                    new Thread(() => Serve(c)) { IsBackground = true }.Start();
                }
                catch (SocketException) { }
            }
        }

        private void Serve(TcpClient client)
        {
            using (client)
            using (NetworkStream s = client.GetStream())
            {
                byte[] buf = new byte[260];
                while (_running && client.Connected)
                {
                    int n = s.Read(buf, 0, buf.Length);
                    if (n < 12) return;
                    byte fc = buf[7];
                    ushort addr = (ushort)((buf[8] << 8) | buf[9]);
                    ushort qty = (ushort)((buf[10] << 8) | buf[11]);
                    byte[] resp;
                    lock (_holding)
                    {
                        if (fc == 0x03 || fc == 0x04)
                        {
                            ushort[] table = fc == 0x03 ? _holding : _input;
                            resp = new byte[9 + qty * 2];
                            resp[8] = (byte)(qty * 2);
                            for (int i = 0; i < qty; i++)
                            {
                                resp[9 + i * 2] = (byte)(table[addr + i] >> 8);
                                resp[10 + i * 2] = (byte)(table[addr + i] & 0xFF);
                            }
                        }
                        else if (fc == 0x06)
                        {
                            _holding[addr] = qty;
                            resp = new byte[12];
                            Array.Copy(buf, 8, resp, 8, 4);
                        }
                        else
                        {
                            resp = new byte[9];
                            fc |= 0x80;
                            resp[8] = 0x01; // illegal function
                        }
                    }
                    Array.Copy(buf, 0, resp, 0, 4);
                    int len = resp.Length - 6;
                    resp[4] = (byte)(len >> 8);
                    resp[5] = (byte)(len & 0xFF);
                    resp[6] = buf[6];
                    resp[7] = fc;
                    s.Write(resp, 0, resp.Length);
                }
            }
        }
    }
}
