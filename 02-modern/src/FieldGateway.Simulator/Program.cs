using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

// Modbus TCP slave simulator (FC 03/04/06). Binds to loopback by default; every request is bounds-checked.
int port = args.Length > 0 ? int.Parse(args[0], CultureInfo.InvariantCulture) : 1502;
var bind = args.Length > 1 ? IPAddress.Parse(args[1]) : IPAddress.Loopback;

var holding = new ushort[1000];
var input = new ushort[1000];
var sync = new object();
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

_ = Task.Run(async () =>
{
    while (!cts.IsCancellationRequested)
    {
        lock (sync)
        {
            input[100] = (ushort)(650 + RandomNumberGenerator.GetInt32(-20, 20)); // temperature x0.1 degC
            input[101] = (ushort)(1013 + RandomNumberGenerator.GetInt32(-5, 5));  // pressure mbar
            input[102] = (ushort)RandomNumberGenerator.GetInt32(1400, 1500);      // motor rpm
        }
        await Task.Delay(500, cts.Token).ConfigureAwait(false);
    }
});

var listener = new TcpListener(bind, port);
listener.Start();
Console.WriteLine($"Modbus TCP simulator on {bind}:{port}. Ctrl+C to stop.");
try
{
    while (!cts.IsCancellationRequested)
    {
        var client = await listener.AcceptTcpClientAsync(cts.Token);
        _ = ServeAsync(client, cts.Token);
    }
}
catch (OperationCanceledException)
{
}
listener.Stop();

async Task ServeAsync(TcpClient client, CancellationToken ct)
{
    using (client)
    {
        var s = client.GetStream();
        var header = new byte[7];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await s.ReadExactlyAsync(header, ct);
                int len = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(4));
                if (len is < 2 or > 254) return;
                var pdu = new byte[len - 1];
                await s.ReadExactlyAsync(pdu, ct);
                byte[] resp = Handle(pdu);
                var frame = new byte[7 + resp.Length];
                header.AsSpan(0, 4).CopyTo(frame);
                BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(4), (ushort)(resp.Length + 1));
                frame[6] = header[6];
                resp.CopyTo(frame, 7);
                await s.WriteAsync(frame, ct);
            }
        }
        catch (Exception ex) when (ex is EndOfStreamException or IOException or OperationCanceledException)
        {
            // client disconnected
        }
    }
}

byte[] Handle(byte[] pdu)
{
    byte fc = pdu[0];
    if (pdu.Length < 5) return [(byte)(fc | 0x80), 0x03];
    ushort addr = BinaryPrimitives.ReadUInt16BigEndian(pdu.AsSpan(1));
    ushort qty = BinaryPrimitives.ReadUInt16BigEndian(pdu.AsSpan(3));
    lock (sync)
    {
        switch (fc)
        {
            case 0x03 or 0x04:
                if (qty is < 1 or > 125) return [(byte)(fc | 0x80), 0x03];
                if (addr + qty > 1000) return [(byte)(fc | 0x80), 0x02];
                var table = fc == 0x03 ? holding : input;
                var r = new byte[2 + qty * 2];
                r[0] = fc;
                r[1] = (byte)(qty * 2);
                for (int i = 0; i < qty; i++) BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(2 + i * 2), table[addr + i]);
                return r;
            case 0x06:
                if (addr >= 1000) return [(byte)(fc | 0x80), 0x02];
                holding[addr] = qty;
                return pdu[..5];
            default:
                return [(byte)(fc | 0x80), 0x01];
        }
    }
}
