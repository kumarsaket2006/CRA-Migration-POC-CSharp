using System.Net.Sockets;
using Indusoft.FieldGateway.Core.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Indusoft.FieldGateway.Core.Modbus;

public interface IModbusClient : IAsyncDisposable
{
    Task<ushort[]> ReadRegistersAsync(byte unitId, byte function, ushort start, ushort count, CancellationToken ct);
    Task WriteSingleRegisterAsync(byte unitId, ushort address, ushort value, CancellationToken ct);
}

public interface IModbusClientFactory
{
    IModbusClient Create(string host, int port);
}

public sealed class ModbusTcpClientFactory(ILoggerFactory loggerFactory) : IModbusClientFactory
{
    public IModbusClient Create(string host, int port) =>
        new ModbusTcpClient(host, port, loggerFactory.CreateLogger<ModbusTcpClient>());
}

/// <summary>
/// Async Modbus TCP master. One outstanding transaction at a time; responses are read with
/// exact-length reads and matched on transaction id + unit id.
/// </summary>
public sealed class ModbusTcpClient(string host, int port, ILogger<ModbusTcpClient> logger) : IModbusClient
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private TcpClient? _client;
    private NetworkStream? _stream;
    private int _transactionId;

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);

    public async Task<ushort[]> ReadRegistersAsync(byte unitId, byte function, ushort start, ushort count, CancellationToken ct)
    {
        var request = ModbusFrame.BuildReadRequest(NextTransactionId(), unitId, function, start, count);
        var pdu = await TransactAsync(request, ct).ConfigureAwait(false);
        return ModbusFrame.ParseReadResponse(pdu, function, count);
    }

    public async Task WriteSingleRegisterAsync(byte unitId, ushort address, ushort value, CancellationToken ct)
    {
        var request = ModbusFrame.BuildWriteSingleRequest(NextTransactionId(), unitId, address, value);
        var pdu = await TransactAsync(request, ct).ConfigureAwait(false);
        ModbusFrame.ValidateWriteResponse(pdu, request.AsSpan(ModbusFrame.MbapHeaderLength));
    }

    private async Task<byte[]> TransactAsync(byte[] request, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(Timeout);
            try
            {
                var stream = await EnsureConnectedAsync(timeout.Token).ConfigureAwait(false);
                await stream.WriteAsync(request, timeout.Token).ConfigureAwait(false);

                var header = new byte[ModbusFrame.MbapHeaderLength];
                await stream.ReadExactlyAsync(header, timeout.Token).ConfigureAwait(false);
                var h = ModbusFrame.ParseHeader(header);
                var pdu = new byte[h.PduLength];
                await stream.ReadExactlyAsync(pdu, timeout.Token).ConfigureAwait(false);

                var req = ModbusFrame.ParseHeader(request);
                if (h.TransactionId != req.TransactionId || h.UnitId != req.UnitId)
                    throw new ModbusProtocolException("Response does not match request (transaction/unit id)");
                return pdu;
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ModbusProtocolException
                                       && !ct.IsCancellationRequested)
            {
                // Drop the connection so the next transaction starts from a clean, re-synchronised stream
                GatewayLog.DeviceCommunicationFailed(logger, host, port, ex.GetType().Name);
                Reset();
                throw;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<NetworkStream> EnsureConnectedAsync(CancellationToken ct)
    {
        if (_stream is not null && _client is { Connected: true })
            return _stream;
        Reset();
        _client = new TcpClient { NoDelay = true };
        await _client.ConnectAsync(host, port, ct).ConfigureAwait(false);
        _stream = _client.GetStream();
        GatewayLog.DeviceConnected(logger, host, port);
        return _stream;
    }

    private ushort NextTransactionId() => (ushort)Interlocked.Increment(ref _transactionId);

    private void Reset()
    {
        _stream?.Dispose();
        _client?.Dispose();
        _stream = null;
        _client = null;
    }

    public ValueTask DisposeAsync()
    {
        Reset();
        _gate.Dispose();
        return ValueTask.CompletedTask;
    }
}
