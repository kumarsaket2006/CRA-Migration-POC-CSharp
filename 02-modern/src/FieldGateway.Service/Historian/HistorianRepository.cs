using System.Data;
using Indusoft.FieldGateway.Core.Devices;
using Microsoft.Data.SqlClient;

namespace Indusoft.FieldGateway.Service.Historian;

public sealed record HistoryPoint(DateTimeOffset Timestamp, double Value);

/// <summary>
/// Parameterised historian access (fixes L07 / CWE-89). The connection string comes from the secret
/// store, uses a least-privilege SQL login or integrated auth, and must set Encrypt=Mandatory.
/// </summary>
public sealed class HistorianRepository(string connectionString)
{
    public async Task InsertAsync(TagValue v, CancellationToken ct)
    {
        await using var con = new SqlConnection(connectionString);
        await con.OpenAsync(ct);
        await using var cmd = new SqlCommand(
            "INSERT INTO dbo.TagHistory (DeviceId, TagName, Value, Quality, Ts) VALUES (@device, @tag, @value, @quality, @ts)", con);
        cmd.Parameters.Add("@device", SqlDbType.NVarChar, 32).Value = v.DeviceId;
        cmd.Parameters.Add("@tag", SqlDbType.NVarChar, 64).Value = v.TagName;
        cmd.Parameters.Add("@value", SqlDbType.Float).Value = v.Value;
        cmd.Parameters.Add("@quality", SqlDbType.TinyInt).Value = (byte)v.Quality;
        cmd.Parameters.Add("@ts", SqlDbType.DateTimeOffset).Value = v.Timestamp;
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<HistoryPoint>> QueryAsync(string deviceId, string tag, DateTimeOffset from, DateTimeOffset to, CancellationToken ct)
    {
        var result = new List<HistoryPoint>();
        await using var con = new SqlConnection(connectionString);
        await con.OpenAsync(ct);
        await using var cmd = new SqlCommand(
            "SELECT TOP (10000) Ts, Value FROM dbo.TagHistory WHERE DeviceId = @device AND TagName = @tag AND Ts BETWEEN @from AND @to ORDER BY Ts", con);
        cmd.Parameters.Add("@device", SqlDbType.NVarChar, 32).Value = deviceId;
        cmd.Parameters.Add("@tag", SqlDbType.NVarChar, 64).Value = tag;
        cmd.Parameters.Add("@from", SqlDbType.DateTimeOffset).Value = from;
        cmd.Parameters.Add("@to", SqlDbType.DateTimeOffset).Value = to;
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            result.Add(new HistoryPoint(r.GetDateTimeOffset(0), r.GetDouble(1)));
        return result;
    }
}
