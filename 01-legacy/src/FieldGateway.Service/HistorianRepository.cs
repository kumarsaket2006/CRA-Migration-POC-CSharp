using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.SqlClient;
using Indusoft.FieldGateway.Core.Devices;

namespace Indusoft.FieldGateway.Service
{
    public class HistorianRepository
    {
        private readonly string _cs = ConfigurationManager.ConnectionStrings["Historian"].ConnectionString;

        public void Insert(TagValue v)
        {
            using (SqlConnection con = new SqlConnection(_cs))
            {
                con.Open();
                // LEGACY-ISSUE: L07 SQL built by string concatenation (CWE-89)
                string sql = "INSERT INTO TagHistory (DeviceId, TagName, Value, Ts) VALUES ('" + v.DeviceId + "','" + v.TagName + "'," +
                             v.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) + ",'" + v.TimestampUtc.ToString("s") + "')";
                using (SqlCommand cmd = new SqlCommand(sql, con))
                {
                    cmd.ExecuteNonQuery();
                }
            }
        }

        public List<HistoryPoint> Query(string deviceId, string tagName, string from, string to)
        {
            List<HistoryPoint> result = new List<HistoryPoint>();
            using (SqlConnection con = new SqlConnection(_cs))
            {
                con.Open();
                // LEGACY-ISSUE: L07 SQL injection through remote WCF parameters (CWE-89)
                string sql = "SELECT Ts, Value FROM TagHistory WHERE DeviceId = '" + deviceId + "' AND TagName = '" + tagName +
                             "' AND Ts BETWEEN '" + from + "' AND '" + to + "' ORDER BY Ts";
                using (SqlCommand cmd = new SqlCommand(sql, con))
                using (SqlDataReader r = cmd.ExecuteReader())
                {
                    while (r.Read())
                    {
                        result.Add(new HistoryPoint { Timestamp = r.GetDateTime(0).ToString("o"), Value = r.GetDouble(1) });
                    }
                }
            }
            return result;
        }
    }
}
