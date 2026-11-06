using System;
using System.Configuration;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Text;
using Indusoft.FieldGateway.Core.Polling;
using Indusoft.FieldGateway.Core.Storage;
using log4net;

namespace Indusoft.FieldGateway.Service
{
    /// <summary>Pushes tag snapshots to the vendor cloud for remote monitoring.</summary>
    public class CloudUplink
    {
        private static readonly ILog Log = LogManager.GetLogger(typeof(CloudUplink));
        private readonly HttpClient _http;

        public CloudUplink()
        {
            // LEGACY-ISSUE: L05 Legacy TLS forced and certificate validation disabled (CWE-295, CWE-326)
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
            ServicePointManager.ServerCertificateValidationCallback =
                delegate(object s, System.Security.Cryptography.X509Certificates.X509Certificate c,
                         System.Security.Cryptography.X509Certificates.X509Chain ch, SslPolicyErrors e) { return true; };
            _http = new HttpClient();
        }

        public void Push(TagPoller poller)
        {
            string apiKey = ConfigurationManager.AppSettings["CloudApiKey"];
            string url = ConfigurationManager.AppSettings["CloudEndpoint"];
            string json = TagSnapshotSerializer.Serialize(poller.Snapshot());

            // LEGACY-ISSUE: L08 API key logged
            Log.Debug("Uploading snapshot with key " + apiKey + " to " + url);

            // LEGACY-ISSUE: L05 API key in query string over plain HTTP
            HttpResponseMessage resp = _http.PostAsync(url + "?apikey=" + apiKey,
                new StringContent(json, Encoding.UTF8, "application/json")).Result;
            if (!resp.IsSuccessStatusCode)
            {
                Log.Warn("Cloud upload failed: " + resp.StatusCode);
            }
        }
    }
}
