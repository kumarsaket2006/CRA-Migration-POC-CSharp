using System;
using System.Configuration;
using System.ServiceModel;
using System.ServiceProcess;
using System.Threading;
using Indusoft.FieldGateway.Core.Config;
using Indusoft.FieldGateway.Core.Devices;
using Indusoft.FieldGateway.Core.Licensing;
using Indusoft.FieldGateway.Core.Polling;
using Indusoft.FieldGateway.Core.Storage;
using log4net;

namespace Indusoft.FieldGateway.Service
{
    // LEGACY-ISSUE: L12 ServiceBase / WCF ServiceHost are Windows/.NET Framework only
    public class GatewayService : ServiceBase
    {
        private static readonly ILog Log = LogManager.GetLogger(typeof(GatewayService));

        public static TagPoller Poller { get; private set; }

        private ServiceHost _host;
        private Timer _cacheTimer;
        private Timer _cloudTimer;
        private DataCache _cache;
        private readonly HistorianRepository _historian = new HistorianRepository();
        private readonly CloudUplink _uplink = new CloudUplink();

        public GatewayService()
        {
            ServiceName = "IndusoftFieldGateway";
        }

        public void StartInteractive(string[] args) { OnStart(args); }
        public void StopInteractive() { OnStop(); }

        protected override void OnStart(string[] args)
        {
            if (!new LicenseManager().IsLicensed())
            {
                Log.Warn("No valid license found - running in demo mode");
            }

            new DeviceConfigLoader().LoadFromFile(ConfigurationManager.AppSettings["DeviceConfigPath"]);

            _cache = new DataCache(ConfigurationManager.AppSettings["CachePath"]);
            Poller = new TagPoller();
            Poller.TagValueChanged += (s, e) =>
            {
                try { _historian.Insert(e.Value); }
                catch (Exception) { /* LEGACY-ISSUE: L11 historian errors ignored */ }
            };
            Poller.Start();

            _cacheTimer = new Timer(_ => _cache.Save(Poller.Snapshot()), null, 10000, 10000);
            _cloudTimer = new Timer(_ => { try { _uplink.Push(Poller); } catch { } }, null, 30000, 30000);

            _host = new ServiceHost(typeof(GatewayWcfService));
            _host.Open();
            Log.Info("FieldGateway started with " + DeviceRegistry.Instance.All().Count + " devices");
        }

        protected override void OnStop()
        {
            if (_host != null) _host.Close();
            if (_cacheTimer != null) _cacheTimer.Dispose();
            if (_cloudTimer != null) _cloudTimer.Dispose();
            if (Poller != null) Poller.Stop();
        }
    }
}
