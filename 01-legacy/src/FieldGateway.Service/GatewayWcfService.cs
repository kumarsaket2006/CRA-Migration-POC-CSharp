using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.ServiceModel;
using Indusoft.FieldGateway.Core.Devices;
using Indusoft.FieldGateway.Core.Firmware;
using Indusoft.FieldGateway.Core.Modbus;
using log4net;

namespace Indusoft.FieldGateway.Service
{
    [ServiceBehavior(InstanceContextMode = InstanceContextMode.Single, ConcurrencyMode = ConcurrencyMode.Multiple)]
    public class GatewayWcfService : IGatewayWcfService
    {
        private static readonly ILog Log = LogManager.GetLogger(typeof(GatewayWcfService));

        // LEGACY-ISSUE: L05 No authentication or authorization on any operation (CWE-306, CWE-862)
        public List<DeviceInfo> ListDevices()
        {
            return DeviceRegistry.Instance.All().Select(d => new DeviceInfo
            {
                Id = d.Id,
                Name = d.Name,
                IpAddress = d.IpAddress,
                MaintenancePassword = d.MaintenancePassword
            }).ToList();
        }

        public double GetTagValue(string deviceId, string tagName)
        {
            TagValue v;
            if (GatewayService.Poller.Snapshot().TryGetValue(deviceId + "." + tagName, out v)) return v.Value;
            throw new FaultException("Unknown tag " + deviceId + "." + tagName);
        }

        public void WriteTag(string deviceId, string tagName, double value)
        {
            FieldDevice device = DeviceRegistry.Instance.Find(deviceId);
            TagDefinition tag = device.Tags.First(t => t.Name == tagName);

            // LEGACY-ISSUE: L10 No range validation and "Writable" flag not enforced -> any caller can write any
            // setpoint/coil on the PLC (CWE-20, CWE-284)
            ushort raw = (ushort)(value / tag.Scale);
            using (ModbusTcpClient client = new ModbusTcpClient(device.IpAddress, device.Port))
            {
                client.Connect();
                client.WriteSingleRegister(device.UnitId, tag.Address, raw);
            }
            Log.Info(string.Format("WriteTag {0}.{1}={2}", deviceId, tagName, value));
        }

        public string UploadFirmware(string deviceId, string fileName, byte[] content)
        {
            string staging = ConfigurationManager.AppSettings["FirmwareStaging"];

            // LEGACY-ISSUE: L10 Caller-controlled file name -> path traversal / arbitrary file write (CWE-22)
            string path = Path.Combine(staging, fileName);
            File.WriteAllBytes(path, content);

            FirmwarePackageVerifier verifier = new FirmwarePackageVerifier(Path.Combine(staging, deviceId));
            string image = verifier.Extract(path);
            if (!verifier.Verify(image))
            {
                return "REJECTED";
            }
            return "STAGED:" + image;
        }

        public List<HistoryPoint> QueryHistory(string deviceId, string tagName, string fromDate, string toDate)
        {
            return new HistorianRepository().Query(deviceId, tagName, fromDate, toDate);
        }
    }
}
