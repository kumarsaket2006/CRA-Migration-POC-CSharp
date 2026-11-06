using System.Collections.Generic;
using System.Runtime.Serialization;
using System.ServiceModel;

namespace Indusoft.FieldGateway.Service
{
    [ServiceContract(Namespace = "urn:indusoft:fieldgateway:v2")]
    public interface IGatewayWcfService
    {
        [OperationContract]
        List<DeviceInfo> ListDevices();

        [OperationContract]
        double GetTagValue(string deviceId, string tagName);

        [OperationContract]
        void WriteTag(string deviceId, string tagName, double value);

        [OperationContract]
        string UploadFirmware(string deviceId, string fileName, byte[] content);

        [OperationContract]
        List<HistoryPoint> QueryHistory(string deviceId, string tagName, string fromDate, string toDate);
    }

    [DataContract]
    public class DeviceInfo
    {
        [DataMember] public string Id { get; set; }
        [DataMember] public string Name { get; set; }
        [DataMember] public string IpAddress { get; set; }
        // LEGACY-ISSUE: L08 Maintenance password exposed through the public API contract
        [DataMember] public string MaintenancePassword { get; set; }
    }

    [DataContract]
    public class HistoryPoint
    {
        [DataMember] public string Timestamp { get; set; }
        [DataMember] public double Value { get; set; }
    }
}
