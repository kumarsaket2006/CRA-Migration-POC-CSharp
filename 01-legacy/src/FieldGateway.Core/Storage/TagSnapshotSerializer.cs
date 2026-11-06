using System.Collections.Generic;
using Indusoft.FieldGateway.Core.Devices;
using Newtonsoft.Json;

namespace Indusoft.FieldGateway.Core.Storage
{
    /// <summary>JSON snapshot used by the cloud uplink / remote HMI.</summary>
    public static class TagSnapshotSerializer
    {
        // LEGACY-ISSUE: L01 TypeNameHandling.All lets the payload choose the CLR type to instantiate
        // -> insecure deserialization of remote input (CWE-502)
        private static readonly JsonSerializerSettings Settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All
        };

        public static string Serialize(IDictionary<string, TagValue> snapshot)
        {
            return JsonConvert.SerializeObject(snapshot, Settings);
        }

        public static IDictionary<string, TagValue> Deserialize(string json)
        {
            return JsonConvert.DeserializeObject<Dictionary<string, TagValue>>(json, Settings);
        }
    }
}
