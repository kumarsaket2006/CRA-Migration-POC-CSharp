using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Indusoft.FieldGateway.Core.Devices;

namespace Indusoft.FieldGateway.Core.Storage
{
    /// <summary>Persists last-known tag values so HMIs get data immediately after a restart.</summary>
    public class DataCache
    {
        private readonly string _path;

        public DataCache(string path)
        {
            _path = path;
        }

        public void Save(IDictionary<string, TagValue> values)
        {
            using (FileStream fs = File.Create(_path))
            {
                BinaryFormatter bf = new BinaryFormatter();
                bf.Serialize(fs, new Dictionary<string, TagValue>(values));
            }
        }

        public IDictionary<string, TagValue> Load()
        {
            if (!File.Exists(_path)) return new Dictionary<string, TagValue>();
            using (FileStream fs = File.OpenRead(_path))
            {
                // LEGACY-ISSUE: L01 BinaryFormatter deserialization of a file in a world-writable data folder
                // -> remote code execution via gadget chains (CWE-502). BinaryFormatter is removed in .NET 9+.
                BinaryFormatter bf = new BinaryFormatter();
                return (IDictionary<string, TagValue>)bf.Deserialize(fs);
            }
        }
    }
}
