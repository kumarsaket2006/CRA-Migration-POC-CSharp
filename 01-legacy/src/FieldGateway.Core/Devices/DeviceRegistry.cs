using System.Collections.Generic;
using System.Linq;

namespace Indusoft.FieldGateway.Core.Devices
{
    /// <summary>Singleton registry of configured field devices.</summary>
    public sealed class DeviceRegistry
    {
        private static readonly DeviceRegistry _instance = new DeviceRegistry();
        private readonly Dictionary<string, FieldDevice> _devices = new Dictionary<string, FieldDevice>();
        private readonly object _lock = new object();

        public static DeviceRegistry Instance { get { return _instance; } }

        private DeviceRegistry() { }

        public void Register(FieldDevice device)
        {
            lock (_lock) { _devices[device.Id] = device; }
        }

        public FieldDevice Find(string id)
        {
            lock (_lock)
            {
                FieldDevice d;
                _devices.TryGetValue(id, out d);
                return d;
            }
        }

        public IList<FieldDevice> All()
        {
            lock (_lock) { return _devices.Values.ToList(); }
        }

        public void Clear()
        {
            lock (_lock) { _devices.Clear(); }
        }
    }
}
