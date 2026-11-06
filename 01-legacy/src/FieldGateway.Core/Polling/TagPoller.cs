using System;
using System.Collections.Generic;
using System.Threading;
using Indusoft.FieldGateway.Core.Devices;
using Indusoft.FieldGateway.Core.Modbus;
using log4net;

namespace Indusoft.FieldGateway.Core.Polling
{
    /// <summary>Polls all registered devices on dedicated threads and raises change events.</summary>
    public class TagPoller
    {
        private static readonly ILog Log = LogManager.GetLogger(typeof(TagPoller));

        private readonly List<Thread> _threads = new List<Thread>();
        private readonly Dictionary<string, TagValue> _lastValues = new Dictionary<string, TagValue>();
        private volatile bool _running;

        public event EventHandler<TagValueChangedEventArgs> TagValueChanged;

        public IDictionary<string, TagValue> Snapshot()
        {
            lock (_lastValues) { return new Dictionary<string, TagValue>(_lastValues); }
        }

        public void Start()
        {
            _running = true;
            foreach (FieldDevice device in DeviceRegistry.Instance.All())
            {
                FieldDevice d = device;
                Thread t = new Thread(() => PollLoop(d));
                t.IsBackground = true;
                t.Name = "Poll-" + d.Id;
                _threads.Add(t);
                t.Start();
            }
        }

        public void Stop()
        {
            // LEGACY-ISSUE: L11 No cooperative cancellation; threads are aborted (Thread.Abort is unsupported in .NET 5+)
            _running = false;
            foreach (Thread t in _threads)
            {
                if (!t.Join(2000)) t.Abort();
            }
            _threads.Clear();
        }

        private void PollLoop(FieldDevice device)
        {
            ModbusTcpClient client = new ModbusTcpClient(device.IpAddress, device.Port);
            while (_running)
            {
                try
                {
                    if (!client.IsConnected) client.Connect();
                    foreach (TagDefinition tag in device.Tags)
                    {
                        ushort[] regs = tag.IsInput
                            ? client.ReadInputRegisters(device.UnitId, tag.Address, tag.Length)
                            : client.ReadHoldingRegisters(device.UnitId, tag.Address, tag.Length);
                        Publish(device, tag, regs[0] * tag.Scale);
                    }
                }
                catch (Exception)
                {
                    // LEGACY-ISSUE: L11 Communication failures swallowed, no security/diagnostic event raised
                    client.Dispose();
                    client = new ModbusTcpClient(device.IpAddress, device.Port);
                }
                Thread.Sleep(device.PollIntervalMs);
            }
            client.Dispose();
        }

        private void Publish(FieldDevice device, TagDefinition tag, double value)
        {
            string key = device.Id + "." + tag.Name;
            TagValue tv = new TagValue
            {
                DeviceId = device.Id,
                TagName = tag.Name,
                Value = value,
                TimestampUtc = DateTime.UtcNow,
                Quality = "Good"
            };
            bool changed;
            lock (_lastValues)
            {
                TagValue old;
                changed = !_lastValues.TryGetValue(key, out old) || old.Value != value;
                _lastValues[key] = tv;
            }
            if (changed && TagValueChanged != null)
            {
                TagValueChanged(this, new TagValueChangedEventArgs(tv));
            }
        }
    }
}
